//go:build windows

package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
	"unsafe"

	"chameleon/internal/rudirect"

	"golang.org/x/sys/windows"
)

// "Российские сайты напрямую" (docs/RU-DIRECT.md).
//
// While the tunnel is up, Russian IPv4 networks are routed through the
// physical uplink with more specific routes than the 0/1 + 128/1 capture, so
// Russian services see the user's own address. DNS questions for Russian
// domains are answered by Yandex DNS over HTTPS (reached directly through the
// same routes) so geo-aware CDNs return Russian edges. Everything else,
// including all other DNS, keeps using the tunnel. The feature is best effort:
// any failure leaves the full tunnel in place, which is the safe direction.

// ruDirectEnabled is set by every "connect" request (default on).
var ruDirectEnabled atomic.Bool

func init() { ruDirectEnabled.Store(true) }

const (
	// Route metric that marks our routes, so stale rows left by a crashed
	// broker can be recognised and purged on the next connect.
	ruDirectMetric    = 6
	mibIPProtoNetMgmt = 3
	errObjectExists   = 5010 // ERROR_OBJECT_ALREADY_EXISTS
	ruDirectMaxErrors = 32
)

var (
	ruIphlpapi                   = windows.NewLazySystemDLL("iphlpapi.dll")
	procInitializeIpForwardEntry = ruIphlpapi.NewProc("InitializeIpForwardEntry")
	procCreateIpForwardEntry2    = ruIphlpapi.NewProc("CreateIpForwardEntry2")
	procDeleteIpForwardEntry2    = ruIphlpapi.NewProc("DeleteIpForwardEntry2")
)

func sockaddrV4(a netip.Addr) (sa windows.RawSockaddrInet) {
	sa.Family = windows.AF_INET
	b := a.As4()
	copy((*[4]byte)(unsafe.Pointer(&sa.Data[0]))[:], b[:])
	return sa
}

func sockaddrAddr(sa *windows.RawSockaddrInet) (netip.Addr, bool) {
	if sa.Family != windows.AF_INET {
		return netip.Addr{}, false
	}
	return netip.AddrFrom4(*(*[4]byte)(unsafe.Pointer(&sa.Data[0]))), true
}

func ipv4Routes() ([]windows.MibIpForwardRow2, error) {
	var table *windows.MibIpForwardTable2
	if e := windows.GetIpForwardTable2(windows.AF_INET, &table); e != nil {
		return nil, e
	}
	defer windows.FreeMibTable(unsafe.Pointer(table))
	return append([]windows.MibIpForwardRow2(nil), table.Rows()...), nil
}

// physicalUplink picks the default route of the physical network: the 0.0.0.0/0
// row (never our TUN) whose next hop matches the gateway used for the node
// bypass, or the lowest-metric default route.
func physicalUplink(rows []windows.MibIpForwardRow2, gateway string, tunIndex uint32) (windows.MibIpForwardRow2, bool) {
	want, _ := netip.ParseAddr(strings.TrimSpace(gateway))
	var best windows.MibIpForwardRow2
	found, matched := false, false
	for _, row := range rows {
		if row.DestinationPrefix.PrefixLength != 0 || row.InterfaceIndex == tunIndex {
			continue
		}
		hop, _ := sockaddrAddr(&row.NextHop)
		isMatch := want.IsValid() && hop == want
		switch {
		case !found, isMatch && !matched, isMatch == matched && row.Metric < best.Metric:
			best, found, matched = row, true, isMatch
		}
	}
	return best, found
}

func deleteRoute(row *windows.MibIpForwardRow2) {
	_, _, _ = procDeleteIpForwardEntry2.Call(uintptr(unsafe.Pointer(row)))
}

// purgeStaleRuDirect removes RU-direct rows left behind by a previous broker
// process (crash or power loss in the middle of a session).
func purgeStaleRuDirect(rows []windows.MibIpForwardRow2) int {
	set := make(map[netip.Prefix]struct{}, len(rudirect.Prefixes()))
	for _, p := range rudirect.Prefixes() {
		set[p] = struct{}{}
	}
	removed := 0
	for i := range rows {
		row := &rows[i]
		if row.Metric != ruDirectMetric || row.Protocol != mibIPProtoNetMgmt {
			continue
		}
		addr, ok := sockaddrAddr(&row.DestinationPrefix.Prefix)
		if !ok {
			continue
		}
		if _, ours := set[netip.PrefixFrom(addr, int(row.DestinationPrefix.PrefixLength))]; ours {
			deleteRoute(row)
			removed++
		}
	}
	return removed
}

// addRuDirect installs the RU-direct routes via the physical uplink. It must
// run after the node bypass and before the capture routes.
func (t *TunDevice) addRuDirect(gateway string) {
	t.ruRoutes = nil
	if !ruDirectEnabled.Load() {
		t.m.logf("ru-direct: выключено пользователем, весь трафик через VPN")
		return
	}
	if e := procCreateIpForwardEntry2.Find(); e != nil {
		t.m.logf("ru-direct: API маршрутов недоступен: %v", e)
		return
	}
	rows, e := ipv4Routes()
	if e != nil {
		t.m.logf("ru-direct: таблица маршрутов недоступна: %v", e)
		return
	}
	if n := purgeStaleRuDirect(rows); n > 0 {
		t.m.logf("ru-direct: удалено старых маршрутов: %d", n)
	}
	tunIndex, _ := strconv.ParseUint(t.ifIndex, 10, 32)
	up, ok := physicalUplink(rows, gateway, uint32(tunIndex))
	if !ok {
		t.m.logf("ru-direct: физический шлюз не найден, весь трафик через VPN")
		return
	}
	failures := 0
	for _, p := range rudirect.Prefixes() {
		var row windows.MibIpForwardRow2
		_, _, _ = procInitializeIpForwardEntry.Call(uintptr(unsafe.Pointer(&row)))
		row.InterfaceLuid = up.InterfaceLuid
		row.InterfaceIndex = up.InterfaceIndex
		row.DestinationPrefix.Prefix = sockaddrV4(p.Addr())
		row.DestinationPrefix.PrefixLength = uint8(p.Bits())
		row.NextHop = up.NextHop
		row.Metric = ruDirectMetric
		row.Protocol = mibIPProtoNetMgmt
		r, _, _ := procCreateIpForwardEntry2.Call(uintptr(unsafe.Pointer(&row)))
		switch r {
		case 0:
			t.ruRoutes = append(t.ruRoutes, row)
		case errObjectExists:
		default:
			if failures++; failures > ruDirectMaxErrors {
				t.m.logf("ru-direct: маршруты отклонены (код %d), весь трафик через VPN", r)
				t.removeRuDirect()
				return
			}
		}
	}
	hop, _ := sockaddrAddr(&up.NextHop)
	t.m.logf("ru-direct: %d сетей РФ напрямую через if %d (%s)", len(t.ruRoutes), up.InterfaceIndex, hop)
}

func (t *TunDevice) removeRuDirect() {
	for i := range t.ruRoutes {
		deleteRoute(&t.ruRoutes[i])
	}
	t.ruRoutes = nil
}

// Yandex public DNS over HTTPS; 77.88.8.8 is inside the RU-direct set, so the
// query leaves through the physical uplink like the traffic it resolves.
var ruResolver = &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{
	Proxy: nil, TLSClientConfig: &tls.Config{ServerName: "common.dot.dns.yandex.net", MinVersion: tls.VersionTLS12},
	DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
		return (&net.Dialer{Timeout: 3 * time.Second}).DialContext(ctx, "tcp4", "77.88.8.8:443")
	},
	MaxIdleConnsPerHost: 2, ForceAttemptHTTP2: true,
}, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}

// handleRuDNS answers DNS questions for Russian domains through Yandex DNS.
// It returns false when the question is not Russian or the resolver failed;
// the caller then uses the regular in-tunnel resolver.
func handleRuDNS(conn net.PacketConn, source net.Addr, query []byte) bool {
	if !ruDirectEnabled.Load() || len(query) < 12 || len(query) > 4096 {
		return false
	}
	name, e := rudirect.QuestionName(query)
	if e != nil || !rudirect.IsRussianDomain(name) {
		return false
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	req, e := http.NewRequestWithContext(ctx, "POST", "https://common.dot.dns.yandex.net/dns-query", bytes.NewReader(query))
	if e != nil {
		return false
	}
	req.Header.Set("Content-Type", "application/dns-message")
	req.Header.Set("Accept", "application/dns-message")
	resp, e := ruResolver.Do(req)
	if e != nil {
		return false
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return false
	}
	answer, e := io.ReadAll(io.LimitReader(resp.Body, 4097))
	if e != nil || len(answer) < 12 || len(answer) > 4096 || answer[0] != query[0] || answer[1] != query[1] {
		return false
	}
	_, _ = conn.WriteTo(answer, source)
	return true
}
