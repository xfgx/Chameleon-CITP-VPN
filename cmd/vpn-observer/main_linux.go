//go:build linux

// vpn-observer passively observes bounded network headers; payload is never persisted.
//
package main

import (
	"chameleon/internal/telemetry"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"golang.org/x/sys/unix"
	"log"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

var node = flag.String("node", "", "opaque node id")
var interfaces = flag.String("interfaces", "", "explicit interfaces, comma separated")
var ports = flag.String("ports", "9443,9444,9445,9446,8443,51830,51821", "VPN carrier ports only; never all browsing traffic")
var directory = flag.String("directory", "/var/log/chameleon/telemetry", "private metadata directory")
var captureDir = flag.String("captures", "/run/chameleon/captures", "header-only diagnostic pcap directory")
var enableFile = flag.String("capture-window", "/run/chameleon/capture-enabled-until", "root-controlled temporary capture window")
var probe = flag.String("probe-host", "", "optional operator-approved HTTPS canary hostname; no user browsing domains")
var maxBytes = flag.Int64("max-bytes", 96<<20, "metadata disk bound")
var asnPath = flag.String("asn-db", "/var/lib/chameleon-observer/ip2asn-ru.tsv", "optional offline IP-to-ASN table (iptoasn TSV) for per-operator quality aggregates")
var qualityWindow = flag.Duration("quality-window", 5*time.Minute, "aggregation window for per-operator connection quality")

var asnDB *telemetry.ASNDB
var quality = telemetry.NewQualityAggregator(time.Now().UTC())

func htons(n uint16) uint16 { return n<<8 | n>>8 }
func filterPorts(values []uint16) []unix.SockFilter {
	// SOCK_DGRAM/AF_PACKET exposes an IP packet, not an Ethernet header. Cap copy
	// length at 128 and reject unrelated IPv4 TCP/UDP ports in the kernel.
	a := []unix.SockFilter{{Code: 0x30, K: 0}, {Code: 0x54, K: 0xf0}, {Code: 0x15, K: 0x40, Jt: 1}, {Code: 0x06, K: 128}, {Code: 0x30, K: 9}, {Code: 0x15, K: 6, Jt: 1}, {Code: 0x15, K: 17}, {Code: 0xb1, K: 0}, {Code: 0x48, K: 0}}
	jumps := []int{}
	for _, p := range values {
		jumps = append(jumps, len(a))
		a = append(a, unix.SockFilter{Code: 0x15, K: uint32(p)})
	}
	a = append(a, unix.SockFilter{Code: 0x48, K: 2})
	for _, p := range values {
		jumps = append(jumps, len(a))
		a = append(a, unix.SockFilter{Code: 0x15, K: uint32(p)})
	}
	deny := len(a)
	a = append(a, unix.SockFilter{Code: 0x06, K: 0})
	allow := len(a)
	a = append(a, unix.SockFilter{Code: 0x06, K: 128})
	a[6].Jf = uint8(deny - 7)
	for _, index := range jumps {
		a[index].Jt = uint8(allow - index - 1)
	}
	return a
}
func enabled() bool {
	b, e := os.ReadFile(*enableFile)
	if e != nil {
		return false
	}
	until, e := strconv.ParseInt(strings.TrimSpace(string(b)), 10, 64)
	now := time.Now().Unix()
	return e == nil && until > now && until <= now+900
}
func observe(ctx context.Context, iface string, allowed map[uint16]bool, values []uint16, store *telemetry.Store) error {
	n, e := net.InterfaceByName(iface)
	if e != nil {
		return e
	}
	fd, e := unix.Socket(unix.AF_PACKET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, int(htons(unix.ETH_P_ALL)))
	if e != nil {
		return e
	}
	defer unix.Close(fd)
	if e = unix.Bind(fd, &unix.SockaddrLinklayer{Protocol: htons(unix.ETH_P_ALL), Ifindex: n.Index}); e != nil {
		return e
	}
	_ = unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_RCVBUF, 8<<20)
	if e = unix.SetNonblock(fd, true); e != nil {
		return e
	}
	program := filterPorts(values)
	if e = unix.SetsockoptSockFprog(fd, unix.SOL_SOCKET, unix.SO_ATTACH_FILTER, &unix.SockFprog{Len: uint16(len(program)), Filter: &program[0]}); e != nil {
		return e
	}
	local := map[string]bool{}
	if addrs, err := n.Addrs(); err == nil {
		for _, a := range addrs {
			if ipn, ok := a.(*net.IPNet); ok {
				local[ipn.IP.String()] = true
			}
		}
	}
	tracker := telemetry.Tracker{Node: *node, Interface: iface, MTU: n.MTU, CaptureDir: *captureDir, ServerPorts: allowed, Local: local, Resolve: asnDB.Lookup, OnEnd: quality.Add}
	buffer := make([]byte, 128)
	lastSweep, lastStats := time.Now(), time.Now()
	emit := func(events []telemetry.Event) error {
		for _, event := range events {
			if err := store.Append(event); err != nil {
				return err
			}
		}
		return nil
	}
	if e = store.Append(telemetry.Event{Node: *node, Kind: "sensor", Interface: iface, Phase: "started", Verdict: "unknown", Reasons: []string{"VPN-carrier headers only; no decrypted payload, browsing DNS/SNI or content capture"}, Observation: "capture metadata only"}); e != nil {
		return e
	}
	for ctx.Err() == nil {
		fds := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLIN}}
		_, e := unix.Poll(fds, 200)
		if e != nil && e != unix.EINTR {
			return e
		}
		now := time.Now().UTC()
		tracker.CaptureEnabled = enabled()
		if fds[0].Revents&unix.POLLIN != 0 {
			for i := 0; i < 4096; i++ {
				length, _, err := unix.Recvfrom(fd, buffer, unix.MSG_DONTWAIT)
				if err == unix.EAGAIN || err == unix.EWOULDBLOCK {
					break
				}
				if err != nil {
					return err
				}
				packet, err := telemetry.ParseHeaders(buffer[:length])
				if err != nil {
					continue
				}
				if !allowed[packet.SrcPort] && !allowed[packet.DstPort] {
					continue
				}
				if err = emit(tracker.Observe(packet, now)); err != nil {
					return err
				}
			}
		}
		if now.Sub(lastSweep) > time.Second {
			if e = emit(tracker.Sweep(now)); e != nil {
				return e
			}
			lastSweep = now
		}
		if now.Sub(lastStats) > 30*time.Second {
			stats, err := unix.GetsockoptTpacketStats(fd, unix.SOL_PACKET, unix.PACKET_STATISTICS)
			if err == nil {
				tracker.Dropped += uint64(stats.Drops)
			}
			phase := "healthy"
			verdict := "normal"
			reasons := []string{"sensor active; this is not a verdict on DPI"}
			if tracker.Dropped+tracker.Evicted > 0 {
				phase = "capture_gap"
				verdict = "unknown"
				reasons = []string{"kernel drops or flow-cap evictions; packet-level evidence is incomplete"}
			}
			if e = store.Append(telemetry.Event{Node: *node, Kind: "sensor", Interface: iface, Phase: phase, Verdict: verdict, Dropped: tracker.Dropped + tracker.Evicted, Reasons: reasons, Observation: fmt.Sprintf("tracked_flows=%d; header_capture=%t", len(tracker.Flows), tracker.CaptureEnabled)}); e != nil {
				return e
			}
			_ = telemetry.SweepCaptures(*captureDir)
			lastStats = now
		}
	}
	return nil
}
func probeCanary(ctx context.Context, store *telemetry.Store, host string) {
	if host == "" || net.ParseIP(host) != nil || strings.ContainsAny(host, " /\\:@") {
		return
	}
	run := func() {
		now := time.Now().UTC()
		resolver := net.DefaultResolver
		c, cancel := context.WithTimeout(ctx, 8*time.Second)
		defer cancel()
		ips, err := resolver.LookupIPAddr(c, host)
		dns := &telemetry.DNSMetadata{Name: host, Synthetic: true, LatencyMS: time.Since(now).Milliseconds()}
		event := telemetry.Event{Node: *node, Kind: "diagnostic", Protocol: "dns", DNS: dns, Verdict: "unknown", Reasons: []string{"operator-configured synthetic canary; answers vary by resolver and location"}}
		if err != nil {
			dns.RCode = "error"
			if e, ok := err.(*net.DNSError); ok && e.IsNotFound {
				dns.RCode = "NXDOMAIN"
			}
			event.Phase = "dns_error"
			event.Confidence = 0.3
			event.Verdict = "suspicious"
			event.Reasons = []string{"synthetic DNS failed; failure alone does not prove poisoning or DPI"}
		} else {
			dns.RCode = "NOERROR"
			for _, ip := range ips {
				if len(dns.Answers) < 8 {
					dns.Answers = append(dns.Answers, ip.IP.String())
				}
			}
			event.Phase = "dns_answer"
		}
		_ = store.Append(event)
		dialer := &net.Dialer{Timeout: 5 * time.Second}
		tlsDialer := tls.Dialer{NetDialer: dialer, Config: &tls.Config{ServerName: host, MinVersion: tls.VersionTLS12, NextProtos: []string{"h2", "http/1.1"}}}
		connection, err := tlsDialer.DialContext(c, "tcp", net.JoinHostPort(host, "443"))
		tlsMeta := &telemetry.TLSMetadata{SNI: host, Synthetic: true}
		event = telemetry.Event{Node: *node, Kind: "diagnostic", Protocol: "tls", TLS: tlsMeta, Verdict: "unknown", Reasons: []string{"synthetic verified TLS probe; not browsing traffic"}}
		if err != nil {
			event.Phase = "tls_error"
			event.Verdict = "suspicious"
			event.Confidence = 0.35
			event.Reasons = []string{"verified TLS canary failed; investigate certificate, server and route before SNI-blocking attribution"}
		} else {
			state := connection.(*tls.Conn).ConnectionState()
			tlsMeta.Version = tls.VersionName(state.Version)
			tlsMeta.ALPN = state.NegotiatedProtocol
			if len(state.PeerCertificates) > 0 {
				sum := sha256.Sum256(state.PeerCertificates[0].RawSubjectPublicKeyInfo)
				tlsMeta.Fingerprint = hex.EncodeToString(sum[:])
			}
			event.Phase = "tls_success"
			event.Verdict = "normal"
			event.Confidence = 0.8
			_ = connection.Close()
		}
		_ = store.Append(event)
	}
	run()
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			run()
		}
	}
}
func main() {
	flag.Parse()
	log.SetFlags(0)
	if *node == "" || *interfaces == "" {
		log.Fatal("required: -node and explicit -interfaces")
	}
	allowed := map[uint16]bool{}
	values := []uint16{}
	for _, s := range strings.Split(*ports, ",") {
		v, e := strconv.Atoi(s)
		if e != nil || v < 1 || v > 65535 {
			log.Fatal("invalid carrier port")
		}
		if !allowed[uint16(v)] {
			allowed[uint16(v)] = true
			values = append(values, uint16(v))
		}
	}
	if len(values) > 32 {
		log.Fatal("too many carrier ports")
	}
	store := &telemetry.Store{Dir: *directory, MaxBytes: *maxBytes, Retention: 72 * time.Hour}
	asnDB = telemetry.OpenASN(*asnPath)
	log.Printf("quality aggregates: window=%v, asn ranges=%d", *qualityWindow, asnDB.Len())
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	go probeCanary(ctx, store, *probe)
	go qualityLoop(ctx, store)
	var wg sync.WaitGroup
	errors := make(chan error, 8)
	for _, name := range strings.Split(*interfaces, ",") {
		name = strings.TrimSpace(name)
		if name == "" {
			continue
		}
		wg.Add(1)
		go func(name string) {
			defer wg.Done()
			if err := observe(ctx, name, allowed, values, store); err != nil {
				errors <- err
				cancel()
			}
		}(name)
	}
	wg.Wait()
	close(errors)
	for err := range errors {
		log.Printf("metadata sensor stopped: %v", err)
		os.Exit(1)
	}
}

// qualityLoop закрывает окна агрегатов качества: пишет по событию netquality
// на группу (оператор/каскад × служба) и снимок за 24 ч в netquality.json.
func qualityLoop(ctx context.Context, store *telemetry.Store) {
	window := *qualityWindow
	if window < time.Minute {
		window = time.Minute
	}
	ticker := time.NewTicker(window)
	defer ticker.Stop()
	lastReload := time.Now()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-ticker.C:
			now = now.UTC()
			sums := quality.Flush(now)
			for _, s := range sums {
				if err := store.Append(telemetry.QualityEvent(*node, s)); err != nil {
					log.Printf("quality event: %v", err)
				}
			}
			writeQualitySnapshot(now, window, sums)
			if time.Since(lastReload) > 10*time.Minute {
				_ = asnDB.Reload()
				lastReload = time.Now()
			}
		}
	}
}

func writeQualitySnapshot(now time.Time, window time.Duration, last []telemetry.QualitySummary) {
	body, err := json.MarshalIndent(map[string]any{
		"generated":   now,
		"node":        *node,
		"window":      window.String(),
		"asn_ranges":  asnDB.Len(),
		"note":        "passive per-operator connection quality from VPN carrier headers; stalls = sender retransmits without ACK progress; last_24h medians are approximate",
		"last_window": last,
		"last_24h":    quality.Rolling(),
	}, "", "  ")
	if err != nil {
		return
	}
	tmp := filepath.Join(*directory, ".netquality.json.tmp")
	if err := os.WriteFile(tmp, body, 0600); err == nil {
		_ = os.Rename(tmp, filepath.Join(*directory, "netquality.json"))
	}
}
