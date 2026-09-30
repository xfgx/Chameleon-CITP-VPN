//go:build windows

package main

// Windows KS uses the existing chaossync wire format, not an alternative protocol.
// Keys stay in broker memory; no keyfile, command-line secret or traffic logging.
import (
	"chameleon/internal/chaossync"
	"chameleon/internal/clientactivation"
	"chameleon/internal/ksprobe"
	"context"
	"encoding/binary"
	"errors"
	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wintun"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"time"
)

type productKS struct {
	adapter  *wintun.Adapter
	ring     wintun.Session
	socket   *net.UDPConn
	cancel   context.CancelFunc
	workers  sync.WaitGroup
	once     sync.Once
	routes   *TunDevice
	up, down atomic.Uint64
	lastRx   atomic.Int64
}

func (k *productKS) stop() {
	if k == nil {
		return
	}
	k.once.Do(func() {
		if k.cancel != nil {
			k.cancel()
		}
		if k.socket != nil {
			k.socket.Close()
		}
		k.workers.Wait()
		if k.routes != nil {
			k.routes.Stop()
		}
		k.ring.End()
		if k.adapter != nil {
			k.adapter.Close()
		}
	})
}
func ksEcho(src, dst net.IP, seq uint16) []byte {
	p := make([]byte, 28)
	p[0] = 0x45
	binary.BigEndian.PutUint16(p[2:], 28)
	p[8] = 64
	p[9] = 1
	copy(p[12:16], src.To4())
	copy(p[16:20], dst.To4())
	p[20] = 8
	binary.BigEndian.PutUint16(p[24:], 0x4b53)
	binary.BigEndian.PutUint16(p[26:], seq)
	checksum := func(b []byte) uint16 {
		var n uint32
		for len(b) >= 2 {
			n += uint32(binary.BigEndian.Uint16(b))
			b = b[2:]
		}
		if len(b) > 0 {
			n += uint32(b[0]) << 8
		}
		for n>>16 != 0 {
			n = (n & 65535) + (n >> 16)
		}
		return ^uint16(n)
	}
	binary.BigEndian.PutUint16(p[10:], checksum(p[:20]))
	binary.BigEndian.PutUint16(p[22:], checksum(p[20:]))
	return p
}
func startProductKS(ctx context.Context, p clientactivation.Server) (_ *productKS, err error) {
	if e := checkKSClock(ctx); e != nil {
		return nil, e
	}
	own, peer := net.ParseIP(p.Inner).To4(), net.ParseIP(p.PeerInner).To4()
	if own == nil || peer == nil || own.Equal(peer) {
		return nil, productFailure("profile", errors.New("invalid KS addresses"))
	}
	master, e := chaossync.ParseMasterKey(p.KSKey)
	if e != nil {
		return nil, productFailure("profile", e)
	}
	host, port, e := net.SplitHostPort(p.Address)
	if e != nil {
		return nil, productFailure("profile", e)
	}
	ips, e := net.DefaultResolver.LookupIP(ctx, "ip4", host)
	if e != nil || len(ips) == 0 {
		return nil, productFailure("ks.handshake", errors.New("IPv4 resolution failed"))
	}
	pn, e := strconv.Atoi(port)
	if e != nil || pn < 1 || pn > 65535 {
		return nil, productFailure("profile", errors.New("invalid KS port"))
	}
	dest := &net.UDPAddr{IP: ips[0].To4(), Port: pn}
	if dest.IP == nil {
		return nil, productFailure("profile", errors.New("IPv4 required"))
	}
	k := &productKS{}
	complete := false
	// Assign a ring only once StartSession succeeds, never End a zero session.
	ad, e := wintun.CreateAdapter("ChameleonFree", "Chameleon VPN", nil)
	if e != nil {
		ad, e = wintun.OpenAdapter("ChameleonFree")
	}
	if e != nil {
		return nil, productFailure("wintun.start", e)
	}
	k.adapter = ad
	ring, e := ad.StartSession(0x800000)
	if e != nil {
		ad.Close()
		return nil, productFailure("wintun.start", e)
	}
	k.ring = ring
	defer func() {
		if !complete {
			k.stop()
		}
	}()
	tunName = "ChameleonFree"
	tunIP = p.Inner
	tunGW = p.PeerInner
	if e = run("netsh", "interface", "ip", "set", "address", "name="+tunName, "static", p.Inner, "255.255.255.0"); e != nil {
		return nil, productFailure("wintun.start", e)
	}
	if e = run("netsh", "interface", "ipv4", "set", "subinterface", tunName, "mtu=1300", "store=active"); e != nil {
		return nil, productFailure("wintun.start", e)
	}
	if e = run("netsh", "interface", "ipv4", "set", "dnsservers", "name="+tunName, "static", "127.0.0.1", "primary"); e != nil {
		return nil, productFailure("wintun.start", e)
	}
	k.socket, e = net.ListenUDP("udp4", &net.UDPAddr{Port: 0})
	if e != nil {
		return nil, productFailure("ks.handshake", e)
	}
	local, cancel := context.WithCancel(context.Background())
	k.cancel = cancel
	tx := chaossync.NewRotatingSender(master, "c2n", 8, time.Now())
	rx := chaossync.NewRotatingReceiver(master, "n2c", 8, time.Now())
	var sent, received, rejected atomic.Uint64
	var sendLock sync.Mutex
	failed := make(chan error, 1)
	send := func(b []byte) error {
		sendLock.Lock()
		defer sendLock.Unlock()
		tx.TickEpoch(time.Now())
		_, e := k.socket.WriteToUDP(tx.Seal(b), dest)
		if e == nil {
			sent.Add(1)
		}
		return e
	}
	confirmed := make(chan struct{}, 1)
	k.workers.Add(3)
	go func() {
		defer k.workers.Done()
		tick := time.NewTicker(2 * time.Second)
		defer tick.Stop()
		var seq uint16
		for {
			select {
			case <-local.Done():
				return
			case <-tick.C:
				seq++
				if e := send(ksEcho(own, peer, seq)); e != nil {
					select {
					case failed <- productFailure("ks.udp_send", e):
					default:
					}
				}
				_ = send(ksprobe.DNS(own, seq))
			}
		}
	}()
	go func() {
		defer k.workers.Done()
		b := make([]byte, 2048)
		for local.Err() == nil {
			n, source, e := k.socket.ReadFromUDP(b)
			if e != nil {
				if local.Err() == nil {
					select {
					case failed <- productFailure("ks.udp_read", e):
					default:
					}
				}
				return
			}
			if !source.IP.Equal(dest.IP) || source.Port != dest.Port {
				continue
			}
			received.Add(1)
			rx.TickEpoch(time.Now())
			packet, ok := rx.Ingest(append([]byte(nil), b[:n]...))
			if !ok || len(packet) < 20 || packet[0]>>4 != 4 || !net.IP(packet[16:20]).Equal(own) {
				rejected.Add(1)
				continue
			}
			k.lastRx.Store(time.Now().Unix())
			select {
			case confirmed <- struct{}{}:
			default:
			}
			if ksprobe.IsReply(packet) {
				continue
			}
			ihl := int(packet[0]&15) * 4
			if ihl >= 20 && len(packet) >= ihl+8 && packet[9] == 1 && packet[ihl] == 0 && binary.BigEndian.Uint16(packet[ihl+4:]) == 0x4b53 {
				continue
			}
			target, e := k.ring.AllocateSendPacket(len(packet))
			if e != nil {
				continue
			}
			copy(target, packet)
			k.ring.SendPacket(target)
			k.down.Add(uint64(len(packet)))
		}
	}()
	go func() {
		defer k.workers.Done()
		for local.Err() == nil {
			packet, e := k.ring.ReceivePacket()
			if errors.Is(e, windows.ERROR_NO_MORE_ITEMS) {
				windows.WaitForSingleObject(k.ring.ReadWaitEvent(), 100)
				continue
			}
			if e != nil {
				return
			}
			copyPacket := append([]byte(nil), packet...)
			k.ring.ReleaseReceivePacket(packet)
			if len(copyPacket) < 20 || copyPacket[0]>>4 != 4 || net.IP(copyPacket[16:20]).Equal(dest.IP) {
				continue
			}
			if send(copyPacket) == nil {
				k.up.Add(uint64(len(copyPacket)))
			}
		}
	}()
	if e := send(ksEcho(own, peer, 0)); e != nil {
		return nil, productFailure("ks.udp_send", e)
	}
	_ = send(ksprobe.DNS(own, 0))
	timer := time.NewTimer(16 * time.Second)
	defer timer.Stop()
	select {
	case failure := <-failed:
		return nil, failure
	case <-ctx.Done():
		return nil, productFailure("ks.handshake", ctx.Err())
	case <-timer.C:
		return nil, productFailure(ksHandshakeStage(received.Load()), &ksHandshakeFailure{sent.Load(), received.Load(), rejected.Load()})
	case <-confirmed:
	}
	if e = addProductGuards(); e != nil {
		return nil, productFailure("firewall", e)
	}
	// Routes are enabled only after an AEAD-authenticated node reply and privacy guards.
	store := &Store{Servers: []ServerEntry{{Addr: dest.String()}}}
	manager := NewManager(store, 8*time.Second, 40*time.Millisecond, "auto", "", nil)
	manager.quiet = true
	k.routes = NewTun(manager)
	index, e := tunIfIndex()
	if e != nil {
		return nil, productFailure("wintun.start", e)
	}
	if e = k.routes.setupRoutes(index); e != nil {
		return nil, productFailure("wintun.start", e)
	}
	// Disable offloads on our adapter only: userspace sends complete checksums.
	_, _ = runOut("powershell", "-NoProfile", "-NonInteractive", "-Command", "$a=Get-NetAdapter -InterfaceIndex "+index+"; $a | Disable-NetAdapterChecksumOffload -TcpIPv4 -UdpIPv4 -Confirm:$false -ErrorAction SilentlyContinue; $a | Disable-NetAdapterLso -IPv4 -Confirm:$false -ErrorAction SilentlyContinue")
	complete = true
	return k, nil
}
