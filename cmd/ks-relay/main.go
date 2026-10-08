//go:build linux

// ks-relay — второе плечо (RU-нода ↔ зарубежный выход) с ПЕРСОНАЛЬНЫМ
// UDP-портом и ключом для каждого пользователя хаба.
//
// Было: все клиенты хаба шли в выход одним общим туннелем (ks2, один порт,
// один ключ, SNAT в один адрес). Стало: у пользователя слота N свой порт
// portbase+N на RU-ноде и свой сеанс на выходе, свой ключ
// K_N = HMAC-SHA256(master, "ks-relay/v1/slot/N"), и выход видит его
// собственный внутренний адрес (без общего SNAT на RU-ноде).
//
//	-role entry  (RU-нода): слушает portbase+N, TUN-пакет от 10.99.9.N → сеанс N.
//	-role exit   (выход):   сам инициирует сеансы на entry:portbase+N (работает
//	                        за NAT/без входящих правил), пакет к 10.99.9.N → сеанс N.
//
// Слот 0 — служебный: адреса концов TUN (-tunip/-ctlpeer). Анти-спуфинг:
// entry принимает от выхода только пакеты К адресу слота, exit — только ОТ
// адреса слота. Не прошедшее AEAD молча отбрасывается. Пустая датаграмма =
// keepalive.
package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"chameleon/internal/chaossync"
)

const relayVersion = "ks-relay/1 (2026-10-08)"

type session struct {
	slot    int
	conn    *net.UDPConn
	tx      *chaossync.Sender
	rx      *chaossync.Receiver
	peer    atomic.Pointer[net.UDPAddr]
	lastRx  atomic.Int64
	pktIn   atomic.Uint64
	pktOut  atomic.Uint64
	byteIn  atomic.Uint64
	byteOut atomic.Uint64
}

var (
	role                 string
	sessions             map[int]*session
	ownAddr, ctlPeerAddr net.IP
	userNet              *net.IPNet
	userBase             uint32
	tunDev               tunDevice
	portBase             int
	slotLo, slotHi       int

	cTunRd, cTunWr, cRecv, cBad, cSpoof, cNoSess, cNoPeer, cSent, cSendErr atomic.Uint64
)

func slotKey(master []byte, slot int) []byte {
	m := hmac.New(sha256.New, master)
	m.Write([]byte("ks-relay/v1/slot/" + strconv.Itoa(slot)))
	return m.Sum(nil)
}

func ip4u(ip net.IP) uint32 {
	b := ip.To4()
	return uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
}

func u2ip(v uint32) net.IP { return net.IPv4(byte(v>>24), byte(v>>16), byte(v>>8), byte(v)).To4() }

// slotFor — слот по внутреннему адресу (служебный 0 или пользовательский).
func slotFor(ip net.IP) int {
	if ip.Equal(ownAddr) || ip.Equal(ctlPeerAddr) {
		return 0
	}
	if !userNet.Contains(ip) {
		return -1
	}
	s := int(ip4u(ip) - userBase)
	if s < slotLo || s > slotHi {
		return -1
	}
	return s
}

func main() {
	flag.StringVar(&role, "role", "", "entry (RU-нода) или exit (зарубежный выход)")
	masterPath := flag.String("master", "/etc/ks-relay/master.key", "общий мастер-ключ плеча (0600)")
	slots := flag.String("slots", "11-250", "диапазон слотов пользователей хаба")
	flag.IntVar(&portBase, "portbase", 52000, "персональный порт слота N = portbase+N (слот 0 = служебный)")
	peerHost := flag.String("peer", "", "exit: адрес RU-ноды (entry)")
	tunName := flag.String("tun", "ksr0", "имя TUN")
	tunIP := flag.String("tunip", "10.96.0.1/30", "адрес этого конца TUN (CIDR)")
	ctlPeer := flag.String("ctlpeer", "10.96.0.2", "адрес другого конца TUN")
	unet := flag.String("usernet", "10.99.9.0/24", "сеть пользователей хаба")
	T := flag.Uint64("T", 8, "период эпохи, с")
	status := flag.String("status", "/run/ks-relay/status.json", "файл состояния ('' = нет)")
	flag.Parse()
	log.SetPrefix("[ks-relay] ")
	log.SetFlags(log.LstdFlags | log.Lmicroseconds)
	if role != "entry" && role != "exit" {
		log.Fatal("fail-closed: -role entry|exit")
	}
	lo, hi, ok := strings.Cut(*slots, "-")
	slotLo, _ = strconv.Atoi(lo)
	slotHi, _ = strconv.Atoi(hi)
	if !ok || slotLo < 1 || slotHi < slotLo || portBase < 1024 || portBase+slotHi > 65535 {
		log.Fatalf("fail-closed: -slots %q / -portbase %d", *slots, portBase)
	}
	ip, _, err := net.ParseCIDR(*tunIP)
	if err != nil {
		log.Fatalf("fail-closed: -tunip: %v", err)
	}
	ownAddr = ip.To4()
	ctlPeerAddr = net.ParseIP(*ctlPeer).To4()
	if _, userNet, err = net.ParseCIDR(*unet); err != nil || ownAddr == nil || ctlPeerAddr == nil {
		log.Fatalf("fail-closed: адреса: %v", err)
	}
	userBase = ip4u(userNet.IP)
	master, err := chaossync.LoadMasterKey(*masterPath)
	if err != nil {
		log.Fatalf("fail-closed: %v", err)
	}
	var peerIP net.IP
	if role == "exit" {
		if peerIP = net.ParseIP(*peerHost).To4(); peerIP == nil {
			log.Fatal("fail-closed: exit требует -peer <IPv4 RU-ноды>")
		}
	}
	// направления: entry шлёт r2x и принимает x2r, exit — наоборот
	outDir, inDir := "r2x", "x2r"
	if role == "exit" {
		outDir, inDir = "x2r", "r2x"
	}
	dev, ifname, err := openTUN(*tunName, *tunIP, false)
	if err != nil {
		log.Fatalf("fail-closed: TUN: %v", err)
	}
	tunDev = dev
	sessions = make(map[int]*session)
	now := time.Now()
	list := []int{0}
	for s := slotLo; s <= slotHi; s++ {
		list = append(list, s)
	}
	for _, s := range list {
		k := slotKey(master, s)
		se := &session{slot: s,
			tx: chaossync.NewRotatingSender(k, outDir, *T, now),
			rx: chaossync.NewRotatingReceiver(k, inDir, *T, now)}
		var c *net.UDPConn
		if role == "entry" {
			c, err = net.ListenUDP("udp4", &net.UDPAddr{Port: portBase + s})
		} else {
			c, err = net.ListenUDP("udp4", nil)
			se.peer.Store(&net.UDPAddr{IP: peerIP, Port: portBase + s})
		}
		if err != nil {
			log.Fatalf("fail-closed: сокет слота %d: %v", s, err)
		}
		_ = c.SetReadBuffer(1 << 20)
		se.conn = c
		sessions[s] = se
		go reader(se)
	}
	log.Printf("%s: роль %s, TUN %s %s↔%s, слоты 0,%d..%d, порты %d+N, пользователи %s",
		relayVersion, role, ifname, ownAddr, ctlPeerAddr, slotLo, slotHi, portBase, userNet)
	if role == "exit" {
		go keepalives()
	}
	if *status != "" {
		go statusLoop(*status)
	}
	go logLoop()
	go func() {
		sig := make(chan os.Signal, 2)
		signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
		<-sig
		tunDev.Close()
		os.Exit(0)
	}()
	tunPump()
}

// keepalives — exit держит NAT-сопоставления и даёт entry узнать свой адрес.
// Слоты разнесены по фазе, чтобы не слать пачкой.
func keepalives() {
	n := len(sessions)
	i := 0
	for _, se := range sessions {
		se := se
		d := time.Duration(i) * 2 * time.Second / time.Duration(n)
		i++
		go func() {
			time.Sleep(d)
			tk := time.NewTicker(2 * time.Second)
			for {
				send(se, nil)
				<-tk.C
			}
		}()
	}
}

func send(se *session, plain []byte) {
	peer := se.peer.Load()
	if peer == nil {
		cNoPeer.Add(1)
		return
	}
	se.tx.TickEpoch(time.Now())
	w := se.tx.Seal(plain)
	if _, err := se.conn.WriteToUDP(w, peer); err != nil {
		cSendErr.Add(1)
		return
	}
	cSent.Add(1)
	if len(plain) > 0 {
		se.pktOut.Add(1)
		se.byteOut.Add(uint64(len(plain)))
	}
}

func reader(se *session) {
	buf := make([]byte, 2048)
	for {
		n, src, err := se.conn.ReadFromUDP(buf)
		if err != nil {
			if strings.Contains(err.Error(), "closed") {
				return
			}
			time.Sleep(20 * time.Millisecond)
			continue
		}
		cRecv.Add(1)
		se.rx.TickEpoch(time.Now())
		plain, ok := se.rx.Ingest(buf[:n])
		if !ok {
			cBad.Add(1)
			continue
		}
		se.lastRx.Store(time.Now().Unix())
		if role == "entry" {
			se.peer.Store(src) // выход за NAT: отвечаем туда, откуда пришло
		}
		if len(plain) == 0 {
			if role == "entry" {
				send(se, nil) // ответный keepalive: выход видит, что плечо живо
			}
			continue
		}
		if len(plain) < 20 || plain[0]>>4 != 4 {
			cBad.Add(1)
			continue
		}
		var check net.IP
		if role == "entry" {
			check = net.IP(plain[16:20]) // к нам: адресат обязан быть владельцем слота
		} else {
			check = net.IP(plain[12:16]) // от RU: источник обязан быть владельцем слота
		}
		if slotFor(check) != se.slot {
			cSpoof.Add(1)
			continue
		}
		se.pktIn.Add(1)
		se.byteIn.Add(uint64(len(plain)))
		cTunWr.Add(1)
		if _, err := tunDev.Write(plain); err != nil {
			log.Printf("tun write: %v", err)
		}
	}
}

func tunPump() {
	buf := make([]byte, 2048)
	for {
		n, err := tunDev.Read(buf)
		if err != nil {
			log.Fatalf("tun read: %v", err)
		}
		cTunRd.Add(1)
		if n < 20 || buf[0]>>4 != 4 {
			continue
		}
		var key net.IP
		if role == "entry" {
			key = net.IP(buf[12:16]) // наружу идёт пакет пользователя: ищем по источнику
		} else {
			key = net.IP(buf[16:20]) // обратно к пользователю: ищем по адресату
		}
		s := slotFor(key)
		se := sessions[s]
		if s < 0 || se == nil {
			cNoSess.Add(1)
			continue
		}
		d := make([]byte, n)
		copy(d, buf[:n])
		send(se, d)
	}
}

func alive(se *session) bool {
	l := se.lastRx.Load()
	return l != 0 && time.Now().Unix()-l <= 10
}

func logLoop() {
	tk := time.NewTicker(10 * time.Second)
	for range tk.C {
		up := 0
		for _, se := range sessions {
			if alive(se) {
				up++
			}
		}
		log.Printf("сеансов живо=%d/%d tunRd=%d tunWr=%d recv=%d sent=%d bad=%d spoof=%d noSess=%d noPeer=%d sendErr=%d",
			up, len(sessions), cTunRd.Load(), cTunWr.Load(), cRecv.Load(), cSent.Load(), cBad.Load(),
			cSpoof.Load(), cNoSess.Load(), cNoPeer.Load(), cSendErr.Load())
	}
}

func statusLoop(path string) {
	_ = os.MkdirAll(filepath.Dir(path), 0o750)
	tk := time.NewTicker(5 * time.Second)
	for range tk.C {
		up := 0
		active := []map[string]any{}
		for _, se := range sessions {
			if alive(se) {
				up++
			}
			if se.pktIn.Load()+se.pktOut.Load() > 0 {
				active = append(active, map[string]any{"slot": se.slot, "port": portBase + se.slot,
					"alive": alive(se), "pktIn": se.pktIn.Load(), "pktOut": se.pktOut.Load(),
					"bytesIn": se.byteIn.Load(), "bytesOut": se.byteOut.Load()})
			}
		}
		doc := map[string]any{"version": relayVersion, "role": role, "time": time.Now().UTC().Format(time.RFC3339),
			"sessions": len(sessions), "alive": up, "control_alive": alive(sessions[0]),
			"portBase": portBase, "slots": fmt.Sprintf("%d-%d", slotLo, slotHi), "active": active,
			"totals": map[string]uint64{"tunRead": cTunRd.Load(), "tunWrite": cTunWr.Load(), "recv": cRecv.Load(),
				"sent": cSent.Load(), "bad": cBad.Load(), "spoof": cSpoof.Load(), "noSession": cNoSess.Load()}}
		b, _ := json.MarshalIndent(doc, "", " ")
		_ = os.WriteFile(path+".tmp", b, 0o640)
		_ = os.Rename(path+".tmp", path)
	}
}
