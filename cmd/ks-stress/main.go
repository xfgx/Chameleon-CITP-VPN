// ks-stress — STRESS-TEST tooling: N виртуальных KS-клиентов против ks-hub.
// Протокол тот же, что у mobilecore/ks.go: c2n Sender, n2c Receiver,
// keepalive ICMP echo каждые 2 с на внутренний адрес хаба.
package main

import (
	"encoding/binary"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"math/rand"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"chameleon/internal/chaossync"
)

const (
	kaID   uint16 = 0x4B53
	dataID uint16 = 0x5354
)

var (
	kaSent, kaRecv, dSent, dRecv, rxBad, sendErr, bytesUp, bytesDown atomic.Uint64
	rttMu                                                            sync.Mutex
	rtts                                                             []float64
	drtts                                                            []float64
	firstMu                                                          sync.Mutex
	firsts                                                           []float64
	hubInner                                                         net.IP
	stopAll                                                          atomic.Bool
)

type vuser struct {
	slot     int
	inner    net.IP
	conn     *net.UDPConn
	txMu     sync.Mutex
	tx       *chaossync.Sender
	rx       *chaossync.Receiver
	active   bool
	pend     sync.Map
	lastRx   atomic.Int64
	start    time.Time
	gotFirst atomic.Bool
	seq      atomic.Uint32
	quit     chan struct{}
}

func csum(b []byte) uint16 {
	var s uint32
	for i := 0; i+1 < len(b); i += 2 {
		s += uint32(binary.BigEndian.Uint16(b[i:]))
	}
	if len(b)%2 == 1 {
		s += uint32(b[len(b)-1]) << 8
	}
	for s>>16 != 0 {
		s = (s & 0xffff) + (s >> 16)
	}
	return ^uint16(s)
}

func echo(src, dst net.IP, id, seq uint16, payload int) []byte {
	p := make([]byte, 20+8+payload)
	p[0] = 0x45
	binary.BigEndian.PutUint16(p[2:], uint16(len(p)))
	p[8] = 64
	p[9] = 1
	copy(p[12:16], src)
	copy(p[16:20], dst)
	binary.BigEndian.PutUint16(p[10:], csum(p[:20]))
	ic := p[20:]
	ic[0] = 8
	binary.BigEndian.PutUint16(ic[4:], id)
	binary.BigEndian.PutUint16(ic[6:], seq)
	for i := 8; i < len(ic); i++ {
		ic[i] = byte(i)
	}
	binary.BigEndian.PutUint16(ic[2:], csum(ic))
	return p
}

func (u *vuser) send(pkt []byte) error {
	u.txMu.Lock()
	u.tx.TickEpoch(time.Now())
	w := u.tx.Seal(pkt)
	u.txMu.Unlock()
	_, err := u.conn.Write(w)
	if err != nil {
		sendErr.Add(1)
	} else {
		bytesUp.Add(uint64(len(w)))
	}
	return err
}

func (u *vuser) reader() {
	buf := make([]byte, 2048)
	for {
		n, err := u.conn.Read(buf)
		if err != nil {
			select {
			case <-u.quit:
				return
			default:
			}
			if stopAll.Load() || strings.Contains(err.Error(), "closed") {
				return
			}
			time.Sleep(50 * time.Millisecond) // ECONNREFUSED и т.п. — клиент не сдаётся
			continue
		}
		bytesDown.Add(uint64(n))
		u.rx.TickEpoch(time.Now())
		plain, ok := u.rx.Ingest(buf[:n])
		if !ok || len(plain) < 28 || plain[0]>>4 != 4 || plain[9] != 1 {
			rxBad.Add(1)
			continue
		}
		ihl := int(plain[0]&0x0f) * 4
		if len(plain) < ihl+8 || plain[ihl] != 0 {
			rxBad.Add(1)
			continue
		}
		id := binary.BigEndian.Uint16(plain[ihl+4:])
		seq := binary.BigEndian.Uint16(plain[ihl+6:])
		now := time.Now()
		u.lastRx.Store(now.UnixNano())
		if !u.gotFirst.Swap(true) {
			firstMu.Lock()
			firsts = append(firsts, now.Sub(u.start).Seconds()*1000)
			firstMu.Unlock()
		}
		key := uint32(id)<<16 | uint32(seq)
		if v, ok := u.pend.LoadAndDelete(key); ok {
			r := now.Sub(v.(time.Time)).Seconds() * 1000
			rttMu.Lock()
			if id == kaID {
				rtts = append(rtts, r)
			} else {
				drtts = append(drtts, r)
			}
			rttMu.Unlock()
		}
		if id == kaID {
			kaRecv.Add(1)
		} else {
			dRecv.Add(1)
		}
	}
}

func (u *vuser) run(pps int, size int) {
	go u.reader()
	// первый keepalive сразу (как клиент при старте), далее каждые 2 с со случайной фазой
	time.Sleep(time.Duration(rand.Intn(200)) * time.Millisecond)
	ka := time.NewTicker(2 * time.Second)
	defer ka.Stop()
	var dt *time.Ticker
	var dc <-chan time.Time
	if u.active && pps > 0 {
		dt = time.NewTicker(time.Second / time.Duration(pps))
		defer dt.Stop()
		dc = dt.C
	}
	sendKA := func() {
		s := uint16(u.seq.Add(1))
		u.pend.Store(uint32(kaID)<<16|uint32(s), time.Now())
		if u.send(echo(u.inner, hubInner, kaID, s, 8)) == nil {
			kaSent.Add(1)
		}
	}
	sendKA()
	var dseq uint16
	for {
		select {
		case <-u.quit:
			return
		case <-ka.C:
			sendKA()
			// чистим старые ожидания (>10 с)
			lim := time.Now().Add(-10 * time.Second)
			u.pend.Range(func(k, v any) bool {
				if v.(time.Time).Before(lim) {
					u.pend.Delete(k)
				}
				return true
			})
		case <-dc:
			dseq++
			if dseq%10 == 0 {
				u.pend.Store(uint32(dataID)<<16|uint32(dseq), time.Now())
			}
			if u.send(echo(u.inner, hubInner, dataID, dseq, size)) == nil {
				dSent.Add(1)
			}
		}
	}
}

func pct(v []float64, p float64) float64 {
	if len(v) == 0 {
		return -1
	}
	i := int(float64(len(v)-1) * p)
	return v[i]
}

type keyent struct {
	slot int
	key  []byte
}

func loadKeys(dir string) []keyent {
	ents, err := os.ReadDir(dir)
	if err != nil {
		log.Fatal(err)
	}
	var out []keyent
	for _, e := range ents {
		n := e.Name()
		if !strings.HasSuffix(n, ".key") {
			continue
		}
		s, _, _ := strings.Cut(strings.TrimSuffix(n, ".key"), "-")
		slot, err := strconv.Atoi(s)
		if err != nil {
			continue
		}
		k, err := chaossync.LoadMasterKey(filepath.Join(dir, n))
		if err != nil {
			log.Fatal(err)
		}
		out = append(out, keyent{slot, k})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].slot < out[j].slot })
	return out
}

func innerFor(base net.IP, slot int) net.IP {
	b := base.To4()
	return net.IPv4(b[0], b[1], byte(slot>>8), byte(slot)).To4()
}

type snap struct{ kaS, kaR, dS, dR, bad, se, up, down uint64 }

func take() snap {
	return snap{kaSent.Load(), kaRecv.Load(), dSent.Load(), dRecv.Load(), rxBad.Load(), sendErr.Load(), bytesUp.Load(), bytesDown.Load()}
}

func main() {
	hub := flag.String("hub", "", "host:port хаба")
	keyDir := flag.String("keys", "", "каталог ключей <slot>-<name>.key")
	inner := flag.String("innerbase", "10.97.0.0", "база /16 внутренних адресов")
	hubIn := flag.String("hubinner", "10.97.0.2", "внутренний адрес хаба")
	levels := flag.String("levels", "100,300,500,700,1000", "ступени числа пользователей")
	ramp := flag.Float64("ramp", 20, "секунд на подключение новых пользователей ступени (0 = все разом)")
	warm := flag.Float64("warm", 15, "секунд прогрева после ramp")
	hold := flag.Float64("hold", 60, "секунд измерения на ступени")
	activeFrac := flag.Float64("active", 0.1, "доля активных пользователей (с трафиком)")
	pps := flag.Int("pps", 20, "пакетов/с у активного пользователя")
	size := flag.Int("size", 1000, "байт полезной нагрузки у пакета активного пользователя")
	win := flag.Uint64("rxwindow", 512, "окно приёмника генератора (экономия CPU генератора)")
	portBase := flag.Int("portbase", 0, "персональные порты хаба: пользователь слота N шлёт на portbase+N (0 = общий порт из -hub)")
	out := flag.String("out", "", "файл JSON-итогов")
	abortFile := flag.String("abortfile", "/tmp/ks-stress.abort", "если файл появился — останов")
	flag.Parse()
	hubInner = net.ParseIP(*hubIn).To4()
	raddr, err := net.ResolveUDPAddr("udp4", *hub)
	if err != nil {
		log.Fatal(err)
	}
	keys := loadKeys(*keyDir)
	base := net.ParseIP(*inner)
	var lv []int
	for _, s := range strings.Split(*levels, ",") {
		n, _ := strconv.Atoi(strings.TrimSpace(s))
		if n > len(keys) {
			log.Fatalf("ключей %d < ступени %d", len(keys), n)
		}
		lv = append(lv, n)
	}
	var users []*vuser
	var results []map[string]any
	rng := rand.New(rand.NewSource(42))
	for _, target := range lv {
		if _, err := os.Stat(*abortFile); err == nil {
			log.Printf("ABORT: найден %s", *abortFile)
			break
		}
		add := target - len(users)
		t0 := time.Now()
		firstMu.Lock()
		firsts = nil
		firstMu.Unlock()
		for i := 0; i < add; i++ {
			k := keys[len(users)]
			dst := raddr
			if *portBase > 0 {
				dst = &net.UDPAddr{IP: raddr.IP, Port: *portBase + k.slot}
			}
			c, err := net.DialUDP("udp4", nil, dst)
			if err != nil {
				log.Fatalf("dial: %v", err)
			}
			_ = c.SetReadBuffer(1 << 20)
			now := time.Now()
			u := &vuser{slot: k.slot, inner: innerFor(base, k.slot), conn: c,
				tx:   chaossync.NewRotatingSender(k.key, "c2n", 8, now),
				rx:   chaossync.NewRotatingReceiver(k.key, "n2c", 8, now),
				quit: make(chan struct{}), start: now,
				active: rng.Float64() < *activeFrac}
			u.rx.SetWindow(*win)
			users = append(users, u)
			go u.run(*pps, *size)
			if *ramp > 0 && add > 0 {
				time.Sleep(time.Duration(*ramp / float64(add) * float64(time.Second)))
			}
		}
		rampDur := time.Since(t0).Seconds()
		time.Sleep(time.Duration(*warm * float64(time.Second)))
		rttMu.Lock()
		rtts, drtts = nil, nil
		rttMu.Unlock()
		a := take()
		tm := time.Now()
		var ms0 runtime.MemStats
		_ = ms0
		// промежуточный прогресс каждые 10 с
		steps := int(*hold / 10)
		if steps < 1 {
			steps = 1
		}
		aborted := false
		for s := 0; s < steps; s++ {
			time.Sleep(time.Duration(*hold / float64(steps) * float64(time.Second)))
			b := take()
			log.Printf("users=%d t=%.0fs ka %d/%d data %d/%d bad=%d", target, time.Since(tm).Seconds(), b.kaR-a.kaR, b.kaS-a.kaS, b.dR-a.dR, b.dS-a.dS, b.bad-a.bad)
			if _, err := os.Stat(*abortFile); err == nil {
				aborted = true
				break
			}
		}
		// ждём хвост ответов 3 с без учёта новых отправок — грубо: сравниваем с отправками до хвоста
		b := take()
		time.Sleep(3 * time.Second)
		c := take()
		el := time.Since(tm).Seconds() - 3
		alive := 0
		lim := time.Now().Add(-6 * time.Second).UnixNano()
		act := 0
		for _, u := range users {
			if u.lastRx.Load() > lim {
				alive++
			}
			if u.active {
				act++
			}
		}
		rttMu.Lock()
		r := append([]float64(nil), rtts...)
		d := append([]float64(nil), drtts...)
		rttMu.Unlock()
		sort.Float64s(r)
		sort.Float64s(d)
		firstMu.Lock()
		f := append([]float64(nil), firsts...)
		firstMu.Unlock()
		sort.Float64s(f)
		kaS := float64(b.kaS - a.kaS)
		kaR := float64(c.kaR - a.kaR)
		dS := float64(b.dS - a.dS)
		dR := float64(c.dR - a.dR)
		lossKA, lossD := 0.0, 0.0
		if kaS > 0 {
			lossKA = (1 - kaR/kaS) * 100
		}
		if dS > 0 {
			lossD = (1 - dR/dS) * 100
		}
		res := map[string]any{
			"users": target, "active_users": act, "alive_users": alive,
			"ramp_s": round(rampDur), "measure_s": round(el),
			"ka_sent": kaS, "ka_loss_pct": round(lossKA),
			"ka_rtt_ms_p50": round(pct(r, .5)), "ka_rtt_ms_p95": round(pct(r, .95)), "ka_rtt_ms_p99": round(pct(r, .99)), "ka_rtt_ms_max": round(pct(r, 1)),
			"data_sent": dS, "data_loss_pct": round(lossD),
			"data_rtt_ms_p50": round(pct(d, .5)), "data_rtt_ms_p95": round(pct(d, .95)), "data_rtt_ms_p99": round(pct(d, .99)),
			"up_mbit": round(float64(b.up-a.up) * 8 / el / 1e6), "down_mbit": round(float64(c.down-a.down) * 8 / el / 1e6),
			"connect_ms_p50": round(pct(f, .5)), "connect_ms_p95": round(pct(f, .95)), "connect_ms_max": round(pct(f, 1)), "new_users": len(f),
			"rx_bad": c.bad - a.bad, "send_err": c.se - a.se, "aborted": aborted,
			"at": time.Now().UTC().Format(time.RFC3339),
		}
		js, _ := json.Marshal(res)
		fmt.Println(string(js))
		results = append(results, res)
		if *out != "" {
			jb, _ := json.MarshalIndent(results, "", " ")
			_ = os.WriteFile(*out, jb, 0o644)
		}
		if aborted {
			log.Printf("ABORT по файлу")
			break
		}
	}
	stopAll.Store(true)
	for _, u := range users {
		close(u.quit)
		u.conn.Close()
	}
}

func round(x float64) float64 { return float64(int64(x*10+0.5)) / 10 }
