package main

import (
	"log"
	"net/netip"
	"sync"
	"time"
)

// connGate — допуск входящих соединений в две фазы.
//
// До завершения рукопожатия (включая blackhole для зондов и забаненных)
// соединение занимает слот «ожидания». Слоты ожидания ограничены общим
// пределом, пределом на адрес (IPv4 или IPv6 /64) и на подсеть (/24 для
// IPv4, /48 для IPv6). Слот сеанса (-max-connections) выдаётся только после
// успешной аутентификации. Поэтому злоумышленник без ключа клиента не может
// занять слоты сеансов, а с одного адреса или подсети — все слоты ожидания.
type connGate struct {
	mu         sync.Mutex
	pending    int
	maxPending int
	perAddr    int
	perNet     int
	byAddr     map[string]int
	byNet      map[string]int
	sessions   chan struct{}

	rejectPending, rejectAddr, rejectNet, rejectSession uint64
}

func newConnGate(maxSessions, maxPending, perAddr, perNet int) *connGate {
	return &connGate{
		maxPending: maxPending,
		perAddr:    perAddr,
		perNet:     perNet,
		byAddr:     make(map[string]int),
		byNet:      make(map[string]int),
		sessions:   make(chan struct{}, maxSessions),
	}
}

// admitted — билет одного соединения. Методы вызываются из одной горутины.
type admitted struct {
	g        *connGate
	addr, nw string
	pending  bool
	session  bool
}

// admit выдаёт слот ожидания. Пустые addr/nw отключают пределы на адрес
// (так для CDN-фронта, где адрес — это IP Cloudflare, общий для всех).
func (g *connGate) admit(addr, nw string) (*admitted, bool) {
	g.mu.Lock()
	defer g.mu.Unlock()
	switch {
	case g.pending >= g.maxPending:
		g.rejectPending++
		return nil, false
	case addr != "" && g.byAddr[addr] >= g.perAddr:
		g.rejectAddr++
		return nil, false
	case nw != "" && g.byNet[nw] >= g.perNet:
		g.rejectNet++
		return nil, false
	}
	g.pending++
	if addr != "" {
		g.byAddr[addr]++
	}
	if nw != "" {
		g.byNet[nw]++
	}
	return &admitted{g: g, addr: addr, nw: nw, pending: true}, true
}

func (g *connGate) releasePendingLocked(a *admitted) {
	g.pending--
	if a.addr != "" {
		if g.byAddr[a.addr]--; g.byAddr[a.addr] <= 0 {
			delete(g.byAddr, a.addr)
		}
	}
	if a.nw != "" {
		if g.byNet[a.nw]--; g.byNet[a.nw] <= 0 {
			delete(g.byNet, a.nw)
		}
	}
}

// promote переводит аутентифицированное соединение в слот сеанса.
func (a *admitted) promote() bool {
	if a == nil {
		return true
	}
	if !a.pending {
		return a.session
	}
	select {
	case a.g.sessions <- struct{}{}:
	default:
		a.g.mu.Lock()
		a.g.rejectSession++
		a.g.mu.Unlock()
		return false
	}
	a.g.mu.Lock()
	a.g.releasePendingLocked(a)
	a.g.mu.Unlock()
	a.pending, a.session = false, true
	return true
}

// done освобождает занятый слот (ожидания или сеанса).
func (a *admitted) done() {
	if a == nil {
		return
	}
	if a.pending {
		a.g.mu.Lock()
		a.g.releasePendingLocked(a)
		a.g.mu.Unlock()
		a.pending = false
	}
	if a.session {
		<-a.g.sessions
		a.session = false
	}
}

// holdFor сокращает blackhole, когда пул ожидания заполнен на 3/4:
// под нагрузкой слоты должны быстрее возвращаться честным клиентам.
func (a *admitted) holdFor(h time.Duration) time.Duration {
	const short = 5 * time.Second
	if a == nil || h <= short {
		return h
	}
	a.g.mu.Lock()
	busy := a.g.pending*4 >= a.g.maxPending*3
	a.g.mu.Unlock()
	if busy {
		return short
	}
	return h
}

// reportLoop раз в 5 минут пишет в журнал, сколько соединений отклонено.
func (g *connGate) reportLoop(every time.Duration) {
	t := time.NewTicker(every)
	defer t.Stop()
	for range t.C {
		g.mu.Lock()
		p, a, n, s := g.rejectPending, g.rejectAddr, g.rejectNet, g.rejectSession
		g.rejectPending, g.rejectAddr, g.rejectNet, g.rejectSession = 0, 0, 0, 0
		pending, sessions := g.pending, len(g.sessions)
		g.mu.Unlock()
		if p+a+n+s > 0 {
			log.Printf("допуск: отклонено за %v — пул ожидания полон: %d, предел на адрес: %d, предел на подсеть: %d, нет слотов сеансов: %d (сейчас ожидают %d, сеансов %d)", every, p, a, n, s, pending, sessions)
		}
	}
}

// addrKeys: ключ адреса (IPv4 целиком, IPv6 — /64) и ключ подсети
// (/24 для IPv4, /48 для IPv6). Бан и пределы по IPv6 ставятся на /64:
// у одного абонента обычно целая /64, и полный адрес обходится сменой IID.
func addrKeys(ip string) (addr, nw string) {
	a, err := netip.ParseAddr(ip)
	if err != nil {
		return ip, ""
	}
	a = a.Unmap().WithZone("")
	if a.Is4() {
		p, _ := a.Prefix(24)
		return a.String(), p.String()
	}
	p64, _ := a.Prefix(64)
	p48, _ := a.Prefix(48)
	return p64.String(), p48.String()
}

// logLimiter — не больше burst строк в секунду, остальное считается и
// сообщается одной строкой: при атаке журнал не должен разрастаться.
type logLimiter struct {
	mu      sync.Mutex
	burst   int
	window  time.Time
	n       int
	dropped int
}

func (l *logLimiter) printf(format string, args ...any) {
	l.mu.Lock()
	now := time.Now()
	if now.Sub(l.window) >= time.Second {
		if l.dropped > 0 {
			log.Printf("журнал: подавлено %d однотипных сообщений о зондах/отказах", l.dropped)
		}
		l.window, l.n, l.dropped = now, 0, 0
	}
	if l.n >= l.burst {
		l.dropped++
		l.mu.Unlock()
		return
	}
	l.n++
	l.mu.Unlock()
	log.Printf(format, args...)
}

var authLog = &logLimiter{burst: 5}
