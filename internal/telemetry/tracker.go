package telemetry

import (
	"fmt"
	"net/netip"
	"strconv"
	"time"
)

// Признак «замирания» потока: отправитель повторяет уже отправленные данные,
// а подтверждения от получателя не продвигаются дольше stallMinSilence.
// Так выглядит целевое замедление или «заморозка» соединения после N байт
// (так ТСПУ режет трафик к зарубежным хостингам), но так же выглядят и обычные
// потери на пути. Поэтому поток получает лишь «suspicious», а выводы делаются
// по агрегатам (QualityAggregator): доля замерших потоков по оператору и
// типичный объём до замирания.
const (
	stallMinRetx    = 2
	stallMinSilence = 2 * time.Second
)

type trackedFlow struct {
	Event
	Last        time.Time
	LastEmit    time.Time
	SYN         bool
	SYNACK      bool
	Established bool
	SeqSeen     [2]uint32
	SeqSet      [2]bool
	TTLSeen     [2]uint8
	FinSeen     [2]bool
	Headers     []CapturedHeader

	clientDir      int          // направление пакетов, которые шлёт клиент
	seqEnd         [2]uint32    // максимальный конец отправленных данных
	seqEndSet      [2]bool      //
	maxAck         [2]uint32    // максимальный ACK, отправленный направлением
	ackSet         [2]bool      //
	progressAt     [2]time.Time // когда данные направления в последний раз подтверждены
	sentAtProgress [2]uint64    // байт данных, отправленных направлением к этому моменту
	sent           [2]uint64    // байт данных (без повторов), отправленных направлением
	retxSince      [2]int       // повторов направления с последнего подтверждения
	stallOpen      bool
	stallDir       int
	stallStart     time.Time
}
type Tracker struct {
	Node           string
	Interface      string
	MTU            int
	CaptureDir     string
	CaptureEnabled bool
	Flows          map[string]*trackedFlow
	Dropped        uint64
	Evicted        uint64
	// ServerPorts — порты служб VPN: сторона с таким портом считается сервером.
	ServerPorts map[uint16]bool
	// Local — адреса самой ноды: если клиент — нода, поток исходящий (каскад).
	Local map[string]bool
	// Resolve — оператор клиента по IP (ASN и название); может быть nil.
	Resolve func(ip string) (uint32, string)
	// OnEnd получает итоговое событие каждого завершённого потока.
	OnEnd func(Event)
}

func flowKey(p Packet) string {
	a := p.Src + ":" + strconv.Itoa(int(p.SrcPort))
	b := p.Dst + ":" + strconv.Itoa(int(p.DstPort))
	if a > b {
		a, b = b, a
	}
	return p.Protocol + "|" + a + "|" + b
}

// seqAfter: a строго «после» b в арифметике последовательностей TCP.
func seqAfter(a, b uint32) bool { return int32(a-b) > 0 }

// ClientNet — подсеть клиента для группировки: /24 для IPv4, /48 для IPv6.
func ClientNet(ip string) string {
	a, err := netip.ParseAddr(ip)
	if err != nil {
		return ""
	}
	a = a.Unmap().WithZone("")
	bits := 48
	if a.Is4() {
		bits = 24
	}
	p, err := a.Prefix(bits)
	if err != nil {
		return ""
	}
	return p.String()
}

func (t *Tracker) classify(f *trackedFlow, p Packet) {
	switch {
	case t.ServerPorts[p.DstPort] && !t.ServerPorts[p.SrcPort]:
		f.clientDir, f.ServerPort = 0, p.DstPort
	case t.ServerPorts[p.SrcPort] && !t.ServerPorts[p.DstPort]:
		f.clientDir, f.ServerPort = 1, p.SrcPort
	case p.Protocol == "tcp" && p.Flags&18 == 18:
		f.clientDir, f.ServerPort = 1, p.SrcPort
	default:
		f.clientDir, f.ServerPort = 0, p.DstPort
	}
	clientIP, serverIP := p.Src, p.Dst
	if f.clientDir == 1 {
		clientIP, serverIP = p.Dst, p.Src
	}
	if t.Local[clientIP] {
		f.Role = "outbound"
		f.Group = "cascade " + serverIP
		return
	}
	f.Role = "inbound"
	f.ClientNet = ClientNet(clientIP)
	if t.Resolve != nil {
		f.ClientASN, f.ClientOrg = t.Resolve(clientIP)
	}
	switch {
	case f.ClientASN != 0:
		f.Group = fmt.Sprintf("AS%d %s", f.ClientASN, f.ClientOrg)
	default:
		f.Group = "unknown"
	}
}

func (f *trackedFlow) dirLabel(d int) string {
	if d == f.clientDir {
		return "to_server"
	}
	return "to_client"
}

func (f *trackedFlow) closeStall(now time.Time, recovered bool) {
	if !f.stallOpen {
		return
	}
	if ms := now.Sub(f.stallStart).Milliseconds(); ms > f.StallMS {
		f.StallMS = ms
	}
	if recovered {
		f.StallRecovered = true
	}
	f.stallOpen = false
}

func (f *trackedFlow) checkStall(now time.Time) bool {
	if f.stallOpen {
		return false
	}
	for d := 0; d < 2; d++ {
		o := 1 - d
		outstanding := f.seqEndSet[d] && (!f.ackSet[o] || seqAfter(f.seqEnd[d], f.maxAck[o]))
		if f.retxSince[d] < stallMinRetx || f.progressAt[d].IsZero() || !outstanding || now.Sub(f.progressAt[d]) < stallMinSilence {
			continue
		}
		f.stallOpen, f.stallDir, f.stallStart = true, d, f.progressAt[d]
		f.Stalls++
		if f.Stalls == 1 {
			f.StallAtBytes = f.sentAtProgress[d]
			f.StallDir = f.dirLabel(d)
		}
		f.Verdict = "suspicious"
		f.Confidence = 0.4
		f.Reasons = append(f.Reasons, fmt.Sprintf("flow stalled %s after %d payload bytes: sender retransmits without ACK progress for >=%v; consistent with throttling/blackholing on path (TSPU-style freeze) or plain loss - judge by per-operator aggregates", f.dirLabel(d), f.sentAtProgress[d], stallMinSilence))
		return true
	}
	return false
}

func (t *Tracker) end(f *trackedFlow, now time.Time, reason string) {
	f.closeStall(now, false)
	if f.EndReason == "" {
		f.EndReason = reason
	}
}

func (t *Tracker) Observe(p Packet, now time.Time) []Event {
	if t.Flows == nil {
		t.Flows = map[string]*trackedFlow{}
	}
	key := flowKey(p)
	f := t.Flows[key]
	out := []Event{}
	if f == nil {
		if len(t.Flows) >= 4096 {
			t.Evicted++
			return out
		}
		id := ID()
		f = &trackedFlow{Event: Event{At: now, Node: t.Node, Kind: "flow", FlowID: id, Interface: t.Interface, SrcIP: p.Src, DstIP: p.Dst, SrcPort: p.SrcPort, DstPort: p.DstPort, Protocol: p.Protocol, Phase: "observed", Started: now, MTU: t.MTU, Verdict: "unknown", Reasons: []string{}, Missing: []string{"encrypted application handshake", "user browsing DNS/SNI/QUIC (not collected)", "TCP window scale and option bytes (not stored)"}}, Last: now}
		t.classify(f, p)
		t.Flows[key] = f
	}
	direction := 0
	if p.Src != f.SrcIP || p.SrcPort != f.SrcPort {
		direction = 1
	}
	f.Last = now
	f.At = now
	f.DurationMS = now.Sub(f.Started).Milliseconds()
	f.Packets++
	f.TCPFlags = Flags(p.Flags)
	f.Seq = p.Seq
	f.Ack = p.Ack
	f.Window = p.Window
	f.TTL = p.TTL
	f.Dropped = t.Dropped
	if direction == 0 {
		f.BytesUp += uint64(p.OriginalLen)
	} else {
		f.BytesDown += uint64(p.OriginalLen)
	}
	if t.CaptureEnabled && len(f.Headers) < 64 {
		f.Headers = append(f.Headers, CapturedHeader{now, p.OriginalLen, append([]byte(nil), p.Header...)})
	}
	critical := false
	ending := false
	if p.Protocol == "tcp" {
		if p.Flags&2 != 0 && p.Flags&16 == 0 {
			f.SYN = true
			f.Phase = "tcp_syn"
		}
		if p.Flags&18 == 18 {
			f.SYNACK = true
			f.Phase = "tcp_syn_ack"
		}
		if f.SYN && f.SYNACK && p.Flags&16 != 0 && p.Flags&2 == 0 {
			if !f.Established {
				f.HandshakeMS = now.Sub(f.Started).Milliseconds()
			}
			f.Established = true
			f.Phase = "tcp_established"
			if f.Verdict != "suspicious" {
				f.Verdict = "normal"
				f.Confidence = 0.7
				f.Reasons = []string{"TCP handshake observed; this does not prove absence of DPI"}
			}
		}
		if p.PayloadLen > 0 {
			if f.SeqSet[direction] && p.Seq == f.SeqSeen[direction] {
				f.Retransmissions++
			}
			f.SeqSeen[direction] = p.Seq
			f.SeqSet[direction] = true
			end := p.Seq + uint32(p.PayloadLen)
			if f.seqEndSet[direction] && !seqAfter(end, f.seqEnd[direction]) {
				f.retxSince[direction]++
			} else {
				if f.seqEndSet[direction] {
					f.sent[direction] += uint64(end - f.seqEnd[direction])
				} else {
					f.sent[direction] += uint64(p.PayloadLen)
				}
				f.seqEnd[direction] = end
				f.seqEndSet[direction] = true
			}
			if f.progressAt[direction].IsZero() {
				f.progressAt[direction] = now
			}
		}
		if p.Flags&16 != 0 && p.Flags&4 == 0 {
			o := 1 - direction
			if !f.ackSet[direction] || seqAfter(p.Ack, f.maxAck[direction]) {
				f.maxAck[direction] = p.Ack
				f.ackSet[direction] = true
				f.progressAt[o] = now
				f.sentAtProgress[o] = f.sent[o]
				f.retxSince[o] = 0
				if f.stallOpen && f.stallDir == o {
					f.closeStall(now, true)
				}
			}
		}
		if f.checkStall(now) {
			critical = true
		}
		if p.Flags&4 != 0 {
			f.RST++
			f.Phase = "tcp_reset"
			if old := f.TTLSeen[direction]; old > 0 && absInt(int(old)-int(p.TTL)) >= 16 && t.Dropped == 0 {
				f.Verdict = "suspicious"
				f.Confidence = 0.55
				f.Reasons = append(f.Reasons, "RST TTL differs from earlier packets in the same direction; possible injection or routing change, not proof of DPI/TSPU")
				critical = true
			}
			ending = true
			if direction == f.clientDir {
				t.end(f, now, "rst_by_client")
			} else {
				t.end(f, now, "rst_by_server")
			}
		}
		if p.Flags&1 != 0 {
			f.FIN++
			f.FinSeen[direction] = true
			f.Phase = "tcp_fin"
		}
		f.TTLSeen[direction] = p.TTL
		if !ending && f.FinSeen[0] && f.FinSeen[1] {
			ending = true
			t.end(f, now, "fin")
		}
	}
	if critical && t.CaptureEnabled && f.CaptureID == "" {
		id := ID()
		if WriteCapture(t.CaptureDir, id, f.Headers) == nil {
			f.CaptureID = id
		}
	}
	if f.LastEmit.IsZero() || now.Sub(f.LastEmit) >= 5*time.Second || critical || p.Flags&5 != 0 || ending {
		e := f.Event
		e.ID = ID()
		out = append(out, e)
		f.LastEmit = now
		if ending && t.OnEnd != nil {
			t.OnEnd(e)
		}
	}
	if ending {
		delete(t.Flows, key)
	}
	return out
}
func (t *Tracker) Sweep(now time.Time) []Event {
	out := []Event{}
	for key, f := range t.Flows {
		timeout := 5 * time.Minute
		if f.Protocol == "udp" {
			timeout = time.Minute
		}
		handshakeMissing := f.Protocol == "tcp" && f.SYN && !f.Established && now.Sub(f.Started) > 10*time.Second
		if handshakeMissing || now.Sub(f.Last) > timeout {
			if handshakeMissing {
				t.end(f, now, "handshake_timeout")
			} else {
				t.end(f, f.Last, "idle")
			}
			e := f.Event
			e.ID = ID()
			e.At = now
			e.DurationMS = now.Sub(f.Started).Milliseconds()
			e.Phase = "idle_expired"
			if handshakeMissing {
				e.Phase = "tcp_handshake_timeout"
				e.Verdict = "suspicious"
				e.Confidence = 0.3
				e.Reasons = []string{"no completed TCP handshake observed; server failure, packet loss, capture gaps or interference require controlled checks"}
			} else {
				e.DurationMS = f.Last.Sub(f.Started).Milliseconds()
			}
			out = append(out, e)
			if t.OnEnd != nil {
				t.OnEnd(e)
			}
			delete(t.Flows, key)
		}
	}
	return out
}
func absInt(n int) int {
	if n < 0 {
		return -n
	}
	return n
}
