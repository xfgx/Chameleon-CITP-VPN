package telemetry

import (
	"strconv"
	"time"
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
}

func flowKey(p Packet) string {
	a := p.Src + ":" + strconv.Itoa(int(p.SrcPort))
	b := p.Dst + ":" + strconv.Itoa(int(p.DstPort))
	if a > b {
		a, b = b, a
	}
	return p.Protocol + "|" + a + "|" + b
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
		}
		if p.Flags&1 != 0 {
			f.FIN++
			f.FinSeen[direction] = true
			f.Phase = "tcp_fin"
		}
		f.TTLSeen[direction] = p.TTL
	}
	if critical && t.CaptureEnabled && f.CaptureID == "" {
		id := ID()
		if WriteCapture(t.CaptureDir, id, f.Headers) == nil {
			f.CaptureID = id
		}
	}
	if f.LastEmit.IsZero() || now.Sub(f.LastEmit) >= 5*time.Second || critical || p.Flags&5 != 0 {
		e := f.Event
		e.ID = ID()
		out = append(out, e)
		f.LastEmit = now
	}
	if p.Flags&4 != 0 || f.FinSeen[0] && f.FinSeen[1] {
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
			}
			out = append(out, e)
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
