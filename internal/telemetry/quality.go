package telemetry

import (
	"fmt"
	"sort"
	"sync"
	"time"
)

// QualitySummary — агрегат качества связи за окно по группе клиентов
// (оператор/ASN для входящих потоков, адрес каскада — для исходящих) и службе.
// Собирается из итоговых событий потоков; payload и адреса назначения
// пользователей сюда не попадают.
type QualitySummary struct {
	From               time.Time      `json:"from"`
	To                 time.Time      `json:"to"`
	Role               string         `json:"role"`
	Service            string         `json:"service"`
	Group              string         `json:"group"`
	ASN                uint32         `json:"asn,omitempty"`
	Flows              int            `json:"flows"`
	Established        int            `json:"established"`
	HandshakeTimeouts  int            `json:"handshake_timeouts"`
	ResetByServer      int            `json:"reset_by_server"`
	ResetByClient      int            `json:"reset_by_client"`
	OneWay             int            `json:"one_way"`
	Stalled            int            `json:"stalled"`
	StallRecovered     int            `json:"stall_recovered"`
	StallToClient      int            `json:"stall_to_client"`
	StallToServer      int            `json:"stall_to_server"`
	StallAtBytes       map[string]int `json:"stall_at_bytes,omitempty"`
	MedianStallAtBytes uint64         `json:"median_stall_at_bytes,omitempty"`
	MedianStallMS      int64          `json:"median_stall_ms,omitempty"`
	MedianLifetimeMS   int64          `json:"median_lifetime_ms,omitempty"`
	MedianHandshakeMS  int64          `json:"median_handshake_ms,omitempty"`
	BytesUp            uint64         `json:"bytes_up"`
	BytesDown          uint64         `json:"bytes_down"`
	Packets            uint64         `json:"packets"`
	Retransmissions    uint64         `json:"retransmissions"`
}

var stallBuckets = []struct {
	max   uint64
	label string
}{{4 << 10, "<4K"}, {8 << 10, "4-8K"}, {16 << 10, "8-16K"}, {32 << 10, "16-32K"}, {64 << 10, "32-64K"}, {256 << 10, "64-256K"}, {1 << 20, "256K-1M"}, {^uint64(0), "1M+"}}

func StallBucket(n uint64) string {
	for _, b := range stallBuckets {
		if n < b.max {
			return b.label
		}
	}
	return "1M+"
}

type qAcc struct {
	s                         QualitySummary
	stallBytes, stallMS, life []int64
	hs                        []int64
}

const (
	maxQualityGroups  = 256
	maxQualitySamples = 4096
)

// QualityAggregator считает QualitySummary по окнам и хранит историю за 24 ч.
type QualityAggregator struct {
	mu      sync.Mutex
	from    time.Time
	cur     map[string]*qAcc
	history []QualitySummary
}

func NewQualityAggregator(now time.Time) *QualityAggregator {
	return &QualityAggregator{from: now, cur: map[string]*qAcc{}}
}

func sample(dst []int64, v int64) []int64 {
	if len(dst) < maxQualitySamples {
		return append(dst, v)
	}
	return dst
}

// Add учитывает итоговое событие завершённого потока.
func (q *QualityAggregator) Add(e Event) {
	if e.Kind != "flow" {
		return
	}
	role, group := e.Role, e.Group
	if role == "" {
		role = "inbound"
	}
	if group == "" {
		group = "unknown"
	}
	service := fmt.Sprintf("%s:%d", e.Protocol, e.ServerPort)
	q.mu.Lock()
	defer q.mu.Unlock()
	key := role + "|" + service + "|" + group
	a := q.cur[key]
	if a == nil {
		if len(q.cur) >= maxQualityGroups {
			group = "other"
			key = role + "|" + service + "|" + group
			a = q.cur[key]
		}
		if a == nil {
			a = &qAcc{s: QualitySummary{Role: role, Service: service, Group: group, ASN: e.ClientASN}}
			q.cur[key] = a
		}
	}
	s := &a.s
	s.Flows++
	s.BytesUp += e.BytesUp
	s.BytesDown += e.BytesDown
	s.Packets += e.Packets
	s.Retransmissions += e.Retransmissions
	if e.Protocol == "tcp" {
		if e.HandshakeMS > 0 {
			s.Established++
			a.hs = sample(a.hs, e.HandshakeMS)
		}
		switch e.EndReason {
		case "handshake_timeout":
			s.HandshakeTimeouts++
		case "rst_by_server":
			s.ResetByServer++
		case "rst_by_client":
			s.ResetByClient++
		}
	} else if e.BytesUp == 0 || e.BytesDown == 0 {
		s.OneWay++
	}
	if e.DurationMS > 0 {
		a.life = sample(a.life, e.DurationMS)
	}
	if e.Stalls > 0 {
		s.Stalled++
		if e.StallRecovered {
			s.StallRecovered++
		}
		if e.StallDir == "to_client" {
			s.StallToClient++
		} else {
			s.StallToServer++
		}
		if s.StallAtBytes == nil {
			s.StallAtBytes = map[string]int{}
		}
		s.StallAtBytes[StallBucket(e.StallAtBytes)]++
		a.stallBytes = sample(a.stallBytes, int64(e.StallAtBytes))
		a.stallMS = sample(a.stallMS, e.StallMS)
	}
}

func median(v []int64) int64 {
	if len(v) == 0 {
		return 0
	}
	c := append([]int64(nil), v...)
	sort.Slice(c, func(i, j int) bool { return c[i] < c[j] })
	return c[len(c)/2]
}

// Flush закрывает текущее окно и возвращает его агрегаты.
func (q *QualityAggregator) Flush(now time.Time) []QualitySummary {
	q.mu.Lock()
	defer q.mu.Unlock()
	out := make([]QualitySummary, 0, len(q.cur))
	for _, a := range q.cur {
		s := a.s
		s.From, s.To = q.from, now
		s.MedianStallAtBytes = uint64(median(a.stallBytes))
		s.MedianStallMS = median(a.stallMS)
		s.MedianLifetimeMS = median(a.life)
		s.MedianHandshakeMS = median(a.hs)
		out = append(out, s)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Flows != out[j].Flows {
			return out[i].Flows > out[j].Flows
		}
		return out[i].Group < out[j].Group
	})
	q.history = append(q.history, out...)
	cutoff := now.Add(-24 * time.Hour)
	keep := q.history[:0]
	for _, s := range q.history {
		if s.To.After(cutoff) {
			keep = append(keep, s)
		}
	}
	q.history = keep
	q.cur = map[string]*qAcc{}
	q.from = now
	return out
}

// Rolling — сводка за последние 24 ч по (роль, служба, группа). Медианы
// приближённые: взвешенное по числу потоков среднее медиан окон.
func (q *QualityAggregator) Rolling() []QualitySummary {
	q.mu.Lock()
	defer q.mu.Unlock()
	type wsum struct {
		s                        QualitySummary
		wStall, wLife, wHS       int64
		sStallB, sStallMS, sLife int64
		sHS                      int64
	}
	m := map[string]*wsum{}
	for _, s := range q.history {
		key := s.Role + "|" + s.Service + "|" + s.Group
		w := m[key]
		if w == nil {
			w = &wsum{s: QualitySummary{From: s.From, Role: s.Role, Service: s.Service, Group: s.Group, ASN: s.ASN, StallAtBytes: map[string]int{}}}
			m[key] = w
		}
		t := &w.s
		if s.From.Before(t.From) {
			t.From = s.From
		}
		if s.To.After(t.To) {
			t.To = s.To
		}
		t.Flows += s.Flows
		t.Established += s.Established
		t.HandshakeTimeouts += s.HandshakeTimeouts
		t.ResetByServer += s.ResetByServer
		t.ResetByClient += s.ResetByClient
		t.OneWay += s.OneWay
		t.Stalled += s.Stalled
		t.StallRecovered += s.StallRecovered
		t.StallToClient += s.StallToClient
		t.StallToServer += s.StallToServer
		for k, v := range s.StallAtBytes {
			t.StallAtBytes[k] += v
		}
		t.BytesUp += s.BytesUp
		t.BytesDown += s.BytesDown
		t.Packets += s.Packets
		t.Retransmissions += s.Retransmissions
		if s.Stalled > 0 {
			w.wStall += int64(s.Stalled)
			w.sStallB += int64(s.MedianStallAtBytes) * int64(s.Stalled)
			w.sStallMS += s.MedianStallMS * int64(s.Stalled)
		}
		w.wLife += int64(s.Flows)
		w.sLife += s.MedianLifetimeMS * int64(s.Flows)
		if s.Established > 0 {
			w.wHS += int64(s.Established)
			w.sHS += s.MedianHandshakeMS * int64(s.Established)
		}
	}
	out := make([]QualitySummary, 0, len(m))
	for _, w := range m {
		s := w.s
		if w.wStall > 0 {
			s.MedianStallAtBytes = uint64(w.sStallB / w.wStall)
			s.MedianStallMS = w.sStallMS / w.wStall
		}
		if w.wLife > 0 {
			s.MedianLifetimeMS = w.sLife / w.wLife
		}
		if w.wHS > 0 {
			s.MedianHandshakeMS = w.sHS / w.wHS
		}
		if len(s.StallAtBytes) == 0 {
			s.StallAtBytes = nil
		}
		out = append(out, s)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Flows != out[j].Flows {
			return out[i].Flows > out[j].Flows
		}
		return out[i].Group < out[j].Group
	})
	return out
}

// QualityEvent превращает агрегат окна в событие телеметрии с вердиктом.
func QualityEvent(node string, s QualitySummary) Event {
	e := Event{Node: node, Kind: "netquality", Phase: "window", Protocol: s.Service, Verdict: "normal", Confidence: 0.5, Quality: &s, Group: s.Group, Role: s.Role, ClientASN: s.ASN}
	e.At = s.To
	e.Observation = fmt.Sprintf("%s %s %s: flows=%d est=%d stalled=%d (recovered %d) hs_timeouts=%d rst_srv=%d rst_cli=%d", s.Role, s.Service, s.Group, s.Flows, s.Established, s.Stalled, s.StallRecovered, s.HandshakeTimeouts, s.ResetByServer, s.ResetByClient)
	base := s.Established
	if base == 0 {
		base = s.Flows
	}
	switch {
	case s.Flows == 0:
		e.Verdict = "unknown"
	case s.Stalled >= 3 && s.Stalled*5 >= base:
		e.Verdict = "suspicious"
		e.Confidence = 0.5
		e.Reasons = []string{fmt.Sprintf("%d of %d flows stalled (typical volume before stall %s, median %d B); repeated freezes for one operator at similar volume point to throttling rather than random loss", s.Stalled, base, topBucket(s.StallAtBytes), s.MedianStallAtBytes)}
	case s.HandshakeTimeouts >= 3 && s.HandshakeTimeouts*5 >= s.Flows:
		e.Verdict = "suspicious"
		e.Confidence = 0.4
		e.Reasons = []string{fmt.Sprintf("%d of %d TCP connections never completed the handshake; possible blocking of the node address for this operator or packet loss", s.HandshakeTimeouts, s.Flows)}
	default:
		e.Reasons = []string{"no repeated stalls or handshake failures in this window; this does not prove absence of DPI"}
	}
	return e
}

func topBucket(h map[string]int) string {
	best, n := "-", 0
	for _, b := range stallBuckets {
		if h[b.label] > n {
			best, n = b.label, h[b.label]
		}
	}
	return best
}
