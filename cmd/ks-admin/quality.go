//go:build linux

package main

import (
	"chameleon/internal/telemetry"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Вкладка «Качество сети»: пятиминутные окна netquality от vpn-observer,
// сгруппированные по оператору (ASN), роли (вход клиентов / каскад) и порту.
// Кольцо заполняется тем же путём, что и flow-история, поэтому переживает
// перезапуск панели в пределах срока хранения flow-history (72 ч).

const maxQualityRows = 30000

var qualityRows []telemetry.Event // под flowState.Lock

func rememberQualityLocked(event telemetry.Event) {
	if event.Kind != "netquality" {
		return
	}
	qualityRows = append(qualityRows, event)
	if len(qualityRows) > maxQualityRows {
		qualityRows = append([]telemetry.Event(nil), qualityRows[len(qualityRows)-maxQualityRows:]...)
	}
}

type qualityOperator struct {
	Node              string         `json:"node"`
	Role              string         `json:"role"`
	Service           string         `json:"service"`
	Group             string         `json:"group"`
	ASN               uint32         `json:"asn,omitempty"`
	Windows           int            `json:"windows"`
	SuspiciousWindows int            `json:"suspicious_windows"`
	Flows             int            `json:"flows"`
	Established       int            `json:"established"`
	HandshakeTimeouts int            `json:"handshake_timeouts"`
	ResetByServer     int            `json:"reset_by_server"`
	ResetByClient     int            `json:"reset_by_client"`
	OneWay            int            `json:"one_way"`
	Stalled           int            `json:"stalled"`
	StallRecovered    int            `json:"stall_recovered"`
	StallToClient     int            `json:"stall_to_client"`
	StallToServer     int            `json:"stall_to_server"`
	StallAtBytes      map[string]int `json:"stall_at_bytes"`
	TypicalStallAt    string         `json:"typical_stall_at,omitempty"`
	MedianStallAt     uint64         `json:"median_stall_at_bytes,omitempty"`
	MedianStallMS     int64          `json:"median_stall_ms,omitempty"`
	MedianLifetimeMS  int64          `json:"median_lifetime_ms,omitempty"`
	MedianHandshakeMS int64          `json:"median_handshake_ms,omitempty"`
	BytesUp           uint64         `json:"bytes_up"`
	BytesDown         uint64         `json:"bytes_down"`
	Retransmissions   uint64         `json:"retransmissions"`
	Packets           uint64         `json:"packets"`
	LastVerdict       string         `json:"last_verdict"`
	LastAt            time.Time      `json:"last_at"`
	stallAt           []uint64
	stallMS           []int64
	lifetime          []int64
	handshake         []int64
}

var qualityBucketOrder = []string{"<4K", "4-8K", "8-16K", "16-32K", "32-64K", "64-256K", "256K-1M", "1M+"}

func medianU64(v []uint64) uint64 {
	if len(v) == 0 {
		return 0
	}
	sort.Slice(v, func(i, j int) bool { return v[i] < v[j] })
	return v[len(v)/2]
}
func medianI64(v []int64) int64 {
	if len(v) == 0 {
		return 0
	}
	sort.Slice(v, func(i, j int) bool { return v[i] < v[j] })
	return v[len(v)/2]
}

func qualitySnapshot(node, role, q string, since time.Duration, limit int, now time.Time) map[string]any {
	from := now.Add(-since)
	q = strings.ToLower(strings.TrimSpace(q))
	flowState.RLock()
	rows := make([]telemetry.Event, 0, 512)
	for _, e := range qualityRows {
		if e.At.Before(from) || (node != "" && e.Node != node) || (role != "" && e.Role != role) {
			continue
		}
		if q != "" && !strings.Contains(strings.ToLower(e.Group+" "+e.Protocol+" "+e.Observation+" "+strconv.FormatUint(uint64(e.ClientASN), 10)), q) {
			continue
		}
		rows = append(rows, e)
	}
	errs := map[string]string{}
	for k, v := range flowState.errors {
		errs[k] = v
	}
	flowState.RUnlock()
	sort.Slice(rows, func(i, j int) bool { return rows[i].At.Before(rows[j].At) })

	groups := map[string]*qualityOperator{}
	totals := qualityOperator{StallAtBytes: map[string]int{}}
	var lastAt time.Time
	for _, e := range rows {
		if e.At.After(lastAt) {
			lastAt = e.At
		}
		s := e.Quality
		key := e.Node + "|" + e.Role + "|" + e.Protocol + "|" + e.Group
		g := groups[key]
		if g == nil {
			g = &qualityOperator{Node: e.Node, Role: e.Role, Service: e.Protocol, Group: e.Group, ASN: e.ClientASN, StallAtBytes: map[string]int{}}
			groups[key] = g
		}
		g.Windows++
		totals.Windows++
		if e.Verdict == "suspicious" {
			g.SuspiciousWindows++
			totals.SuspiciousWindows++
		}
		g.LastVerdict, g.LastAt = e.Verdict, e.At
		if s == nil {
			continue
		}
		for _, t := range []*qualityOperator{g, &totals} {
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
			t.BytesUp += s.BytesUp
			t.BytesDown += s.BytesDown
			t.Retransmissions += s.Retransmissions
			t.Packets += s.Packets
			for b, n := range s.StallAtBytes {
				t.StallAtBytes[b] += n
			}
			if s.MedianStallAtBytes > 0 {
				t.stallAt = append(t.stallAt, s.MedianStallAtBytes)
			}
			if s.MedianStallMS > 0 {
				t.stallMS = append(t.stallMS, s.MedianStallMS)
			}
			if s.MedianLifetimeMS > 0 {
				t.lifetime = append(t.lifetime, s.MedianLifetimeMS)
			}
			if s.MedianHandshakeMS > 0 {
				t.handshake = append(t.handshake, s.MedianHandshakeMS)
			}
		}
	}
	finish := func(g *qualityOperator) {
		g.MedianStallAt, g.MedianStallMS = medianU64(g.stallAt), medianI64(g.stallMS)
		g.MedianLifetimeMS, g.MedianHandshakeMS = medianI64(g.lifetime), medianI64(g.handshake)
		best := 0
		for _, b := range qualityBucketOrder {
			if g.StallAtBytes[b] > best {
				g.TypicalStallAt, best = b, g.StallAtBytes[b]
			}
		}
	}
	operators := make([]*qualityOperator, 0, len(groups))
	for _, g := range groups {
		finish(g)
		operators = append(operators, g)
	}
	finish(&totals)
	sort.Slice(operators, func(i, j int) bool {
		a, b := operators[i], operators[j]
		if a.SuspiciousWindows != b.SuspiciousWindows {
			return a.SuspiciousWindows > b.SuspiciousWindows
		}
		if a.Stalled != b.Stalled {
			return a.Stalled > b.Stalled
		}
		return a.Flows > b.Flows
	})
	windows := rows
	if len(windows) > limit {
		windows = windows[len(windows)-limit:]
	}
	out := make([]telemetry.Event, len(windows))
	for i := range windows {
		out[len(windows)-1-i] = windows[i]
	}
	return map[string]any{
		"from": from, "to": now, "last_window_at": lastAt, "window_count": len(rows),
		"totals": totals, "operators": operators, "windows": out, "buckets": qualityBucketOrder,
		"source_errors": errs,
	}
}

func handleQuality(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "GET required", 405)
		return
	}
	v := r.URL.Query()
	since := time.Hour
	if n, e := strconv.Atoi(v.Get("since")); e == nil && n >= 300 && n <= 3*86400 {
		since = time.Duration(n) * time.Second
	}
	limit := 300
	if n, e := strconv.Atoi(v.Get("limit")); e == nil && n > 0 && n <= 2000 {
		limit = n
	}
	role := v.Get("role")
	if role != "" && role != "inbound" && role != "outbound" {
		role = ""
	}
	q := v.Get("q")
	if len(q) > 200 {
		q = q[:200]
	}
	writeJSON(w, qualitySnapshot(v.Get("node"), role, q, since, limit, time.Now().UTC()))
}
