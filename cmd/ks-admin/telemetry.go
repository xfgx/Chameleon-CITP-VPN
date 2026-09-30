//go:build linux

package main

import (
	"chameleon/internal/telemetry"
	"context"
	"encoding/base64"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"net/http"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"
)

var flowState = struct {
	sync.RWMutex
	rows      []telemetry.Event
	cursor    map[string]string
	errors    map[string]string
	seen      map[string]bool
	seenOrder []string
	path      string
	store     *telemetry.Store
}{cursor: map[string]string{}, errors: map[string]string{}}

func rememberFlowLocked(event telemetry.Event) {
	if flowState.seen == nil {
		flowState.seen = map[string]bool{}
	}
	if flowState.seen[event.ID] {
		return
	}
	flowState.seen[event.ID] = true
	flowState.seenOrder = append(flowState.seenOrder, event.ID)
	if len(flowState.seenOrder) > 40000 {
		delete(flowState.seen, flowState.seenOrder[0])
		flowState.seenOrder = flowState.seenOrder[1:]
	}
	flowState.rows = append(flowState.rows, event)
	if len(flowState.rows) > 6000 {
		flowState.rows = flowState.rows[len(flowState.rows)-6000:]
	}
}
func initFlowTelemetry(dir string) {
	flowState.path = filepath.Join(dir, "telemetry-cursors.json")
	flowState.store = &telemetry.Store{Dir: filepath.Join(dir, "flow-history"), Retention: 72 * time.Hour, MaxBytes: 96 << 20}
	_ = readStrictJSON(flowState.path, &flowState.cursor, 65536)
	if flowState.cursor == nil {
		flowState.cursor = map[string]string{}
	}
	flowState.seen = map[string]bool{}
	cursor := ""
	for i := 0; i < 2000; i++ {
		batch, e := telemetry.Read(flowState.store.Dir, cursor, 1000)
		if e != nil {
			break
		}
		for _, event := range batch.Records {
			rememberFlowLocked(event)
		}
		cursor = batch.Cursor
		if !batch.More {
			break
		}
	}
}
func pollFlowTelemetry() {
	clusterState.RLock()
	nodes := append([]nodeConfig{}, clusterState.nodes...)
	clusterState.RUnlock()
	var wg sync.WaitGroup
	for _, n := range nodes {
		wg.Add(1)
		go func(n nodeConfig) {
			defer wg.Done()
			for i := 0; i < 4; i++ {
				flowState.RLock()
				cursor := flowState.cursor[n.ID]
				flowState.RUnlock()
				response, e := callNode(context.Background(), n, nodeRequest{Action: "telemetry", Cursor: cursor, Limit: 500})
				if e != nil || response.Telemetry == nil {
					flowState.Lock()
					if e != nil {
						flowState.errors[n.ID] = redactLog(e.Error())
					} else {
						flowState.errors[n.ID] = "metadata agent not enabled"
					}
					flowState.Unlock()
					return
				}
				batch := response.Telemetry
				for _, event := range batch.Records {
					event.Node = n.ID
					event.Normalize()
					flowState.RLock()
					duplicate := flowState.seen[event.ID]
					flowState.RUnlock()
					if duplicate {
						continue
					}
					if event.DeviceID != "" {
						attachFlowIdentity(&event)
					}
					if e = flowState.store.Append(event); e != nil {
						flowState.Lock()
						flowState.errors[n.ID] = "durable metadata storage unavailable"
						flowState.Unlock()
						return
					}
					flowState.Lock()
					rememberFlowLocked(event)
					flowState.Unlock()
				}
				flowState.Lock()
				flowState.cursor[n.ID] = batch.Cursor
				delete(flowState.errors, n.ID)
				if batch.Gap {
					flowState.errors[n.ID] = "source cursor gap: some events were rotated or unavailable"
				}
				e = marshalPrivate(flowState.path, flowState.cursor)
				if e != nil {
					flowState.errors[n.ID] = "durable cursor unavailable"
				}
				flowState.Unlock()
				if !batch.More {
					return
				}
			}
		}(n)
	}
	wg.Wait()
}
func attachFlowIdentity(e *telemetry.Event) {
	activationState.Lock()
	defer activationState.Unlock()
	for user, u := range activationState.data.Users {
		for _, d := range u.Devices {
			if d.DeviceID == e.DeviceID || d.KSDeviceID == e.DeviceID {
				e.UserID = user
				return
			}
		}
	}
}
func flowMatches(e telemetry.Event, q map[string][]string) bool {
	v := func(k string) string {
		values := q[k]
		if len(values) > 0 {
			return values[0]
		}
		return ""
	}
	if n := v("node"); n != "" && n != e.Node {
		return false
	}
	if id := v("user_id"); id != "" && id != e.UserID {
		return false
	}
	if id := v("device_id"); id != "" && id != e.DeviceID {
		return false
	}
	if id := v("flow_id"); id != "" && id != e.FlowID {
		return false
	}
	if ip := v("ip"); ip != "" && ip != e.SrcIP && ip != e.DstIP {
		return false
	}
	if p := v("protocol"); p != "" && p != e.Protocol {
		return false
	}
	if verdict := v("verdict"); verdict != "" && verdict != e.Verdict {
		return false
	}
	if domain := v("domain"); domain != "" {
		if (e.DNS == nil || !strings.Contains(e.DNS.Name, domain)) && (e.TLS == nil || !strings.Contains(e.TLS.SNI, domain)) {
			return false
		}
	}
	for _, field := range []string{"from", "to"} {
		if s := v(field); s != "" {
			date, err := time.Parse(time.RFC3339, s)
			if err != nil {
				return false
			}
			if field == "from" && e.At.Before(date) || field == "to" && e.At.After(date) {
				return false
			}
		}
	}
	if s := strings.ToLower(v("q")); s != "" {
		blob, _ := json.Marshal(e)
		if !strings.Contains(strings.ToLower(string(blob)), s) {
			return false
		}
	}
	return true
}
func safeCSV(s string) string {
	test := strings.TrimLeftFunc(s, unicode.IsSpace)
	if test != "" && strings.ContainsAny(test[:1], "=+-@") {
		return "'" + s
	}
	if strings.HasPrefix(s, "\t") || strings.HasPrefix(s, "\r") {
		return "'" + s
	}
	return s
}
func writeFlowCSVRow(writer *csv.Writer, e telemetry.Event) error {
	row := []string{e.At.Format(time.RFC3339Nano), e.Node, e.UserID, e.DeviceID, e.FlowID, e.SrcIP, strconv.Itoa(int(e.SrcPort)), e.DstIP, strconv.Itoa(int(e.DstPort)), e.Protocol, e.Phase, strconv.FormatInt(e.DurationMS, 10), strconv.FormatUint(e.BytesUp, 10), strconv.FormatUint(e.BytesDown, 10), e.TCPFlags, strconv.FormatUint(e.Retransmissions, 10), strconv.Itoa(int(e.Window)), strconv.Itoa(e.MTU), e.Verdict, strconv.FormatFloat(e.Confidence, 'f', 2, 64), strings.Join(e.Reasons, "; "), e.CaptureID}
	for i, s := range row {
		row[i] = safeCSV(s)
	}
	return writer.Write(row)
}
func handleFlows(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "GET required", 405)
		return
	}
	q := r.URL.Query()
	flowState.RLock()
	rows := append([]telemetry.Event{}, flowState.rows...)
	errors := map[string]string{}
	for k, v := range flowState.errors {
		errors[k] = v
	}
	store := flowState.store
	flowState.RUnlock()
	if store == nil {
		http.Error(w, "Telemetry not initialised", 503)
		return
	}
	if q.Get("export") == "csv" {
		if err := audit(requestActor(r), "", "flow.export", "", "retained metadata only"); err != nil {
			http.Error(w, "Audit unavailable", 503)
			return
		}
		w.Header().Set("Content-Type", "text/csv; charset=utf-8")
		w.Header().Set("Content-Disposition", `attachment; filename="chameleon-flow-metadata.csv"`)
		w.Header().Set("X-Export-Scope", "all-retained-metadata; max-age=72h; disk-cap=96MiB")
		writer := csv.NewWriter(w)
		_ = writer.Write([]string{"timestamp", "node", "user_id", "device_id", "flow_id", "source_ip", "source_port", "destination_ip", "destination_port", "protocol", "phase", "duration_ms", "bytes_up", "bytes_down", "flags", "retransmissions", "window", "mtu", "verdict", "confidence", "reason", "pcap_id"})
		cursor := ""
		for {
			if r.Context().Err() != nil {
				return
			}
			batch, err := telemetry.Read(store.Dir, cursor, 1000)
			if err != nil {
				return
			}
			for _, event := range batch.Records {
				if flowMatches(event, q) {
					if writeFlowCSVRow(writer, event) != nil {
						return
					}
				}
			}
			writer.Flush()
			if writer.Error() != nil {
				return
			}
			cursor = batch.Cursor
			if !batch.More {
				return
			}
		}
	}
	limit := boundedInt(q.Get("limit"), 300, 1, 2000)
	out := []telemetry.Event{}
	truncated := false
	next := ""
	gap := false
	scope := "live-window-6000-events"
	if q.Get("history") == "1" || q.Get("cursor") != "" {
		scope = "retained-72h-or-disk-cap"
		cursor := q.Get("cursor")
		scanned := 0
		for {
			if r.Context().Err() != nil {
				return
			}
			batch, err := telemetry.Read(store.Dir, cursor, min(1000, limit-len(out)))
			if err != nil {
				http.Error(w, "Invalid history cursor or unavailable metadata", 400)
				return
			}
			scanned += len(batch.Records)
			gap = gap || batch.Gap
			for _, e := range batch.Records {
				if flowMatches(e, q) {
					out = append(out, e)
				}
			}
			cursor = batch.Cursor
			if !batch.More {
				break
			}
			if len(out) >= limit || scanned >= 10000 {
				next = cursor
				truncated = true
				break
			}
		}
	} else {
		sort.SliceStable(rows, func(i, j int) bool { return rows[i].At.After(rows[j].At) })
		matched := 0
		for _, e := range rows {
			if flowMatches(e, q) {
				matched++
				if len(out) < limit {
					out = append(out, e)
				}
			}
		}
		truncated = matched > len(out)
	}
	writeJSON(w, map[string]any{"records": out, "truncated": truncated, "next_cursor": next, "cursor_gap": gap, "scope": scope, "source_errors": errors, "retention_hours": 72, "pcap_retention_minutes": 60, "payload_collected": false})
}
func handleFlowStream(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "GET required", 405)
		return
	}
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "Streaming unsupported", 503)
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("X-Accel-Buffering", "no")
	w.Header().Set("Cache-Control", "no-store")
	last := r.Header.Get("Last-Event-ID")
	deadline := time.NewTimer(25 * time.Second)
	defer deadline.Stop()
	tick := time.NewTicker(2 * time.Second)
	defer tick.Stop()
	send := func() {
		flowState.RLock()
		rows := append([]telemetry.Event{}, flowState.rows...)
		flowState.RUnlock()
		start := 0
		if last != "" {
			found := false
			for i, e := range rows {
				if e.ID == last {
					start = i + 1
					found = true
					break
				}
			}
			if !found {
				_, _ = fmt.Fprint(w, "event: gap\ndata: {\"message\":\"stream cursor outside in-memory window; use metadata export\"}\n\n")
				start = max(0, len(rows)-100)
			}
		} else {
			start = max(0, len(rows)-100)
		}
		for _, e := range rows[start:] {
			last = e.ID
			if !flowMatches(e, r.URL.Query()) {
				continue
			}
			b, _ := json.Marshal(e)
			_, _ = fmt.Fprintf(w, "id: %s\nevent: flow\ndata: %s\n\n", e.ID, b)
		}
		_, _ = fmt.Fprint(w, ": heartbeat\n\n")
		flusher.Flush()
	}
	send()
	for {
		select {
		case <-r.Context().Done():
			return
		case <-deadline.C:
			return
		case <-tick.C:
			send()
		}
	}
}
func handleCapture(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "GET required", 405)
		return
	}
	n, ok := findNode(r.URL.Query().Get("node"))
	id := r.URL.Query().Get("id")
	if !ok || !telemetry.ValidCaptureID(id) {
		http.Error(w, "Invalid capture", 400)
		return
	}
	response, e := callNode(r.Context(), n, nodeRequest{Action: "capture", CaptureID: id})
	if e != nil {
		http.Error(w, "Capture unavailable or expired", 404)
		return
	}
	b, e := base64.StdEncoding.DecodeString(response.Capture)
	if e != nil || len(b) > 8192 {
		http.Error(w, "Invalid capture response", 502)
		return
	}
	if audit(requestActor(r), n.ID, "capture.download", id, "header-only") != nil {
		http.Error(w, "Audit unavailable", 503)
		return
	}
	w.Header().Set("Content-Type", "application/vnd.tcpdump.pcap")
	w.Header().Set("Content-Disposition", `attachment; filename="headers-`+id+`.pcap"`)
	_, _ = w.Write(b)
}
func handleCaptureWindow(w http.ResponseWriter, r *http.Request) {
	if !requireMutation(w, r) {
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 1024)
	var in struct {
		Node    string `json:"node"`
		Seconds int    `json:"seconds"`
	}
	if decodeStrictJSON(r.Body, &in) != nil || in.Seconds < 0 || in.Seconds > 900 {
		http.Error(w, "Max 15 minute diagnostic window", 400)
		return
	}
	n, ok := findNode(in.Node)
	if !ok {
		http.Error(w, "Unknown node", 400)
		return
	}
	if audit(requestActor(r), n.ID, "capture.enable", "", fmt.Sprintf("header-only %d seconds", in.Seconds)) != nil {
		http.Error(w, "Audit unavailable", 503)
		return
	}
	response, e := callNode(r.Context(), n, nodeRequest{Action: "capture-window", Seconds: in.Seconds})
	if e != nil {
		http.Error(w, "Sensor action unavailable", 503)
		return
	}
	writeJSON(w, map[string]any{"expires_at": response.CaptureUntil, "payload_collected": false})
}
