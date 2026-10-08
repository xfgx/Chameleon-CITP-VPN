//go:build linux

package main

import (
	"chameleon/internal/telemetry"
	"encoding/json"
	"net/http/httptest"
	"testing"
	"time"
)

func TestQualitySnapshotAggregatesPerOperator(t *testing.T) {
	flowState.Lock()
	old := qualityRows
	qualityRows = nil
	now := time.Now().UTC()
	mk := func(at time.Time, group string, asn uint32, stalled int, bucket string, verdict string) telemetry.Event {
		s := telemetry.QualitySummary{Role: "inbound", Service: "tcp:9443", Group: group, ASN: asn, Flows: 10, Established: 10, Stalled: stalled, StallToClient: stalled, StallAtBytes: map[string]int{bucket: stalled}, MedianStallAtBytes: 20000, MedianLifetimeMS: 5000, BytesUp: 100, BytesDown: 200}
		return telemetry.Event{ID: telemetry.ID(), At: at, Node: "ru", Kind: "netquality", Protocol: s.Service, Role: s.Role, Group: group, ClientASN: asn, Verdict: verdict, Quality: &s}
	}
	rememberQualityLocked(telemetry.Event{ID: "flow", At: now, Kind: "flow"})
	rememberQualityLocked(mk(now.Add(-2*time.Hour), "MTS", 8359, 9, "1M+", "suspicious")) // вне периода 1 ч
	rememberQualityLocked(mk(now.Add(-20*time.Minute), "MTS", 8359, 4, "16-32K", "suspicious"))
	rememberQualityLocked(mk(now.Add(-10*time.Minute), "MTS", 8359, 3, "16-32K", "suspicious"))
	rememberQualityLocked(mk(now.Add(-5*time.Minute), "Beeline", 3216, 0, "<4K", "normal"))
	flowState.Unlock()
	t.Cleanup(func() { flowState.Lock(); qualityRows = old; flowState.Unlock() })

	snap := qualitySnapshot("", "", "", time.Hour, 2, now)
	ops := snap["operators"].([]*qualityOperator)
	if len(ops) != 2 || ops[0].Group != "MTS" {
		t.Fatalf("operators not grouped/sorted: %+v", ops)
	}
	m := ops[0]
	if m.Windows != 2 || m.SuspiciousWindows != 2 || m.Stalled != 7 || m.Flows != 20 || m.TypicalStallAt != "16-32K" || m.MedianStallAt != 20000 {
		t.Fatalf("bad MTS aggregate: %+v", m)
	}
	tot := snap["totals"].(qualityOperator)
	if tot.Flows != 30 || tot.Stalled != 7 || tot.Windows != 3 {
		t.Fatalf("bad totals: %+v", tot)
	}
	if w := snap["windows"].([]telemetry.Event); len(w) != 2 || w[0].Group != "Beeline" {
		t.Fatalf("windows must be newest-first and limited: %+v", w)
	}
	if snap := qualitySnapshot("", "outbound", "", time.Hour, 10, now); len(snap["operators"].([]*qualityOperator)) != 0 {
		t.Fatal("role filter ignored")
	}
	if snap := qualitySnapshot("", "", "3216", time.Hour, 10, now); len(snap["operators"].([]*qualityOperator)) != 1 {
		t.Fatal("ASN search ignored")
	}
	rec := httptest.NewRecorder()
	handleQuality(rec, httptest.NewRequest("GET", "/api/quality?since=3600&role=bogus", nil))
	var body map[string]any
	if rec.Code != 200 || json.Unmarshal(rec.Body.Bytes(), &body) != nil || body["window_count"].(float64) != 3 {
		t.Fatalf("handler: %d %s", rec.Code, rec.Body.String())
	}
}
