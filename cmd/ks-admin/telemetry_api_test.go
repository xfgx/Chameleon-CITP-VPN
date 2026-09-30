//go:build linux

package main

import (
	"bytes"
	"chameleon/internal/telemetry"
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestCSVFormulaProtection(t *testing.T) {
	for _, s := range []string{"=HYPERLINK(1)", " +1", "\t@cmd", "\r-1"} {
		if !strings.HasPrefix(safeCSV(s), "'") {
			t.Fatalf("unsafe CSV %q", s)
		}
	}
	if safeCSV("normal") != "normal" {
		t.Fatal("unnecessary mutation")
	}
}
func TestMetadataHistoryBeyondLiveWindow(t *testing.T) {
	dir := t.TempDir()
	history := filepath.Join(dir, "flow-history")
	if e := os.Mkdir(history, 0700); e != nil {
		t.Fatal(e)
	}
	var buf bytes.Buffer
	var final telemetry.Event
	now := time.Now().UTC()
	for i := 0; i < 331; i++ {
		final = telemetry.Event{ID: fmt.Sprintf("event-%04d", i), At: now.Add(time.Duration(i) * time.Millisecond), Node: "ru", Kind: "flow", FlowID: "flow-fixture", Protocol: "tcp", Verdict: "unknown"}
		b, _ := json.Marshal(final)
		buf.Write(b)
		buf.WriteByte('\n')
	}
	if e := os.WriteFile(filepath.Join(history, "events-"+now.Format("20060102-15")+".jsonl"), buf.Bytes(), 0600); e != nil {
		t.Fatal(e)
	}
	flowState.Lock()
	oldStore, oldRows := flowState.store, flowState.rows
	flowState.store = &telemetry.Store{Dir: history}
	flowState.rows = []telemetry.Event{final}
	flowState.Unlock()
	defer func() { flowState.Lock(); flowState.store = oldStore; flowState.rows = oldRows; flowState.Unlock() }()
	var out struct {
		Records []telemetry.Event `json:"records"`
		Next    string            `json:"next_cursor"`
		Scope   string            `json:"scope"`
	}
	w := httptest.NewRecorder()
	handleFlows(w, httptest.NewRequest("GET", "/api/flows", nil))
	if e := json.Unmarshal(w.Body.Bytes(), &out); e != nil || len(out.Records) != 1 {
		t.Fatal("live scope", e, w.Body.String())
	}
	cursor := ""
	all := map[string]bool{}
	for page := 0; page < 20; page++ {
		w = httptest.NewRecorder()
		handleFlows(w, httptest.NewRequest("GET", "/api/flows?history=1&limit=75&cursor="+url.QueryEscape(cursor), nil))
		out.Records = nil
		if e := json.Unmarshal(w.Body.Bytes(), &out); e != nil {
			t.Fatal(e, w.Body.String())
		}
		for _, e := range out.Records {
			if all[e.ID] {
				t.Fatal("duplicate history record")
			}
			all[e.ID] = true
		}
		cursor = out.Next
		if cursor == "" {
			break
		}
	}
	if len(all) != 331 {
		t.Fatal("history truncated to RAM", len(all))
	}
	oldPath := auditState.path
	auditState.path = filepath.Join(dir, "audit.jsonl")
	defer func() { auditState.path = oldPath }()
	w = httptest.NewRecorder()
	handleFlows(w, httptest.NewRequest("GET", "/api/flows?export=csv&limit=1", nil))
	if w.Code != 200 || strings.Count(w.Body.String(), "\n") != 332 {
		t.Fatal("export was truncated", w.Code, strings.Count(w.Body.String(), "\n"))
	}
}
