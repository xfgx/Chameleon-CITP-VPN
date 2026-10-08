//go:build linux

package main

import (
	"encoding/json"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func TestChangelogEmbeddedAndExtra(t *testing.T) {
	dir := t.TempDir()
	old := changelogExtraPath
	changelogExtraPath = filepath.Join(dir, "extra.json")
	defer func() { changelogExtraPath = old }()
	_ = os.WriteFile(changelogExtraPath, []byte(`{"entries":[{"id":"local-1","at":"2999-01-01T00:00:00Z","type":"ops","component":"node","title":"ручная запись"}]}`), 0o600)
	rec := httptest.NewRecorder()
	handleChangelog(rec, httptest.NewRequest("GET", "/api/changelog", nil))
	var body struct {
		Entries []changelogEntry `json:"entries"`
		Total   int              `json:"total"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body.Total < 50 || body.Entries[0].ID != "local-1" || body.Entries[0].Source != "local" {
		t.Fatalf("unexpected changelog: total=%d first=%+v", body.Total, body.Entries[0])
	}
	for _, e := range body.Entries {
		if e.ID == "" || e.At == "" || e.Title == "" || e.Type == "" || e.Component == "" {
			t.Fatalf("incomplete entry %+v", e)
		}
	}
	rec = httptest.NewRecorder()
	handleChangelog(rec, httptest.NewRequest("GET", "/api/changelog?component=android&q=4.5.2", nil))
	_ = json.Unmarshal(rec.Body.Bytes(), &body)
	if len(body.Entries) == 0 {
		t.Fatal("filter returned nothing")
	}
	for _, e := range body.Entries {
		if e.Component != "android" {
			t.Fatalf("filter leak %+v", e)
		}
	}
}
