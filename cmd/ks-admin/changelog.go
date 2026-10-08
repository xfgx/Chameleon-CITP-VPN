//go:build linux

package main

import (
	_ "embed"
	"encoding/json"
	"net/http"
	"os"
	"sort"
	"strings"
	"time"
)

// Вкладка «Журнал изменений»: встроенный в бинарник журнал работ (коммиты,
// выкладки, выпуски, откаты) плюс необязательный локальный файл с записями,
// добавленными на ноде без пересборки.

//go:embed changelog.json
var embeddedChangelog []byte

// changelogExtraPath — записи, дописанные на ноде (тот же формат).
var changelogExtraPath = "/var/lib/ks-admin/changelog.json"

type changelogEntry struct {
	ID        string   `json:"id"`
	At        string   `json:"at"`
	Type      string   `json:"type"`
	Component string   `json:"component"`
	Version   string   `json:"version,omitempty"`
	Title     string   `json:"title"`
	Details   []string `json:"details,omitempty"`
	Commit    string   `json:"commit,omitempty"`
	Source    string   `json:"source,omitempty"`
}

type changelogFile struct {
	Entries []changelogEntry `json:"entries"`
}

func loadChangelog() ([]changelogEntry, string) {
	var base changelogFile
	_ = json.Unmarshal(embeddedChangelog, &base)
	seen := map[string]bool{}
	out := make([]changelogEntry, 0, len(base.Entries))
	for _, e := range base.Entries {
		e.Source = "build"
		seen[e.ID] = true
		out = append(out, e)
	}
	extraErr := ""
	if raw, err := os.ReadFile(changelogExtraPath); err == nil {
		var extra changelogFile
		if len(raw) > 4<<20 {
			extraErr = "локальный журнал больше 4 МиБ — пропущен"
		} else if err := json.Unmarshal(raw, &extra); err != nil {
			extraErr = "локальный журнал не разобран: " + err.Error()
		} else {
			for _, e := range extra.Entries {
				if e.ID == "" || seen[e.ID] || strings.TrimSpace(e.Title) == "" {
					continue
				}
				e.Source = "local"
				seen[e.ID] = true
				out = append(out, e)
			}
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].At > out[j].At })
	return out, extraErr
}

func handleChangelog(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "GET required", 405)
		return
	}
	v := r.URL.Query()
	component, kind := v.Get("component"), v.Get("type")
	q := strings.ToLower(strings.TrimSpace(v.Get("q")))
	all, extraErr := loadChangelog()
	components := map[string]int{}
	types := map[string]int{}
	filtered := make([]changelogEntry, 0, len(all))
	for _, e := range all {
		components[e.Component]++
		types[e.Type]++
		if component != "" && e.Component != component {
			continue
		}
		if kind != "" && e.Type != kind {
			continue
		}
		if q != "" {
			hay := strings.ToLower(strings.Join(append([]string{e.Title, e.Version, e.Commit, e.Component, e.Type}, e.Details...), " "))
			if !strings.Contains(hay, q) {
				continue
			}
		}
		filtered = append(filtered, e)
	}
	latest := ""
	if len(all) > 0 {
		latest = all[0].At
	}
	writeJSON(w, map[string]any{
		"entries":     filtered,
		"total":       len(all),
		"components":  components,
		"types":       types,
		"latest_at":   latest,
		"extra_error": extraErr,
		"extra_path":  changelogExtraPath,
		"served_at":   time.Now().UTC().Format(time.RFC3339),
	})
}
