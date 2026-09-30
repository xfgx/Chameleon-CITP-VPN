//go:build linux

package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"
)

type logRecord struct {
	At      time.Time `json:"at"`
	Level   string    `json:"level"`
	Node    string    `json:"node,omitempty"`
	Source  string    `json:"source"`
	Actor   string    `json:"actor,omitempty"`
	Message string    `json:"message"`
}

var auditState = struct {
	sync.Mutex
	rows []logRecord
	path string
}{}
var jsonlMu sync.Mutex
var secretValue = regexp.MustCompile(`(?i)((?:authorization|password|passwd|пароль|bearer|token|secret|private[_-]?key|client[_-]?key|master[_-]?key|ks[_-]?key|cf[_-]?seed|write[_-]?token)\s*(?:[:=]\s*|\s+))[^\s,;]+`)
var authorizationValue = regexp.MustCompile(`(?i)(authorization\s*[:=]\s*)(?:bearer|basic)\s+[^\s,;]+`)
var opaqueValue = regexp.MustCompile(`[A-Za-z0-9_+/\-]{42,}={0,2}`)
var privatePEM = regexp.MustCompile(`(?s)-----BEGIN[^\n]*PRIVATE KEY-----.*?(?:-----END[^\n]*PRIVATE KEY-----|$)`)
var urlQuery = regexp.MustCompile(`(https?://[^\s?]+)\?[^\s]+`)

func redactLog(s string) string {
	s = privatePEM.ReplaceAllString(s, "[REDACTED PRIVATE KEY]")
	s = authorizationValue.ReplaceAllString(s, "${1}[REDACTED]")
	s = secretValue.ReplaceAllString(s, "${1}[REDACTED]")
	s = opaqueValue.ReplaceAllString(s, "[REDACTED TOKEN]")
	s = urlQuery.ReplaceAllString(s, "${1}?[REDACTED]")
	s = strings.ReplaceAll(s, "\x00", "")
	if len(s) > 2048 {
		s = string([]rune(s)[:min(len([]rune(s)), 1024)]) + "…"
	}
	return s
}

func initAudit(dir string) error {
	auditState.Lock()
	defer auditState.Unlock()
	auditState.path = filepath.Join(dir, "audit.jsonl")
	for _, path := range []string{auditState.path + ".1", auditState.path} {
		f, err := os.Open(path)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return err
		}
		scan := bufio.NewScanner(io.LimitReader(f, 9<<20))
		scan.Buffer(make([]byte, 8192), 65536)
		for scan.Scan() {
			var r logRecord
			if json.Unmarshal(scan.Bytes(), &r) == nil {
				r.Message = redactLog(r.Message)
				auditState.rows = append(auditState.rows, r)
				if len(auditState.rows) > 4000 {
					auditState.rows = auditState.rows[len(auditState.rows)-4000:]
				}
			}
		}
		_ = f.Close()
		if err := scan.Err(); err != nil {
			return fmt.Errorf("audit recovery: %w", err)
		}
	}
	return nil
}

func appendDurableJSONL(path string, value any, maxBytes int64, keep int, syncDisk bool) error {
	if path == "" {
		return errors.New("journal path is not configured")
	}
	b, err := json.Marshal(value)
	if err != nil {
		return err
	}
	jsonlMu.Lock()
	defer jsonlMu.Unlock()
	if st, err := os.Stat(path); err == nil && st.Size()+int64(len(b)+1) > maxBytes {
		if err := os.Remove(fmt.Sprintf("%s.%d", path, keep)); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		for i := keep - 1; i >= 1; i-- {
			from := fmt.Sprintf("%s.%d", path, i)
			if err := os.Rename(from, fmt.Sprintf("%s.%d", path, i+1)); err != nil && !errors.Is(err, os.ErrNotExist) {
				return err
			}
		}
		if err := os.Rename(path, path+".1"); err != nil {
			return err
		}
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
	if err != nil {
		return err
	}
	defer f.Close()
	if _, err = f.Write(append(b, '\n')); err != nil {
		return err
	}
	if syncDisk {
		return f.Sync()
	}
	return nil
}

func audit(actor, node, action, device, outcome string) error {
	r := logRecord{At: time.Now().UTC(), Level: "INFO", Node: node, Source: "audit", Actor: actor, Message: redactLog(strings.TrimSpace(action + " " + device + " · " + outcome))}
	if strings.Contains(outcome, "failed") || strings.Contains(outcome, "partial") {
		r.Level = "WARN"
	}
	auditState.Lock()
	defer auditState.Unlock()
	if auditState.path == "" {
		return errors.New("audit is not initialized")
	}
	if err := appendDurableJSONL(auditState.path, r, 8<<20, 4, true); err != nil {
		return err
	}
	auditState.rows = append(auditState.rows, r)
	if len(auditState.rows) > 4000 {
		auditState.rows = auditState.rows[len(auditState.rows)-4000:]
	}
	return nil
}

func filteredLogs(rows []logRecord, level, query, node string, since time.Time, limit int) []logRecord {
	out := make([]logRecord, 0)
	query = strings.ToLower(query)
	for i := len(rows) - 1; i >= 0; i-- {
		r := rows[i]
		if r.At.Before(since) || level != "" && r.Level != level || node != "" && r.Node != node {
			continue
		}
		r.Message = redactLog(r.Message)
		if query != "" && !strings.Contains(strings.ToLower(r.Message+" "+r.Source+" "+r.Actor), query) {
			continue
		}
		out = append(out, r)
		if len(out) >= limit {
			break
		}
	}
	return out
}

func handleLogs(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "GET required", 405)
		return
	}
	q := r.URL.Query()
	sinceSec := boundedInt(q.Get("since"), 3600, 60, 604800)
	limit := boundedInt(q.Get("limit"), 300, 1, 500)
	level := strings.ToUpper(q.Get("level"))
	if level != "" && level != "INFO" && level != "WARN" && level != "ERROR" && level != "DEBUG" {
		http.Error(w, "Некорректный уровень", 400)
		return
	}
	var rows []logRecord
	if q.Get("kind") == "audit" {
		if roleRank(requestPrincipal(r).Role) < roleRank("admin") {
			http.Error(w, "Insufficient role", 403)
			return
		}
		auditState.Lock()
		rows = append(rows, auditState.rows...)
		auditState.Unlock()
	} else {
		n, ok := findNode(q.Get("node"))
		if !ok {
			http.Error(w, "Неизвестная нода", 400)
			return
		}
		response, err := callNode(r.Context(), n, nodeRequest{Action: "logs", Since: sinceSec, Limit: 500})
		if err != nil {
			http.Error(w, "Журнал ноды недоступен: "+redactLog(err.Error()), 502)
			return
		}
		rows = response.Logs
	}
	node := ""
	if q.Get("kind") != "audit" {
		node = q.Get("node")
	}
	filtered := filteredLogs(rows, level, strings.TrimSpace(q.Get("q")), node, time.Now().Add(-time.Duration(sinceSec)*time.Second), limit)
	if q.Get("download") == "1" {
		w.Header().Set("Content-Type", "application/x-ndjson")
		w.Header().Set("Content-Disposition", `attachment; filename="chameleon-logs.jsonl"`)
		enc := json.NewEncoder(w)
		for _, record := range filtered {
			_ = enc.Encode(record)
		}
		return
	}
	writeJSON(w, map[string]any{"records": filtered, "truncated": len(rows) >= 500 || len(filtered) >= limit})
}
