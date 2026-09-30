//go:build linux

package main

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"mime"
	"net/http"
	"os"
	"path/filepath"
	"strings"
)

type releaseItem struct {
	Name        string `json:"name"`
	Title       string `json:"title"`
	Platform    string `json:"platform"`
	Description string `json:"description"`
	SHA256      string `json:"sha256"`
	Size        int64  `json:"size"`
}

func releaseManifest() ([]releaseItem, error) {
	var items []releaseItem
	err := readStrictJSON(filepath.Join(*fReleases, "manifest.json"), &items, 65536)
	if errors.Is(err, os.ErrNotExist) {
		return []releaseItem{}, nil
	}
	if err != nil {
		return nil, err
	}
	if len(items) > 32 {
		return nil, errors.New("release manifest too large")
	}
	for _, item := range items {
		if filepath.Base(item.Name) != item.Name || strings.ContainsAny(item.Name, "\\\r\n\x00") || strings.HasPrefix(item.Name, ".") || len(item.SHA256) != 64 || item.Size <= 0 || item.Size > 512<<20 {
			return nil, errors.New("invalid release metadata")
		}
		if _, err := hex.DecodeString(item.SHA256); err != nil {
			return nil, err
		}
	}
	return items, nil
}
func handleReleases(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "GET required", 405)
		return
	}
	items, err := releaseManifest()
	if err != nil {
		http.Error(w, "Манифест релиза недоступен", 503)
		return
	}
	if r.URL.Path == "/api/releases" {
		writeJSON(w, map[string]any{"releases": items})
		return
	}
	name := strings.TrimPrefix(r.URL.Path, "/api/releases/")
	for _, item := range items {
		if item.Name != name {
			continue
		}
		path := filepath.Join(*fReleases, name)
		st, err := os.Lstat(path)
		if err != nil || !st.Mode().IsRegular() || st.Size() != item.Size {
			http.Error(w, "Артефакт недоступен", 503)
			return
		}
		f, err := os.Open(path)
		if err != nil {
			http.Error(w, "Артефакт недоступен", 503)
			return
		}
		defer f.Close()
		h := sha256.New()
		if _, err := io.Copy(h, f); err != nil || hex.EncodeToString(h.Sum(nil)) != item.SHA256 {
			http.Error(w, "Контрольная сумма не совпала; загрузка заблокирована", 503)
			return
		}
		_, _ = f.Seek(0, io.SeekStart)
		w.Header().Set("Content-Disposition", mime.FormatMediaType("attachment", map[string]string{"filename": name}))
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("X-Artifact-SHA256", item.SHA256)
		http.ServeContent(w, r, name, st.ModTime(), f)
		return
	}
	http.NotFound(w, r)
}
