//go:build linux

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

var fWebsite = flag.String("website-monitor", "", "optional private build-host monitoring config")

type websiteConfig struct {
	URL       string `json:"url"`
	TokenFile string `json:"token_file"`
}

var websiteState = struct {
	sync.RWMutex
	data map[string]any
}{data: map[string]any{"error": "website monitoring not configured"}}

func pollWebsite() {
	if *fWebsite == "" {
		return
	}
	var config websiteConfig
	if readStrictJSON(*fWebsite, &config, 4096) != nil || config.URL != "https://vpn.example.com/vpn/internal/monitor" {
		setWebsiteError("website monitoring config rejected")
		return
	}
	st, e := os.Stat(config.TokenFile)
	if e != nil || st.Mode().Perm()&0077 != 0 {
		setWebsiteError("website credential unavailable")
		return
	}
	token, e := os.ReadFile(config.TokenFile)
	token = bytes.TrimSpace(token)
	if e != nil || len(token) < 32 || len(token) > 256 {
		setWebsiteError("website credential invalid")
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	r, e := http.NewRequestWithContext(ctx, "GET", config.URL, nil)
	if e != nil {
		setWebsiteError("website request unavailable")
		return
	}
	r.Header.Set("Authorization", "Bearer "+string(token))
	client := &http.Client{Timeout: 10 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	response, e := client.Do(r)
	if e != nil {
		setWebsiteError("build-host monitoring unreachable")
		return
	}
	defer response.Body.Close()
	if response.StatusCode != 200 {
		setWebsiteError(fmt.Sprintf("build-host monitoring HTTP %d", response.StatusCode))
		return
	}
	b, e := io.ReadAll(io.LimitReader(response.Body, 2<<20))
	var data map[string]any
	if e != nil || json.Unmarshal(b, &data) != nil || data["node"] != "build-host" {
		setWebsiteError("build-host monitoring response rejected")
		return
	}
	delete(data, "addresses")
	websiteState.Lock()
	websiteState.data = data
	websiteState.Unlock()
}
func setWebsiteError(message string) {
	websiteState.Lock()
	websiteState.data = map[string]any{"error": strings.TrimSpace(message), "at": time.Now().UTC()}
	websiteState.Unlock()
}
func websiteSnapshot() map[string]any {
	websiteState.RLock()
	defer websiteState.RUnlock()
	return websiteState.data
}
