//go:build linux

package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	_ "embed"
	"encoding/hex"
	"net/http"
	"strings"
)

//go:embed ui/console.html
var consoleHTML string

//go:embed ui/login.html
var consoleLoginHTML string

//go:embed ui/console.css
var consoleCSS string

//go:embed ui/console.js
var consoleJS string

func handleAssets(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "GET required", 405)
		return
	}
	switch r.URL.Path {
	case "/assets/console.css":
		w.Header().Set("Content-Type", "text/css; charset=utf-8")
		_, _ = w.Write([]byte(consoleCSS))
	case "/assets/console.js":
		w.Header().Set("Content-Type", "text/javascript; charset=utf-8")
		_, _ = w.Write([]byte(consoleJS))
	default:
		http.NotFound(w, r)
	}
}

func mutationToken(session string) string {
	mac := hmac.New(sha256.New, []byte(session))
	_, _ = mac.Write([]byte("chameleon-admin-mutation-v2"))
	return hex.EncodeToString(mac.Sum(nil))
}

func requireMutation(w http.ResponseWriter, r *http.Request) bool {
	if r.URL.Path != "/logout" && roleRank(requestPrincipal(r).Role) < roleRank("admin") {
		http.Error(w, "Insufficient role", 403)
		return false
	}
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		http.Error(w, "Требуется POST", http.StatusMethodNotAllowed)
		return false
	}
	ck, err := r.Cookie(cookieName)
	if err != nil || !sessions.valid(ck.Value) || !sameOrigin(r) || !strings.HasPrefix(r.Header.Get("Content-Type"), "application/json") || subtle.ConstantTimeCompare([]byte(r.Header.Get("X-CSRF-Token")), []byte(mutationToken(ck.Value))) != 1 {
		http.Error(w, "Запрос отклонён: проверьте сессию и CSRF", http.StatusForbidden)
		return false
	}
	return true
}

func handleConsole(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "GET required", 405)
		return
	}
	ck, _ := r.Cookie(cookieName)
	writeJSON(w, map[string]any{"csrf": mutationToken(ck.Value), "user": requestActor(r), "role": requestPrincipal(r).Role, "version": adminVersion, "nodes": clusterSnapshot(), "website": websiteSnapshot()})
}
