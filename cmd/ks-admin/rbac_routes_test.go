//go:build linux

package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestProductionRoutesEnforceRoles(t *testing.T) {
	old := sessions
	sessions = newSessStore()
	t.Cleanup(func() { sessions = old })
	tokens := map[string]string{}
	for _, role := range []string{"viewer", "operator", "admin"} {
		token, err := sessions.createAs(principal{User: "test-" + role, Role: role})
		if err != nil {
			t.Fatal(err)
		}
		tokens[role] = token
	}
	mux := adminMux()
	cases := []struct {
		role, method, path, body string
		status                   int
	}{
		{"", "GET", "/api/events", "", 401},
		{"viewer", "GET", "/api/events", "", 403},
		{"operator", "GET", "/api/events", "", 200},
		{"viewer", "GET", "/api/logs", "", 403},
		{"viewer", "GET", "/api/flows", "", 403},
		{"operator", "GET", "/api/activations", "", 403},
		{"operator", "GET", "/api/flows/capture", "", 403},
		{"operator", "POST", "/api/flows/capture-window", "{}", 403},
		{"operator", "POST", "/api/devices", "{}", 403},
		{"viewer", "POST", "/api/devices", "{}", 403},
		{"admin", "POST", "/api/devices", "{", 400},
	}
	for _, tc := range cases {
		t.Run(tc.role+"-"+tc.method+"-"+tc.path, func(t *testing.T) {
			req := httptest.NewRequest(tc.method, "https://admin.example"+tc.path, strings.NewReader(tc.body))
			if token := tokens[tc.role]; token != "" {
				req.AddCookie(&http.Cookie{Name: cookieName, Value: token})
				req.Header.Set("X-CSRF-Token", mutationToken(token))
			}
			req.Header.Set("Origin", "https://admin.example")
			req.Header.Set("Content-Type", "application/json")
			rec := httptest.NewRecorder()
			mux.ServeHTTP(rec, req)
			if rec.Code != tc.status {
				t.Fatalf("got HTTP %d, want %d", rec.Code, tc.status)
			}
		})
	}
}

func TestViewerCanStillLogout(t *testing.T) {
	old := sessions
	sessions = newSessStore()
	t.Cleanup(func() { sessions = old })
	token, err := sessions.createAs(principal{User: "viewer", Role: "viewer"})
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest("POST", "https://admin.example/logout", strings.NewReader("{}"))
	req.AddCookie(&http.Cookie{Name: cookieName, Value: token})
	req.Header.Set("Origin", "https://admin.example")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-CSRF-Token", mutationToken(token))
	rec := httptest.NewRecorder()
	if !requireMutation(rec, req) {
		t.Fatalf("read-only users must be able to end their own session: HTTP %d", rec.Code)
	}
}
