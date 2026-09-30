//go:build linux

package main

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func testPublic(t *testing.T) string {
	t.Helper()
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return base64.RawURLEncoding.EncodeToString(key.PublicKey().Bytes())
}
func TestAllowlistManagedAndExternal(t *testing.T) {
	pub := testPublic(t)
	other := testPublic(t)
	id := "a123456789abcdef"
	before := []byte("# existing\n" + other + "\n")
	after, err := mutateAllowlist(before, id, pub, false)
	if err != nil {
		t.Fatal(err)
	}
	again, err := mutateAllowlist(after, id, pub, false)
	if err != nil || string(again) != string(after) {
		t.Fatal("grant is not idempotent", err)
	}
	revoked, err := mutateAllowlist(after, id, pub, true)
	if err != nil || string(revoked) != string(before) {
		t.Fatal("revoke changed unrelated key", err)
	}
	if _, err := mutateAllowlist(before, id, other, true); err == nil {
		t.Fatal("external key was revocable")
	}
	if _, err := mutateAllowlist(before, "../../etc/passwd", pub, false); err == nil {
		t.Fatal("path traversal accepted")
	}
}
func TestLogSecretsAndBounds(t *testing.T) {
	for _, secret := range []string{"password=hunter2", "token=top-secret", "Authorization: Bearer sensitive", "cf_seed=really-secret", "ks_key=" + strings.Repeat("a", 43), "-----BEGIN PRIVATE KEY-----\nprivate material\n-----END PRIVATE KEY-----"} {
		got := redactLog(secret)
		if strings.Contains(got, "hunter2") || strings.Contains(got, "top-secret") || strings.Contains(got, "sensitive") || strings.Contains(got, "really-secret") || strings.Contains(got, "private material") {
			t.Fatalf("secret survived redaction: %q", got)
		}
	}
	if len(redactLog(strings.Repeat("q ", 4000))) > 4096 {
		t.Fatal("unbounded log")
	}
}
func TestStrictJSONRejectsTrailingAndUnknown(t *testing.T) {
	var input nodeRequest
	for _, s := range []string{`{"action":"status"} {}`, `{"action":"status","command":"rm"}`} {
		if decodeStrictJSON(strings.NewReader(s), &input) == nil {
			t.Fatal("accepted", s)
		}
	}
}
func TestMutationCSRFAndOrigin(t *testing.T) {
	sessions = newSessStore()
	token, _ := sessions.create()
	for _, tc := range []struct {
		origin, csrf string
		want         bool
	}{{"https://admin.example", mutationToken(token), true}, {"https://admin.example:444", mutationToken(token), false}, {"https://evil.example", mutationToken(token), false}, {"https://admin.example", "wrong", false}} {
		r := httptest.NewRequest(http.MethodPost, "https://admin.example/api/devices", strings.NewReader("{}"))
		r.Header.Set("Origin", tc.origin)
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("X-CSRF-Token", tc.csrf)
		r.AddCookie(&http.Cookie{Name: cookieName, Value: token})
		w := httptest.NewRecorder()
		if got := requireMutation(w, r); got != tc.want {
			t.Fatalf("origin %s got %v", tc.origin, got)
		}
	}
}
func TestAuditRecoversAndRotates(t *testing.T) {
	dir := t.TempDir()
	auditState.rows = nil
	if err := initAudit(dir); err != nil {
		t.Fatal(err)
	}
	if err := audit("operator", "ru", "grant", "device-1", "ok token=not-for-logs"); err != nil {
		t.Fatal(err)
	}
	auditState.rows = nil
	if err := initAudit(dir); err != nil {
		t.Fatal(err)
	}
	if len(auditState.rows) != 1 || strings.Contains(auditState.rows[0].Message, "not-for-logs") {
		t.Fatal("audit restore or masking failed")
	}
	p := filepath.Join(dir, "rotation.jsonl")
	for i := 0; i < 20; i++ {
		if err := appendDurableJSONL(p, map[string]string{"entry": strings.Repeat("x", 80)}, 150, 2, true); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := os.Stat(p + ".3"); !os.IsNotExist(err) {
		t.Fatal("retention unbounded")
	}
}
func TestPartialProvisionAndRevokeRetry(t *testing.T) {
	dir := t.TempDir()
	auditState.rows = nil
	if err := initAudit(dir); err != nil {
		t.Fatal(err)
	}
	if err := loadDevices(dir); err != nil {
		t.Fatal(err)
	}
	clusterState.nodes = []nodeConfig{{ID: "ru"}, {ID: "myserv"}}
	original := nodeApply
	defer func() { nodeApply = original }()
	offline := true
	nodeApply = func(_ context.Context, n nodeConfig, r nodeRequest) (nodeResponse, error) {
		if n.ID == "myserv" && offline {
			return nodeResponse{}, errors.New("offline")
		}
		return nodeResponse{}, nil
	}
	devicesState.rows = []managedDevice{{ID: "device123456789", Nodes: []string{"ru", "myserv"}, Protocol: "citp", PublicKey: testPublic(t), Created: time.Now(), Status: map[string]deviceNodeState{}}}
	if err := applyDeviceLocked(context.Background(), 0, "admin"); err != nil {
		t.Fatal(err)
	}
	if devicesState.rows[0].State != "partial" || devicesState.rows[0].Status["ru"].State != "active" {
		t.Fatal("partial success lost")
	}
	devicesState.rows[0].Revoked = true
	if err := applyDeviceLocked(context.Background(), 0, "admin"); err != nil {
		t.Fatal(err)
	}
	if devicesState.rows[0].State != "partial" {
		t.Fatal("unreachable revoke incorrectly confirmed")
	}
	offline = false
	if err := applyDeviceLocked(context.Background(), 0, "admin"); err != nil {
		t.Fatal(err)
	}
	if devicesState.rows[0].State != "revoked" {
		t.Fatal("revoke retry failed")
	}
	var restored []managedDevice
	if err := readStrictJSON(devicesState.path, &restored, 1<<20); err != nil || restored[0].State != "revoked" {
		t.Fatal("state not durable", err)
	}
}
func TestProfileContainsNoClientPrivateKey(t *testing.T) {
	clusterState.nodes = []nodeConfig{{ID: "ru", Name: "RU", Address: "203.0.113.10:7443", PublicKey: testPublic(t)}}
	profile, err := buildDeviceProfile(context.Background(), managedDevice{ID: "device123456", Nodes: []string{"ru"}, Protocol: "citp", PublicKey: testPublic(t)})
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(profile)
	if strings.Contains(string(b), "private") || strings.Contains(string(b), "ks_key") {
		t.Fatal("secret in public profile")
	}
}
