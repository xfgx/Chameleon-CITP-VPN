//go:build linux

package main

import (
	"bytes"
	"chameleon/internal/activation"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"
)

func setupActivation(t *testing.T) (activation.Claims, ed25519.PrivateKey) {
	t.Helper()
	dir := t.TempDir()
	priv, pub := filepath.Join(dir, "key.pem"), filepath.Join(dir, "keys.json")
	if e := activation.GenerateFiles(priv, pub, "test"); e != nil {
		t.Fatal(e)
	}
	key, e := activation.LoadPrivate(priv)
	if e != nil {
		t.Fatal(e)
	}
	oldKeys := *fActivationKeys
	oldOrigin := *fActivationOrigin
	oldApply := nodeApply
	oldConf := conf
	t.Cleanup(func() {
		*fActivationKeys = oldKeys
		*fActivationOrigin = oldOrigin
		nodeApply = oldApply
		conf = oldConf
	})
	*fActivationKeys = pub
	*fActivationOrigin = ""
	conf = &adminConf{User: "test-admin"}
	auditState.rows = nil
	if e = initAudit(dir); e != nil {
		t.Fatal(e)
	}
	devicesState.rows = nil
	if e = loadDevices(dir); e != nil {
		t.Fatal(e)
	}
	clusterState.nodes = []nodeConfig{{ID: "ru", Name: "Test entry", Role: "entry", Address: "127.0.0.1:7443", PublicKey: testPublic(t)}}
	nodeApply = func(context.Context, nodeConfig, nodeRequest) (nodeResponse, error) { return nodeResponse{}, nil }
	if e = initActivations(dir); e != nil {
		t.Fatal(e)
	}
	nonce, _ := activation.NewNonce()
	return activation.Claims{Version: 1, Audience: activation.Audience, KeyID: "test", UserID: "opaque-user-0123456789", Plan: "free", IssuedAt: time.Now().Unix(), ExpiresAt: time.Now().Add(time.Hour).Unix(), DeviceLimit: 2, Nonce: nonce}, key
}
func activationRequest(t *testing.T, h http.HandlerFunc, path string, body any) *httptest.ResponseRecorder {
	t.Helper()
	b, e := json.Marshal(body)
	if e != nil {
		t.Fatal(e)
	}
	r := httptest.NewRequest("POST", "https://example.test"+path, bytes.NewReader(b))
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h(w, r)
	return w
}
func challengeProof(t *testing.T, token string, key ed25519.PrivateKey, transport string) (map[string]any, int) {
	t.Helper()
	pub := base64.RawURLEncoding.EncodeToString(key.Public().(ed25519.PublicKey))
	w := activationRequest(t, handleActivationChallenge, "/vpn-api/v1/challenge", map[string]any{"token": token, "device_public_key": pub, "client_public_key": transport, "platform": "android"})
	if w.Code != 200 {
		return nil, w.Code
	}
	var c struct {
		ID        string `json:"challenge_id"`
		Challenge string `json:"challenge"`
		Digest    string `json:"token_digest"`
	}
	if e := json.Unmarshal(w.Body.Bytes(), &c); e != nil {
		t.Fatal(e)
	}
	sig := ed25519.Sign(key, activation.ProofMessage(c.ID, c.Challenge, c.Digest))
	return map[string]any{"challenge_id": c.ID, "signature": base64.RawURLEncoding.EncodeToString(sig)}, 200
}
func TestActivationEnrollmentReplayAndLimit(t *testing.T) {
	c, issuer := setupActivation(t)
	token, e := activation.Sign(c, issuer, time.Now())
	if e != nil {
		t.Fatal(e)
	}
	_, device, _ := ed25519.GenerateKey(rand.Reader)
	transport := testPublic(t)
	proof, status := challengeProof(t, token, device, transport)
	if status != 200 {
		t.Fatal(status)
	}
	w := activationRequest(t, handleActivationEnroll, "/vpn-api/v1/enroll", proof)
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	if w = activationRequest(t, handleActivationEnroll, "/vpn-api/v1/enroll", proof); w.Code != 403 {
		t.Fatal("replayed proof accepted")
	}
	proof, _ = challengeProof(t, token, device, transport)
	if w = activationRequest(t, handleActivationEnroll, "/vpn-api/v1/enroll", proof); w.Code != 200 {
		t.Fatal("idempotent retry", w.Code, w.Body.String())
	}
	if len(devicesState.rows) != 1 {
		t.Fatal("duplicate managed device")
	}
	for i := 0; i < 2; i++ {
		_, k, _ := ed25519.GenerateKey(rand.Reader)
		p, _ := challengeProof(t, token, k, testPublic(t))
		w = activationRequest(t, handleActivationEnroll, "/vpn-api/v1/enroll", p)
		want := 200
		if i == 1 {
			want = 409
		}
		if w.Code != want {
			t.Fatalf("device limit: %d want %d", w.Code, want)
		}
	}
}
func TestActivationWrongProofAndTransportChange(t *testing.T) {
	c, key := setupActivation(t)
	token, _ := activation.Sign(c, key, time.Now())
	_, device, _ := ed25519.GenerateKey(rand.Reader)
	transport := testPublic(t)
	p, _ := challengeProof(t, token, device, transport)
	_, other, _ := ed25519.GenerateKey(rand.Reader)
	p["signature"] = base64.RawURLEncoding.EncodeToString(ed25519.Sign(other, []byte("wrong proof")))
	if w := activationRequest(t, handleActivationEnroll, "/vpn-api/v1/enroll", p); w.Code != 403 {
		t.Fatal("wrong signature accepted")
	}
	p, _ = challengeProof(t, token, device, transport)
	if w := activationRequest(t, handleActivationEnroll, "/vpn-api/v1/enroll", p); w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	p, _ = challengeProof(t, token, device, testPublic(t))
	if w := activationRequest(t, handleActivationEnroll, "/vpn-api/v1/enroll", p); w.Code != 403 {
		t.Fatal("transport binding changed")
	}
}
func TestActivationExpirationRenewalAndManualRevocation(t *testing.T) {
	c, key := setupActivation(t)
	token, _ := activation.Sign(c, key, time.Now())
	_, device, _ := ed25519.GenerateKey(rand.Reader)
	transport := testPublic(t)
	p, _ := challengeProof(t, token, device, transport)
	w := activationRequest(t, handleActivationEnroll, "/vpn-api/v1/enroll", p)
	if w.Code != 200 {
		t.Fatal(w.Code)
	}
	u := activationState.data.Users[c.UserID]
	u.Claims.ExpiresAt = time.Now().Unix() - 1
	expireActivations()
	if !devicesState.rows[0].Revoked || !u.Devices[base64.RawURLEncoding.EncodeToString(device.Public().(ed25519.PublicKey))].Expired {
		t.Fatal("expiry did not revoke")
	}
	c.IssuedAt++
	c.ExpiresAt = time.Now().Add(time.Hour).Unix()
	c.Nonce, _ = activation.NewNonce()
	token, _ = activation.Sign(c, key, time.Now())
	p, _ = challengeProof(t, token, device, transport)
	w = activationRequest(t, handleActivationEnroll, "/vpn-api/v1/enroll", p)
	if w.Code != 200 || devicesState.rows[0].Revoked {
		t.Fatal("valid renewal rejected", w.Code, w.Body.String())
	}
	if e := markActivationManualRevoke(devicesState.rows[0].ID); e != nil {
		t.Fatal(e)
	}
	p, _ = challengeProof(t, token, device, transport)
	if w = activationRequest(t, handleActivationEnroll, "/vpn-api/v1/enroll", p); w.Code != 403 {
		t.Fatal("manual revoke undone by reenrollment")
	}
}
func TestViewerCannotMutate(t *testing.T) {
	sessions = newSessStore()
	token, e := sessions.createAs(principal{"read-only", "viewer"})
	if e != nil {
		t.Fatal(e)
	}
	r := httptest.NewRequest("POST", "https://admin.example/api/devices", bytes.NewReader([]byte("{}")))
	r.AddCookie(&http.Cookie{Name: cookieName, Value: token})
	r.Header.Set("Origin", "https://admin.example")
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("X-CSRF-Token", mutationToken(token))
	w := httptest.NewRecorder()
	if requireMutation(w, r) || w.Code != 403 {
		t.Fatal("viewer mutation allowed")
	}
}
