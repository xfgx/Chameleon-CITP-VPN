package activation

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func fixture(t *testing.T) (Claims, ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	p, k, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	n, _ := NewNonce()
	return Claims{Version: Version, Audience: Audience, KeyID: "test-key", UserID: "opaque-user-0123456789", Plan: "free", IssuedAt: time.Now().Unix(), ExpiresAt: time.Now().Add(time.Hour).Unix(), DeviceLimit: 2, Nonce: n}, p, k
}
func TestSignVerify(t *testing.T) {
	c, p, k := fixture(t)
	token, e := Sign(c, k, time.Now())
	if e != nil {
		t.Fatal(e)
	}
	got, e := Verify(token, map[string]ed25519.PublicKey{c.KeyID: p}, time.Now())
	if e != nil || got != c {
		t.Fatalf("%v %v", got, e)
	}
}
func TestTamperedAndUntrusted(t *testing.T) {
	c, p, k := fixture(t)
	tok, _ := Sign(c, k, time.Now())
	parts := strings.Split(tok, ".")
	data, _ := base64.RawURLEncoding.DecodeString(parts[0])
	data = []byte(strings.Replace(string(data), `"device_limit":2`, `"device_limit":5`, 1))
	if _, e := Verify(base64.RawURLEncoding.EncodeToString(data)+"."+parts[1], map[string]ed25519.PublicKey{c.KeyID: p}, time.Now()); e == nil {
		t.Fatal("tampering accepted")
	}
	if _, e := Verify(tok, nil, time.Now()); e == nil {
		t.Fatal("unknown key accepted")
	}
}
func TestExpiryAudienceLimits(t *testing.T) {
	c, _, k := fixture(t)
	for _, change := range []func(*Claims){func(c *Claims) { c.ExpiresAt = time.Now().Unix() - 1 }, func(c *Claims) { c.Audience = "another-app" }, func(c *Claims) { c.DeviceLimit = 0 }, func(c *Claims) { c.IssuedAt = time.Now().Add(time.Hour).Unix() }, func(c *Claims) { c.Nonce = "broken" }} {
		bad := c
		change(&bad)
		if _, e := Sign(bad, k, time.Now()); e == nil {
			t.Fatal("invalid claims signed")
		}
	}
}
func TestDuplicateClaims(t *testing.T) {
	c, p, k := fixture(t)
	tok, _ := Sign(c, k, time.Now())
	a := strings.Split(tok, ".")
	b, _ := base64.RawURLEncoding.DecodeString(a[0])
	b = append([]byte(`{"device_limit":5,`), b[1:]...)
	s := ed25519.Sign(k, b)
	if _, e := Verify(base64.RawURLEncoding.EncodeToString(b)+"."+base64.RawURLEncoding.EncodeToString(s), map[string]ed25519.PublicKey{c.KeyID: p}, time.Now()); e == nil {
		t.Fatal("duplicate field accepted")
	}
}
func TestPrivateFilePermissionsAndNoOverwrite(t *testing.T) {
	c, _, _ := fixture(t)
	d := t.TempDir()
	priv, pub := filepath.Join(d, "issuer.pem"), filepath.Join(d, "trusted.json")
	if e := GenerateFiles(priv, pub, c.KeyID); e != nil {
		t.Fatal(e)
	}
	if _, e := LoadPrivate(priv); e != nil {
		t.Fatal(e)
	}
	if _, e := LoadTrust(pub); e != nil {
		t.Fatal(e)
	}
	if e := GenerateFiles(priv, pub, c.KeyID); e == nil {
		t.Fatal("private key overwritten")
	}
	_ = os.Chmod(priv, 0644)
	if _, e := LoadPrivate(priv); e == nil {
		t.Fatal("unsafe private mode accepted")
	}
}
