// Package activation implements personally signed entitlements, not VPN transport keys.
package activation

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"
	"time"
)

const Audience = "chameleon-free-vpn"
const Version = 1

var identifier = regexp.MustCompile(`^[A-Za-z0-9_-]{16,64}$`)
var keyID = regexp.MustCompile(`^[A-Za-z0-9_-]{1,40}$`)
var nonceID = regexp.MustCompile(`^[a-f0-9]{32}$`)

type Claims struct {
	Version     int    `json:"version"`
	Audience    string `json:"aud"`
	KeyID       string `json:"kid"`
	UserID      string `json:"user_id"`
	Plan        string `json:"plan"`
	IssuedAt    int64  `json:"issued_at"`
	ExpiresAt   int64  `json:"expires_at"`
	DeviceLimit int    `json:"device_limit"`
	Nonce       string `json:"nonce"`
}
type PublicKey struct {
	ID       string `json:"kid"`
	Key      string `json:"public_key"`
	Disabled bool   `json:"disabled,omitempty"`
}
type TrustFile struct {
	Version int         `json:"version"`
	Keys    []PublicKey `json:"keys"`
}

func (c Claims) Validate(now time.Time) error {
	if c.Version != Version || c.Audience != Audience || !keyID.MatchString(c.KeyID) || !identifier.MatchString(c.UserID) || !nonceID.MatchString(c.Nonce) || c.Plan != "free" || c.DeviceLimit < 1 || c.DeviceLimit > 5 {
		return errors.New("invalid entitlement claims")
	}
	if c.IssuedAt <= 0 || c.IssuedAt > now.Unix()+120 || c.ExpiresAt <= now.Unix() || c.ExpiresAt <= c.IssuedAt || c.ExpiresAt-c.IssuedAt > 90*24*3600 {
		return errors.New("entitlement expired or invalid lifetime")
	}
	return nil
}
func StrictJSON(data []byte, dst any) error {
	// Duplicate fields are rejected, including contradictory expiry or device limits.
	dec := json.NewDecoder(bytes.NewReader(data))
	t, err := dec.Token()
	if err != nil || t != json.Delim('{') {
		return errors.New("JSON object required")
	}
	seen := map[string]bool{}
	for dec.More() {
		t, err = dec.Token()
		if err != nil {
			return err
		}
		k, ok := t.(string)
		if !ok || seen[k] {
			return errors.New("duplicate JSON field")
		}
		seen[k] = true
		var raw json.RawMessage
		if err = dec.Decode(&raw); err != nil {
			return err
		}
	}
	if _, err = dec.Token(); err != nil {
		return err
	}
	if _, err = dec.Token(); err != io.EOF {
		return errors.New("trailing JSON")
	}
	d := json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	return d.Decode(dst)
}
func Verify(token string, trusted map[string]ed25519.PublicKey, now time.Time) (Claims, error) {
	var c Claims
	if len(token) > 6000 || strings.ContainsAny(token, " \t\r\n") {
		return c, errors.New("invalid entitlement")
	}
	parts := strings.Split(token, ".")
	if len(parts) != 2 {
		return c, errors.New("invalid entitlement format")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil || len(payload) > 4096 {
		return c, errors.New("invalid entitlement payload")
	}
	signature, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil || len(signature) != ed25519.SignatureSize {
		return c, errors.New("invalid entitlement signature")
	}
	if err = StrictJSON(payload, &c); err != nil {
		return Claims{}, errors.New("invalid entitlement claims")
	}
	key := trusted[c.KeyID]
	if len(key) != ed25519.PublicKeySize || !ed25519.Verify(key, payload, signature) {
		return Claims{}, errors.New("entitlement signature rejected")
	}
	if err = c.Validate(now); err != nil {
		return Claims{}, err
	}
	return c, nil
}
func Sign(c Claims, key ed25519.PrivateKey, now time.Time) (string, error) {
	if len(key) != ed25519.PrivateKeySize {
		return "", errors.New("invalid signing key")
	}
	if err := c.Validate(now); err != nil {
		return "", err
	}
	b, err := json.Marshal(c)
	if err != nil {
		return "", err
	}
	sig := ed25519.Sign(key, b)
	return base64.RawURLEncoding.EncodeToString(b) + "." + base64.RawURLEncoding.EncodeToString(sig), nil
}
func LoadTrust(path string) (map[string]ed25519.PublicKey, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if len(b) > 16384 {
		return nil, errors.New("trust file too large")
	}
	var f TrustFile
	if err = StrictJSON(b, &f); err != nil {
		return nil, err
	}
	if f.Version != Version || len(f.Keys) < 1 || len(f.Keys) > 8 {
		return nil, errors.New("invalid trust set")
	}
	out := map[string]ed25519.PublicKey{}
	seen := map[string]bool{}
	for _, p := range f.Keys {
		if !keyID.MatchString(p.ID) || seen[p.ID] {
			return nil, errors.New("invalid or duplicate key id")
		}
		seen[p.ID] = true
		b, e := base64.RawURLEncoding.DecodeString(p.Key)
		if e != nil || len(b) != ed25519.PublicKeySize {
			return nil, errors.New("invalid trust key")
		}
		if !p.Disabled {
			out[p.ID] = ed25519.PublicKey(b)
		}
	}
	if len(out) == 0 {
		return nil, errors.New("no active signing keys")
	}
	return out, nil
}
func NewNonce() (string, error) {
	b := make([]byte, 16)
	_, err := rand.Read(b)
	return hex.EncodeToString(b), err
}
func TokenDigest(token string) string {
	s := sha256.Sum256([]byte(token))
	return hex.EncodeToString(s[:])
}
func ProofMessage(challengeID, challenge, digest string) []byte {
	return []byte("chameleon-device-proof-v1\n" + challengeID + "\n" + challenge + "\n" + digest)
}
func LoadPrivate(path string) (ed25519.PrivateKey, error) {
	st, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if st.Mode().Perm()&0077 != 0 {
		return nil, errors.New("private signing key must not be group/world-readable")
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	p, _ := pem.Decode(b)
	if p == nil {
		return nil, errors.New("PKCS8 PEM required")
	}
	k, err := x509.ParsePKCS8PrivateKey(p.Bytes)
	if err != nil {
		return nil, err
	}
	key, ok := k.(ed25519.PrivateKey)
	if !ok {
		return nil, errors.New("Ed25519 private key required")
	}
	return key, nil
}
func GenerateFiles(privatePath, publicPath, id string) error {
	if !keyID.MatchString(id) {
		return errors.New("invalid key id")
	}
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return err
	}
	f, err := os.OpenFile(privatePath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	b := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	_, e := f.Write(b)
	if e == nil {
		e = f.Sync()
	}
	ce := f.Close()
	if e != nil {
		return e
	}
	if ce != nil {
		return ce
	}
	data, err := json.MarshalIndent(TrustFile{Version: Version, Keys: []PublicKey{{ID: id, Key: base64.RawURLEncoding.EncodeToString(pub)}}}, "", "  ")
	if err != nil {
		return err
	}
	out, err := os.OpenFile(publicPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0644)
	if err != nil {
		return fmt.Errorf("private key saved; public output failed: %w", err)
	}
	_, e = out.Write(append(data, '\n'))
	if e == nil {
		e = out.Sync()
	}
	ce = out.Close()
	if e != nil {
		return e
	}
	return ce
}
