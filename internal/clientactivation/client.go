// Package clientactivation validates a profile obtained only from the fixed HTTPS gateway.
package clientactivation

import (
	"bytes"
	"chameleon/internal/activation"
	"context"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"
)

const Website = "https://vpn.example.com/vpn/"
const endpoint = Website + "api/v1/"

type Credentials struct {
	Token            string `json:"token"`
	Seed             string `json:"seed"`
	TransportPrivate string `json:"transport_private"`
}
type Server struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	Mode      string `json:"mode"`
	Address   string `json:"addr"`
	PublicKey string `json:"pubkey"`
	KSKey     string `json:"ks_key"`
	Inner     string `json:"inner"`
	PeerInner string `json:"peer_inner"`
}
type Profile struct {
	Kind              string   `json:"kind"`
	Version           int      `json:"version"`
	ResolutionVersion int      `json:"resolution_auth_version"`
	ClientPublic      string   `json:"client_public_key"`
	UserID            string   `json:"user_id"`
	ExpiresAt         int64    `json:"expires_at"`
	Servers           []Server `json:"servers"`
}

func NewCredentials() (Credentials, error) {
	var c Credentials
	_, key, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		return c, e
	}
	transport, e := ecdh.X25519().GenerateKey(rand.Reader)
	if e != nil {
		return c, e
	}
	c.Seed = base64.RawURLEncoding.EncodeToString(key.Seed())
	c.TransportPrivate = base64.RawURLEncoding.EncodeToString(transport.Bytes())
	return c, nil
}
func (c Credentials) keys() (ed25519.PrivateKey, *ecdh.PrivateKey, error) {
	seed, e := base64.RawURLEncoding.DecodeString(c.Seed)
	if e != nil || len(seed) != 32 {
		return nil, nil, errors.New("invalid installation key")
	}
	b, e := base64.RawURLEncoding.DecodeString(c.TransportPrivate)
	if e != nil {
		return nil, nil, e
	}
	transport, e := ecdh.X25519().NewPrivateKey(b)
	if e != nil {
		return nil, nil, e
	}
	return ed25519.NewKeyFromSeed(seed), transport, nil
}
func post(ctx context.Context, client *http.Client, base, path string, value any, out any) error {
	b, e := json.Marshal(value)
	if e != nil || len(b) > 16384 {
		return errors.New("invalid activation request")
	}
	r, e := http.NewRequestWithContext(ctx, "POST", base+path, bytes.NewReader(b))
	if e != nil {
		return e
	}
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Accept", "application/json")
	response, e := client.Do(r)
	if e != nil {
		return errors.New("activation service unreachable")
	}
	defer response.Body.Close()
	if response.StatusCode != 200 {
		return fmt.Errorf("activation HTTP %d", response.StatusCode)
	}
	b, e = io.ReadAll(io.LimitReader(response.Body, 65537))
	if e != nil || len(b) > 65536 {
		return errors.New("activation response too large")
	}
	return json.Unmarshal(b, out)
}
func Fetch(ctx context.Context, c Credentials) (Profile, error) {
	client := &http.Client{Timeout: 40 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	return fetch(ctx, client, endpoint, c)
}
func fetch(ctx context.Context, client *http.Client, base string, c Credentials) (Profile, error) {
	var profile Profile
	if c.Token == "" || len(c.Token) > 6000 || strings.ContainsAny(c.Token, " \r\n\t") {
		return profile, errors.New("activation token required")
	}
	key, transport, e := c.keys()
	if e != nil {
		return profile, e
	}
	pub := base64.RawURLEncoding.EncodeToString(key.Public().(ed25519.PublicKey))
	clientPub := base64.RawURLEncoding.EncodeToString(transport.PublicKey().Bytes())
	var challenge struct {
		ID      string `json:"challenge_id"`
		Value   string `json:"challenge"`
		Digest  string `json:"token_digest"`
		Version int    `json:"proof_version"`
	}
	if e = post(ctx, client, base, "challenge", map[string]any{"token": c.Token, "device_public_key": pub, "client_public_key": clientPub, "platform": "windows"}, &challenge); e != nil {
		return profile, e
	}
	if challenge.Version != 1 || len(challenge.ID) < 16 || len(challenge.ID) > 128 || len(challenge.Value) < 16 || len(challenge.Value) > 128 || challenge.Digest != activation.TokenDigest(c.Token) {
		return profile, errors.New("device challenge rejected")
	}
	signature := ed25519.Sign(key, activation.ProofMessage(challenge.ID, challenge.Value, challenge.Digest))
	if e = post(ctx, client, base, "enroll", map[string]string{"challenge_id": challenge.ID, "signature": base64.RawURLEncoding.EncodeToString(signature)}, &profile); e != nil {
		return profile, e
	}
	if profile.Kind != "chameleon-device-profile" || profile.Version != 2 || profile.ResolutionVersion != 2 || strings.TrimRight(profile.ClientPublic, "=") != clientPub || profile.ExpiresAt <= time.Now().Unix() || profile.ExpiresAt > time.Now().Add(91*24*time.Hour).Unix() || len(profile.Servers) < 1 || len(profile.Servers) > 16 {
		return Profile{}, errors.New("profile validation failed")
	}
	for _, s := range profile.Servers {
		host, port, e := net.SplitHostPort(s.Address)
		if e != nil || host == "" || port == "" || len(s.Address) > 260 || (s.Mode != "citp" && s.Mode != "ks") {
			return Profile{}, errors.New("node profile rejected")
		}
		if s.Mode == "citp" {
			b, e := base64.RawURLEncoding.DecodeString(strings.TrimRight(s.PublicKey, "="))
			if e != nil || len(b) != 32 {
				return Profile{}, errors.New("node key rejected")
			}
		}
	}
	return profile, nil
}
