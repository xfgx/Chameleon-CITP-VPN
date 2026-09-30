//go:build linux

package main

import (
	"chameleon/internal/activation"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

var fActivationKeys = flag.String("activation-keys", "", "trusted public Ed25519 key JSON; empty disables public enrolment")
var fActivationOrigin = flag.String("activation-origin", "", "one allowed HTTPS website origin; native clients may omit Origin")

type activationDevice struct {
	PublicKey    string    `json:"public_key"`
	TransportKey string    `json:"transport_key"`
	Platform     string    `json:"platform"`
	DeviceID     string    `json:"device_id"`
	KSDeviceID   string    `json:"ks_device_id,omitempty"`
	Revoked      bool      `json:"revoked"`
	Expired      bool      `json:"expired,omitempty"`
	Created      time.Time `json:"created"`
	Updated      time.Time `json:"updated"`
}
type activationUser struct {
	Claims  activation.Claims            `json:"claims"`
	Revoked bool                         `json:"revoked"`
	Devices map[string]*activationDevice `json:"devices"`
}
type activationData struct {
	Version       int                        `json:"version"`
	Users         map[string]*activationUser `json:"users"`
	RevokedNonces map[string]bool            `json:"revoked_nonces"`
}
type deviceChallenge struct {
	Claims                                               activation.Claims
	PublicKey, TransportKey, Platform, Challenge, Digest string
	Expires                                              time.Time
}
type rateBucket struct {
	At time.Time
	N  int
}

var activationState = struct {
	sync.Mutex
	path       string
	trusted    map[string]ed25519.PublicKey
	data       activationData
	challenges map[string]deviceChallenge
	rates      map[string]rateBucket
}{}

func initActivations(dir string) error {
	if *fActivationKeys == "" {
		return nil
	}
	trust, err := activation.LoadTrust(*fActivationKeys)
	if err != nil {
		return err
	}
	activationState.Lock()
	defer activationState.Unlock()
	activationState.path = filepath.Join(dir, "activations.json")
	activationState.trusted = trust
	activationState.challenges = map[string]deviceChallenge{}
	activationState.rates = map[string]rateBucket{}
	activationState.data = activationData{Version: 1, Users: map[string]*activationUser{}, RevokedNonces: map[string]bool{}}
	err = readStrictJSON(activationState.path, &activationState.data, 8<<20)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if len(activationState.data.Users) > 1024 || activationState.data.Version != 1 {
		return errors.New("invalid activation registry")
	}
	if activationState.data.Users == nil {
		activationState.data.Users = map[string]*activationUser{}
	}
	if activationState.data.RevokedNonces == nil {
		activationState.data.RevokedNonces = map[string]bool{}
	}
	return nil
}
func saveActivationsLocked() error { return marshalPrivate(activationState.path, activationState.data) }
func marshalPrivate(path string, data any) error {
	b, err := json.Marshal(data)
	if err != nil {
		return err
	}
	return atomicPrivateFile(path, b)
}
func activationPOST(w http.ResponseWriter, r *http.Request) bool {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		http.Error(w, "POST required", 405)
		return false
	}
	if !strings.HasPrefix(r.Header.Get("Content-Type"), "application/json") {
		http.Error(w, "JSON required", 415)
		return false
	}
	if origin := r.Header.Get("Origin"); origin != "" && (*fActivationOrigin == "" || origin != *fActivationOrigin) {
		http.Error(w, "Origin rejected", 403)
		return false
	}
	activationState.Lock()
	defer activationState.Unlock()
	if activationState.trusted == nil {
		http.Error(w, "Activation is not configured", 503)
		return false
	}
	now := time.Now()
	ip := clientIP(r)
	b := activationState.rates[ip]
	if now.Sub(b.At) > time.Minute {
		b = rateBucket{At: now}
	}
	if b.N >= 120 {
		w.Header().Set("Retry-After", "60")
		http.Error(w, "Rate limit", 429)
		return false
	}
	b.N++
	activationState.rates[ip] = b
	if len(activationState.rates) > 2048 {
		for k, v := range activationState.rates {
			if now.Sub(v.At) > 2*time.Minute {
				delete(activationState.rates, k)
			}
		}
		if len(activationState.rates) > 2048 {
			http.Error(w, "Busy", 503)
			return false
		}
	}
	return true
}
func handleActivationChallenge(w http.ResponseWriter, r *http.Request) {
	if !activationPOST(w, r) {
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 16384)
	var in struct {
		Token        string `json:"token"`
		PublicKey    string `json:"device_public_key"`
		TransportKey string `json:"client_public_key"`
		Platform     string `json:"platform"`
	}
	if decodeStrictJSON(r.Body, &in) != nil {
		http.Error(w, "Invalid request", 400)
		return
	}
	pub, err := base64.RawURLEncoding.DecodeString(in.PublicKey)
	if err != nil || len(pub) != 32 || !validPublicKey(in.TransportKey) || (in.Platform != "android" && in.Platform != "windows") {
		http.Error(w, "Invalid installation key or platform", 400)
		return
	}
	activationState.Lock()
	defer activationState.Unlock()
	c, err := activation.Verify(in.Token, activationState.trusted, time.Now())
	if err != nil || activationState.data.RevokedNonces[c.Nonce] {
		http.Error(w, "Entitlement rejected or expired", 403)
		return
	}
	if u := activationState.data.Users[c.UserID]; u != nil && (u.Revoked || c.IssuedAt < u.Claims.IssuedAt) {
		http.Error(w, "Entitlement revoked or superseded", 403)
		return
	}
	for id, v := range activationState.challenges {
		if time.Now().After(v.Expires) {
			delete(activationState.challenges, id)
		}
	}
	if len(activationState.challenges) >= 2048 {
		http.Error(w, "Busy", 503)
		return
	}
	id, err := randToken(24)
	if err != nil {
		http.Error(w, "Random source unavailable", 503)
		return
	}
	challenge, err := randToken(32)
	if err != nil {
		http.Error(w, "Random source unavailable", 503)
		return
	}
	digest := activation.TokenDigest(in.Token)
	activationState.challenges[id] = deviceChallenge{Claims: c, PublicKey: in.PublicKey, TransportKey: normalizePublicKey(in.TransportKey), Platform: in.Platform, Challenge: challenge, Digest: digest, Expires: time.Now().Add(90 * time.Second)}
	writeJSON(w, map[string]any{"challenge_id": id, "challenge": challenge, "token_digest": digest, "expires_in": 90, "proof_version": 1})
}
func activationDeviceID(user, pub, kind string) string {
	sum := sha256.Sum256([]byte(user + "\n" + pub + "\n" + kind))
	return hex.EncodeToString(sum[:12])
}
func activationEntryNodes() []string {
	clusterState.RLock()
	defer clusterState.RUnlock()
	out := []string{}
	for _, n := range clusterState.nodes {
		if n.Role == "entry" {
			out = append(out, n.ID)
		}
	}
	return out
}
func ensureActivationManaged(ctx context.Context, c activation.Claims, b *activationDevice, kind string) error {
	id := b.DeviceID
	if kind == "ks" {
		id = b.KSDeviceID
	}
	if id == "" {
		return nil
	}
	index := deviceIndex(id)
	if index < 0 {
		if len(devicesState.rows) >= 1024 {
			return errors.New("device registry capacity reached")
		}
		nodes := activationEntryNodes()
		if kind == "ks" {
			keep := []string{}
			for _, id := range nodes {
				n, _ := findNode(id)
				if n.SupportsKS {
					keep = append(keep, id)
				}
			}
			nodes = keep
		}
		if len(nodes) == 0 {
			return errors.New("entry node unavailable")
		}
		d := managedDevice{ID: id, Name: "free-" + c.UserID[:8] + "-" + id[:6] + "-" + kind, Platform: b.Platform, Protocol: kind, Nodes: nodes, Status: map[string]deviceNodeState{}, State: "partial", Created: time.Now().UTC(), Updated: time.Now().UTC()}
		if kind == "citp" {
			d.PublicKey = b.TransportKey
		}
		devicesState.rows = append(devicesState.rows, d)
		index = len(devicesState.rows) - 1
	}
	d := &devicesState.rows[index]
	if d.Revoked {
		return errors.New("installation revoked")
	}
	if kind == "citp" && d.PublicKey != b.TransportKey {
		return errors.New("transport identity mismatch")
	}
	if d.State != "active" {
		return applyDeviceLocked(ctx, index, "activation:"+c.UserID)
	}
	return nil
}
func handleActivationEnroll(w http.ResponseWriter, r *http.Request) {
	if !activationPOST(w, r) {
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 2048)
	var in struct {
		ID        string `json:"challenge_id"`
		Signature string `json:"signature"`
	}
	if decodeStrictJSON(r.Body, &in) != nil {
		http.Error(w, "Invalid proof request", 400)
		return
	}
	activationState.Lock()
	defer activationState.Unlock()
	v, ok := activationState.challenges[in.ID]
	if !ok || time.Now().After(v.Expires) {
		delete(activationState.challenges, in.ID)
		http.Error(w, "Challenge expired", 403)
		return
	}
	sig, err := base64.RawURLEncoding.DecodeString(in.Signature)
	pub, _ := base64.RawURLEncoding.DecodeString(v.PublicKey)
	if err != nil || len(sig) != 64 || !ed25519.Verify(ed25519.PublicKey(pub), activation.ProofMessage(in.ID, v.Challenge, v.Digest), sig) {
		http.Error(w, "Device proof rejected", 403)
		return
	}
	delete(activationState.challenges, in.ID)
	c := v.Claims
	if c.Validate(time.Now()) != nil || activationState.data.RevokedNonces[c.Nonce] || len(activationState.trusted[c.KeyID]) != 32 {
		http.Error(w, "Entitlement rejected", 403)
		return
	}
	u := activationState.data.Users[c.UserID]
	if u == nil {
		if len(activationState.data.Users) >= 1024 {
			http.Error(w, "Capacity reached", 503)
			return
		}
		u = &activationUser{Claims: c, Devices: map[string]*activationDevice{}}
		activationState.data.Users[c.UserID] = u
	}
	if u.Revoked || c.IssuedAt < u.Claims.IssuedAt {
		http.Error(w, "Entitlement revoked or superseded", 403)
		return
	}
	if u.Devices == nil {
		u.Devices = map[string]*activationDevice{}
	}
	b := u.Devices[v.PublicKey]
	if b != nil && (b.Revoked || b.TransportKey != v.TransportKey || b.Platform != v.Platform) {
		http.Error(w, "Installation revoked or changed", 403)
		return
	}
	if b == nil {
		count := 0
		for _, d := range u.Devices {
			if !d.Revoked {
				count++
			}
		}
		if count >= min(c.DeviceLimit, 2) {
			http.Error(w, "Device limit reached; revoke a previous installation", 409)
			return
		}
		b = &activationDevice{PublicKey: v.PublicKey, TransportKey: v.TransportKey, Platform: v.Platform, DeviceID: activationDeviceID(c.UserID, v.PublicKey, "citp"), Created: time.Now().UTC()}
		u.Devices[v.PublicKey] = b
	}
	// Registry reservation is durable before touching a VPN node. Retries are idempotent.
	u.Claims = c
	b.Updated = time.Now().UTC()
	if err := saveActivationsLocked(); err != nil {
		http.Error(w, "Registry unavailable", 503)
		return
	}
	devicesState.Lock()
	defer devicesState.Unlock()
	if b.Expired {
		for _, id := range []string{b.DeviceID, b.KSDeviceID} {
			if i := deviceIndex(id); i >= 0 {
				devicesState.rows[i].Revoked = false
				devicesState.rows[i].State = "partial"
			}
		}
		if err := saveDevicesLocked(); err != nil {
			http.Error(w, "Registry unavailable", 503)
			return
		}
		b.Expired = false
		if err := saveActivationsLocked(); err != nil {
			http.Error(w, "Registry unavailable", 503)
			return
		}
	}
	if err := ensureActivationManaged(r.Context(), c, b, "citp"); err != nil {
		http.Error(w, "Node provisioning pending; retry", 503)
		return
	}
	primary := devicesState.rows[deviceIndex(b.DeviceID)]
	raw, err := buildDeviceProfile(r.Context(), primary)
	if err != nil {
		http.Error(w, "Profile unavailable", 503)
		return
	}
	profile := raw.(map[string]any)
	servers := profile["servers"].([]connectionProfile)
	// KS is optional fallback; capacity or a hub failure never silently claims success.
	fallback := "not_available"
	for _, id := range primary.Nodes {
		n, _ := findNode(id)
		if n.SupportsKS {
			if b.KSDeviceID == "" {
				b.KSDeviceID = activationDeviceID(c.UserID, v.PublicKey, "ks")
				if err := saveActivationsLocked(); err != nil {
					http.Error(w, "Registry unavailable", 503)
					return
				}
			}
			if err := ensureActivationManaged(r.Context(), c, b, "ks"); err == nil {
				ks := devicesState.rows[deviceIndex(b.KSDeviceID)]
				if raw, e := buildDeviceProfile(r.Context(), ks); e == nil {
					servers = append(servers, raw.(map[string]any)["servers"].([]connectionProfile)...)
					fallback = "available"
				}
			}
			break
		}
	}
	profile["servers"] = servers
	profile["user_id"] = c.UserID
	profile["expires_at"] = c.ExpiresAt
	profile["plan"] = c.Plan
	profile["fallback"] = fallback
	if err := audit("activation:"+c.UserID, "", "device.enroll", b.DeviceID, "ok"); err != nil {
		http.Error(w, "Audit unavailable", 503)
		return
	}
	writeJSON(w, profile)
}
func revokeActivationDevicesLocked(u *activationUser) error {
	devicesState.Lock()
	defer devicesState.Unlock()
	var first error
	for _, b := range u.Devices {
		if !u.Revoked && !b.Revoked && !b.Expired {
			continue
		}
		for _, id := range []string{b.DeviceID, b.KSDeviceID} {
			index := deviceIndex(id)
			if index < 0 {
				continue
			}
			d := &devicesState.rows[index]
			if d.Revoked && d.State == "revoked" {
				continue
			}
			d.Revoked = true
			ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
			err := applyDeviceLocked(ctx, index, "activation-expiry")
			cancel()
			if err != nil && first == nil {
				first = err
			}
		}
	}
	return first
}
func expireActivations() {
	if *fActivationKeys == "" {
		return
	}
	trust, err := activation.LoadTrust(*fActivationKeys)
	if err != nil {
		_ = audit("system", "", "activation.trust", "", "failed: public key reload")
		return
	}
	activationState.Lock()
	defer activationState.Unlock()
	activationState.trusted = trust
	for _, u := range activationState.data.Users {
		expired := u.Claims.ExpiresAt <= time.Now().Unix() || len(trust[u.Claims.KeyID]) != 32 || activationState.data.RevokedNonces[u.Claims.Nonce]
		if expired {
			for _, b := range u.Devices {
				b.Expired = true
			}
		}
		if u.Revoked || expired {
			if err := saveActivationsLocked(); err != nil {
				continue
			}
			if err := revokeActivationDevicesLocked(u); err != nil {
				_ = audit("system", "", "activation.revoke", u.Claims.UserID, "failed: retry scheduled")
			}
		}
	}
}
func handleActivations(w http.ResponseWriter, r *http.Request) {
	activationState.Lock()
	defer activationState.Unlock()
	if r.Method == http.MethodGet {
		users := []activationUser{}
		for _, u := range activationState.data.Users {
			users = append(users, *u)
		}
		sort.Slice(users, func(i, j int) bool { return users[i].Claims.IssuedAt > users[j].Claims.IssuedAt })
		writeJSON(w, map[string]any{"enabled": activationState.trusted != nil, "users": users, "policy": map[string]any{"plan": "free", "max_devices": 2, "default_days": 30, "issuer": "separate Telegram bot"}})
		return
	}
	if !requireMutation(w, r) {
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 2048)
	var in struct {
		UserID   string `json:"user_id"`
		DeviceID string `json:"device_id,omitempty"`
		Action   string `json:"action"`
	}
	if decodeStrictJSON(r.Body, &in) != nil || in.Action != "revoke" {
		http.Error(w, "Invalid request", 400)
		return
	}
	u := activationState.data.Users[in.UserID]
	if u == nil {
		http.NotFound(w, r)
		return
	}
	if in.DeviceID == "" {
		u.Revoked = true
		activationState.data.RevokedNonces[u.Claims.Nonce] = true
	} else {
		found := false
		for _, b := range u.Devices {
			if b.DeviceID == in.DeviceID {
				b.Revoked = true
				found = true
			}
		}
		if !found {
			http.NotFound(w, r)
			return
		}
	}
	if err := saveActivationsLocked(); err != nil {
		http.Error(w, "Registry unavailable", 503)
		return
	}
	if err := revokeActivationDevicesLocked(u); err != nil {
		http.Error(w, "Revocation pending; retry", 503)
		return
	}
	_ = audit(requestActor(r), "", "activation.revoke", in.UserID, "ok")
	writeJSON(w, map[string]any{"ok": true})
}
func handleActivationInfo(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "GET required", 405)
		return
	}
	activationState.Lock()
	defer activationState.Unlock()
	writeJSON(w, map[string]any{"enabled": activationState.trusted != nil, "version": 1, "aud": activation.Audience, "max_devices": 2, "default_days": 30})
}
