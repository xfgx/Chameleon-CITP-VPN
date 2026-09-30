package mobilecore

import (
	"chameleon/internal/activation"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
)

// GenActivationKey returns an installation-specific Ed25519 seed. Keep it in OS-protected storage.
func GenActivationKey() string {
	b := make([]byte, ed25519.SeedSize)
	if _, e := rand.Read(b); e != nil {
		return ""
	}
	return base64.RawURLEncoding.EncodeToString(b)
}
func ActivationPublicKey(seed string) string {
	b, e := base64.RawURLEncoding.DecodeString(seed)
	if e != nil || len(b) != ed25519.SeedSize {
		return ""
	}
	return base64.RawURLEncoding.EncodeToString(ed25519.NewKeyFromSeed(b).Public().(ed25519.PublicKey))
}
func ActivationTokenDigest(token string) string { return activation.TokenDigest(token) }
func SignActivation(seed, id, challenge, digest string) string {
	b, e := base64.RawURLEncoding.DecodeString(seed)
	if e != nil || len(b) != ed25519.SeedSize || len(id) > 128 || len(challenge) > 128 || len(digest) != 64 {
		return ""
	}
	return base64.RawURLEncoding.EncodeToString(ed25519.Sign(ed25519.NewKeyFromSeed(b), activation.ProofMessage(id, challenge, digest)))
}
