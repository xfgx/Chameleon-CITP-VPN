package clientactivation

import (
	"chameleon/internal/activation"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestProofAndProfileBinding(t *testing.T) {
	c, e := NewCredentials()
	if e != nil {
		t.Fatal(e)
	}
	c.Token = "fixture-personal-token"
	key, transport, e := c.keys()
	if e != nil {
		t.Fatal(e)
	}
	pub := base64.RawURLEncoding.EncodeToString(transport.PublicKey().Bytes())
	challengeID := "test-challenge-1234567890"
	challenge := "test-challenge-value-1234567890"
	verified := false
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			t.Fatal("not POST")
		}
		switch r.URL.Path {
		case "/challenge":
			var input map[string]string
			_ = json.NewDecoder(r.Body).Decode(&input)
			if input["platform"] != "windows" || input["client_public_key"] != pub {
				t.Fatal("wrong identity")
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"challenge_id": challengeID, "challenge": challenge, "token_digest": activation.TokenDigest(c.Token), "proof_version": 1})
		case "/enroll":
			var input map[string]string
			_ = json.NewDecoder(r.Body).Decode(&input)
			signature, _ := base64.RawURLEncoding.DecodeString(input["signature"])
			verified = ed25519.Verify(key.Public().(ed25519.PublicKey), activation.ProofMessage(challengeID, challenge, activation.TokenDigest(c.Token)), signature)
			_ = json.NewEncoder(w).Encode(Profile{Kind: "chameleon-device-profile", Version: 2, ResolutionVersion: 2, ClientPublic: pub, ExpiresAt: time.Now().Add(time.Hour).Unix(), Servers: []Server{{Mode: "citp", Address: "198.51.100.1:7443", PublicKey: pub}}})
		}
	}))
	defer server.Close()
	profile, e := fetch(context.Background(), server.Client(), server.URL+"/", c)
	if e != nil || !verified || len(profile.Servers) != 1 {
		t.Fatal("enrollment failed", e, verified)
	}
}
