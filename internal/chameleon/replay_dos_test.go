package chameleon

import (
	"crypto/ecdh"
	"crypto/rand"
	"net"
	"testing"
	"time"
)

func TestReplayCacheIsBoundedAndFailsClosed(t *testing.T) {
	cache := newReplayCache()
	var clientA, clientB [32]byte
	clientA[0], clientB[0] = 1, 2
	for i := 0; i < maxReplayPerClient; i++ {
		var nonce [16]byte
		nonce[0] = byte(i >> 8)
		nonce[1] = byte(i)
		if cache.seenOrAddFor(clientA, nonce, time.Hour) {
			t.Fatalf("fresh nonce %d rejected before client bucket reached its bound", i)
		}
	}
	var extra [16]byte
	extra[0], extra[1], extra[2] = 0xff, 0xff, 1
	if !cache.seenOrAddFor(clientA, extra, time.Hour) {
		t.Fatal("full client bucket must fail closed")
	}
	if cache.seenOrAddFor(clientB, extra, time.Hour) {
		t.Fatal("one client's full bucket must not block other clients")
	}
	if cache.size() != maxReplayPerClient+1 {
		t.Fatalf("unexpected replay cache size: %d", cache.size())
	}
	if !cache.seenOrAddFor(clientB, extra, time.Hour) {
		t.Fatal("replayed nonce must be rejected")
	}
}

func TestReplayCacheExpiredEntriesAreReused(t *testing.T) {
	cache := newReplayCache()
	var client [32]byte
	for i := 0; i < maxReplayPerClient; i++ {
		var nonce [16]byte
		nonce[0], nonce[1] = byte(i>>8), byte(i)
		cache.seenOrAddFor(client, nonce, time.Nanosecond)
	}
	time.Sleep(time.Millisecond)
	var fresh [16]byte
	fresh[5] = 9
	if cache.seenOrAddFor(client, fresh, time.Hour) {
		t.Fatal("expired entries must be swept instead of failing closed")
	}
	if cache.size() != 1 {
		t.Fatalf("expired entries were not removed: %d", cache.size())
	}
}

// Рукопожатие чужого (не из белого списка) клиента не должно занимать
// место в кэше повторов: иначе кэш можно заполнить, зная лишь ключ ноды.
func TestHandshakeRejectsUnknownClientBeforeReplayCache(t *testing.T) {
	serverKey, _ := ecdh.X25519().GenerateKey(rand.Reader)
	allowed, _ := ecdh.X25519().GenerateKey(rand.Reader)
	stranger, _ := ecdh.X25519().GenerateKey(rand.Reader)
	var allowedPub [32]byte
	copy(allowedPub[:], allowed.PublicKey().Bytes())
	allow := map[[32]byte]bool{allowedPub: true}

	before := serverReplay.size()
	for i := 0; i < 20; i++ {
		c, s := net.Pipe()
		done := make(chan error, 1)
		go func() {
			_, _, err := ServerHandshake(s, serverKey, allow)
			_ = s.Close()
			done <- err
		}()
		_, _ = ClientHandshake(c, serverKey.PublicKey(), stranger)
		_ = c.Close()
		if err := <-done; err != ErrAuth {
			t.Fatalf("stranger handshake: want ErrAuth, got %v", err)
		}
	}
	if after := serverReplay.size(); after != before {
		t.Fatalf("rejected handshakes consumed replay cache: %d -> %d", before, after)
	}

	c, s := net.Pipe()
	done := make(chan error, 1)
	go func() {
		_, _, err := ServerHandshake(s, serverKey, allow)
		done <- err
	}()
	if _, err := ClientHandshake(c, serverKey.PublicKey(), allowed); err != nil {
		t.Fatalf("allowed client handshake failed: %v", err)
	}
	if err := <-done; err != nil {
		t.Fatalf("server rejected allowed client: %v", err)
	}
	_ = c.Close()
	_ = s.Close()
	if serverReplay.size() != before+1 {
		t.Fatalf("allowed handshake must be recorded once: %d -> %d", before, serverReplay.size())
	}
}
