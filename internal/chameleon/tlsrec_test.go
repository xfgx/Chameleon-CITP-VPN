package chameleon

import (
	"crypto/ecdh"
	"crypto/rand"
	"net"
	"testing"
)

// Сервер принимает hello и с TLS-заголовком, и без (старые клиенты).
func TestHandshakeTLSRecordBothForms(t *testing.T) {
	srv, _ := ecdh.X25519().GenerateKey(rand.Reader)
	for _, rec := range []bool{false, true} {
		cl, _ := ecdh.X25519().GenerateKey(rand.Reader)
		allow := map[[32]byte]bool{[32]byte(cl.PublicKey().Bytes()): true}
		a, b := net.Pipe()
		errc := make(chan error, 1)
		go func() { _, _, err := ServerHandshake(b, srv, allow); errc <- err }()
		ClientTLSRecord = rec
		var first [5]byte
		if rec {
			// проверяем, что на проводе реально заголовок TLS
			pa, pb := net.Pipe()
			go func() { _, _ = ClientHandshake(pa, srv.PublicKey(), cl) }()
			_, _ = pb.Read(first[:])
			pa.Close()
			pb.Close()
			if first != tlsRecHdr {
				t.Fatalf("wire prefix %x", first)
			}
		}
		if _, err := ClientHandshake(a, srv.PublicKey(), cl); err != nil {
			t.Fatalf("rec=%v client: %v", rec, err)
		}
		if err := <-errc; err != nil {
			t.Fatalf("rec=%v server: %v", rec, err)
		}
	}
	ClientTLSRecord = false
}
