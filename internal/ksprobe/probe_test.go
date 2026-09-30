package ksprobe

import (
	"bytes"
	"chameleon/internal/chaossync"
	"encoding/binary"
	"net"
	"testing"
	"time"
)

func TestProbeChecksums(t *testing.T) {
	p := DNS(net.IPv4(10, 99, 9, 15), 0x4348)
	if checksum(p[:20]) != 0 {
		t.Fatal("IP checksum")
	}
	b := make([]byte, 12+len(p)-20)
	copy(b, p[12:20])
	b[9] = 17
	binary.BigEndian.PutUint16(b[10:], uint16(len(p)-20))
	copy(b[12:], p[20:])
	if checksum(b) != 0 {
		t.Fatal("UDP checksum")
	}
	if len(p) != 45 || p[40] != 0 || binary.BigEndian.Uint16(p[41:]) != 2 {
		t.Fatal("fixed root query")
	}
}
func TestHubWireInteroperability(t *testing.T) {
	var master [32]byte
	master[0] = 3
	now := time.Unix(1800000000, 0)
	tx := chaossync.NewRotatingSender(master[:], "c2n", 8, now)
	rx := chaossync.NewRotatingReceiver(master[:], "c2n", 8, now)
	p := DNS(net.IPv4(10, 99, 9, 15), 4)
	plain, ok := rx.Ingest(tx.Seal(p))
	if !ok || !bytes.Equal(plain, p) {
		t.Fatal("hub wire mismatch")
	}
}
