package chaossync

import "testing"

func TestPadIP(t *testing.T) {
	ack := make([]byte, 52, 2048)
	ack[0] = 0x45
	lens := map[int]int{}
	for i := 0; i < 5000; i++ {
		p := PadIP(ack[:52], 255, 600)
		if len(p) < 52 || len(p) > 52+255 {
			t.Fatalf("bad len %d", len(p))
		}
		lens[len(p)]++
	}
	for l, c := range lens {
		if c > 5000/20 {
			t.Fatalf("length %d is %d/5000 — still an ACK-echo signature", l, c)
		}
	}
	big := make([]byte, 1400)
	big[0] = 0x45
	if len(PadIP(big, 255, 600)) != 1400 {
		t.Fatal("large packet padded")
	}
	junk := make([]byte, 40)
	if len(PadIP(junk, 255, 600)) != 40 {
		t.Fatal("non-IP padded")
	}
}
