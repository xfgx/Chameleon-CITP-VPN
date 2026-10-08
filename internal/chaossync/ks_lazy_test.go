package chaossync

import "testing"

// Ленивое окно: молчащий приёмник держит мало позиций, активный дорастает
// до полного окна и переживает длинную серию потерь.
func TestKsLazyWindow(t *testing.T) {
	m := make([]byte, 32)
	m[0] = 7
	tx := NewSender(m, 5, "c2n")
	rx := NewReceiver(m, 5, "c2n")
	if _, ok := rx.Ingest(tx.Seal([]byte("hello-0"))); !ok {
		t.Fatal("first datagram rejected")
	}
	if n := len(rx.cur.ahead); n > ksLazyAhead+1 {
		t.Fatalf("idle receiver holds %d positions, want <= %d", n, ksLazyAhead+1)
	}
	// 3000 успешных — окно должно вырасти, затем 2000 потерь подряд переживаются
	for i := 0; i < 3000; i++ {
		if _, ok := rx.Ingest(tx.Seal([]byte("x"))); !ok {
			t.Fatalf("datagram %d rejected", i)
		}
	}
	for i := 0; i < 2000; i++ {
		tx.Seal([]byte("lost"))
	}
	if _, ok := rx.Ingest(tx.Seal([]byte("after-loss"))); !ok {
		t.Fatal("receiver did not survive 2000 consecutive losses after warm-up")
	}
	if n := len(rx.cur.ahead); n > ksWindow {
		t.Fatalf("window overflow: %d", n)
	}
}
