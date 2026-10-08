package chameleon

import (
	"testing"
	"time"
)

// Медленный читатель больше не рвёт поток: feed ждёт место в очереди
// (TCP-подпор), а не закрывает поток мгновенно.
func TestStreamFeedBackpressure(t *testing.T) {
	m := newMux(nil)
	s := &Stream{m: m, id: 7, inCh: make(chan []byte, 2)}
	if err := m.putStream(s); err != nil {
		t.Fatal(err)
	}
	s.feed([]byte("a"))
	s.feed([]byte("b"))
	done := make(chan bool, 1)
	go func() { done <- s.feed([]byte("c")) }()
	select {
	case <-done:
		t.Fatal("feed returned while queue full (expected to wait)")
	case <-time.After(200 * time.Millisecond):
	}
	<-s.inCh // читатель освободил место
	select {
	case ok := <-done:
		if !ok {
			t.Fatal("stream closed instead of waiting")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("feed did not resume after reader drained")
	}
	if m.get(7) == nil {
		t.Fatal("stream removed")
	}
}

func TestBlackholeHoldRandom(t *testing.T) {
	seen := map[time.Duration]bool{}
	for i := 0; i < 50; i++ {
		d := blackholeHold(45 * time.Second)
		if d < 45*time.Second*35/100 || d > 45*time.Second {
			t.Fatalf("hold %v out of range", d)
		}
		seen[d.Truncate(time.Second)] = true
	}
	if len(seen) < 5 {
		t.Fatalf("blackhole hold is not random: %v", seen)
	}
}
