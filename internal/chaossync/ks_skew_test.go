package chaossync

import (
	"testing"
	"time"
)

// Дрейф часов (beta, 2026-10-08): окно эпох base±1 + выученное смещение.
// До фикса: +1 с → 87.5%, +3 с → 62.5%, ≥ +9 с → 0%.
func TestKsClockSkewWindow(t *testing.T) {
	m := []byte("0123456789abcdef0123456789abcdef")
	base := time.Unix(1_800_000_000, 0)
	for _, d := range []float64{-30, -9, -7, -3, -1, -0.2, 0, 0.2, 1, 3, 7, 9, 20, 30} {
		s := NewRotatingSender(m, "c2n", 8, base.Add(time.Duration(d*1e9)))
		r := NewRotatingReceiver(m, "c2n", 8, base)
		ok, n := 0, 0
		for ms := 0; ms < 120000; ms += 50 {
			now := base.Add(time.Duration(ms) * time.Millisecond)
			s.TickEpoch(now.Add(time.Duration(d * 1e9)))
			w := s.Seal(make([]byte, 100))
			r.TickEpoch(now)
			if _, k := r.Ingest(w); k {
				ok++
			}
			n++
		}
		pct := 100 * float64(ok) / float64(n)
		t.Logf("skew %+.1fs: delivered %.1f%% (offset %d)", d, pct, r.Offset())
		min := 99.0
		if d >= 20 || d <= -20 {
			min = 95 // первые датаграммы до поиска эпохи теряются
		}
		if pct < min {
			t.Errorf("skew %+.1fs: delivered %.1f%% < %.0f%%", d, pct, min)
		}
	}
}

// Регрессия ленивого окна: 300 потерь подряд в начале эпохи.
func TestKsLazyGapAtEpochStart(t *testing.T) {
	m := []byte("0123456789abcdef0123456789abcdef")
	base := time.Unix(1_800_000_000, 0)
	s := NewRotatingSender(m, "c2n", 8, base)
	r := NewRotatingReceiver(m, "c2n", 8, base)
	if _, ok := r.Ingest(s.Seal([]byte("warm"))); !ok {
		t.Fatal("warm-up rejected")
	}
	t1 := base.Add(8 * time.Second)
	s.TickEpoch(t1)
	r.TickEpoch(t1)
	for i := 0; i < 3000; i++ {
		s.Seal([]byte("lost"))
	}
	if _, ok := r.Ingest(s.Seal([]byte("after-gap"))); !ok {
		t.Fatal("receiver stalled after 3000 losses at epoch start")
	}
	if _, ok := r.Ingest(s.Seal([]byte("next"))); !ok {
		t.Fatal("receiver stalled after recovery")
	}
}

// Повтор невозможен после сдвига окна назад и вперёд.
func TestKsReplayAcrossOffsetShift(t *testing.T) {
	m := []byte("0123456789abcdef0123456789abcdef")
	base := time.Unix(1_800_000_000, 0)
	s := NewRotatingSender(m, "c2n", 8, base.Add(20*time.Second))
	r := NewRotatingReceiver(m, "c2n", 8, base)
	var seen [][]byte
	for ms := 0; ms < 60000; ms += 100 {
		now := base.Add(time.Duration(ms) * time.Millisecond)
		s.TickEpoch(now.Add(20 * time.Second))
		r.TickEpoch(now)
		w := s.Seal([]byte("x"))
		if _, ok := r.Ingest(w); ok {
			seen = append(seen, w)
		}
	}
	for i, w := range seen {
		if _, ok := r.Ingest(w); ok {
			t.Fatalf("replay %d accepted", i)
		}
	}
}

// Отправитель с SetOffset печатает в эпохе получателя и не возвращается
// в использованную эпоху (нет повтора key/nonce).
func TestKsSenderOffsetMonotonic(t *testing.T) {
	m := []byte("0123456789abcdef0123456789abcdef")
	base := time.Unix(1_800_000_000, 0)
	s := NewRotatingSender(m, "n2c", 8, base)
	s.SetOffset(2)
	s.TickEpoch(base)
	e1 := s.epoch
	s.SetOffset(0)
	s.TickEpoch(base.Add(time.Second))
	if s.epoch != e1 {
		t.Fatalf("sender went back from epoch %d to %d", e1, s.epoch)
	}
	// старый приёмник (без окна next) на часах +16 с видит эпоху отправителя
	old := NewRotatingReceiver(m, "n2c", 8, base.Add(16*time.Second))
	if _, ok := old.Ingest(s.Seal([]byte("hi"))); !ok {
		t.Fatal("offset sender not readable by receiver in shifted epoch")
	}
}
