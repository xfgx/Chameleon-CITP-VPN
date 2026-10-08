package chaossync

import (
	"os"
	"runtime"
	"testing"
	"time"
)

func TestMeasureSkew(t *testing.T) {
	if os.Getenv("CHAMELEON_MEASURE") == "" {
		t.Skip("измерение для docs/KS-REVIEW: CHAMELEON_MEASURE=1 go test -run TestMeasure -v")
	}
	m := []byte("0123456789abcdef0123456789abcdef")
	base := time.Unix(1_800_000_000, 0)
	for _, d := range []float64{-30, -9, -7, -3, -1, -0.2, 0, 0.2, 1, 3, 7, 9, 30} {
		s := NewRotatingSender(m, "c2n", 8, base.Add(time.Duration(d*1e9)))
		r := NewRotatingReceiver(m, "c2n", 8, base)
		ok, n := 0, 0
		for ms := 0; ms < 80000; ms += 50 {
			now := base.Add(time.Duration(ms) * time.Millisecond)
			s.TickEpoch(now.Add(time.Duration(d * 1e9)))
			w := s.Seal(make([]byte, 100))
			r.TickEpoch(now)
			if _, k := r.Ingest(w); k {
				ok++
			}
			n++
		}
		t.Logf("SKEW sender%+.1fs: delivered %.1f%%", d, 100*float64(ok)/float64(n))
	}
}

func TestMeasureMem(t *testing.T) {
	if os.Getenv("CHAMELEON_MEASURE") == "" {
		t.Skip("измерение для docs/KS-REVIEW: CHAMELEON_MEASURE=1 go test -run TestMeasure -v")
	}
	m := []byte("0123456789abcdef0123456789abcdef")
	var a, b runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&a)
	sinks := make([]*ksEpochSink, 20)
	for i := range sinks {
		sinks[i] = newKsEpochSink(m, uint64(i), "c2n")
		sinks[i].used = ksWindow
		sinks[i].fill(ksWindow)
	}
	runtime.GC()
	runtime.ReadMemStats(&b)
	t.Logf("MEM full-window sink: %.0f KB (%d entries)", float64(b.HeapAlloc-a.HeapAlloc)/20/1024, len(sinks[0].ahead))
	runtime.GC()
	runtime.ReadMemStats(&a)
	for i := range sinks {
		sinks[i] = newKsEpochSink(m, uint64(i+100), "c2n")
		sinks[i].fill(ksWindow)
	}
	runtime.GC()
	runtime.ReadMemStats(&b)
	t.Logf("MEM idle (lazy) sink: %.0f KB (%d entries)", float64(b.HeapAlloc-a.HeapAlloc)/20/1024, len(sinks[0].ahead))
}

func TestMeasureReplayAndLen(t *testing.T) {
	if os.Getenv("CHAMELEON_MEASURE") == "" {
		t.Skip("измерение для docs/KS-REVIEW: CHAMELEON_MEASURE=1 go test -run TestMeasure -v")
	}
	m := []byte("0123456789abcdef0123456789abcdef")
	s := NewSender(m, 5, "c2n")
	r := NewReceiver(m, 5, "c2n")
	for _, n := range []int{0, 40, 1400} {
		w := s.Seal(make([]byte, n))
		_, ok1 := r.Ingest(w)
		_, ok2 := r.Ingest(w)
		t.Logf("LEN plain=%d wire=%d first=%v replay=%v", n, len(w), ok1, ok2)
	}
	// пакет «из будущего» дальше окна
	for i := 0; i < 300; i++ {
		s.Seal(nil)
	}
	_, ok := r.Ingest(s.Seal(make([]byte, 10)))
	t.Logf("GAP 300 lost then 1: accepted=%v", ok)
}

func BenchmarkMeasureIngest(b *testing.B) {
	m := []byte("0123456789abcdef0123456789abcdef")
	s := NewSender(m, 5, "c2n")
	r := NewReceiver(m, 5, "c2n")
	w := make([][]byte, b.N)
	for i := range w {
		w[i] = s.Seal(make([]byte, 64))
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		r.Ingest(w[i])
	}
}
