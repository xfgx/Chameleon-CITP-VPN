package telemetry

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func tcp(src, dst string, sp, dp uint16, flags uint8, seq, ack uint32, n int) Packet {
	return Packet{Src: src, Dst: dst, SrcPort: sp, DstPort: dp, Protocol: "tcp", Flags: flags, Seq: seq, Ack: ack, PayloadLen: n, OriginalLen: 40 + n, TTL: 60}
}

// Сервер отдаёт ~16 КБ, дальше подтверждения клиента пропадают, сервер
// повторяет данные — классическая «заморозка». Ожидаем stall to_client на 16 КБ.
func TestTrackerDetectsFreezeAfterVolume(t *testing.T) {
	var ended []Event
	tr := Tracker{Node: "ru", Interface: "eth0", ServerPorts: map[uint16]bool{9443: true},
		Resolve: func(string) (uint32, string) { return 12389, "ROSTELECOM-AS" },
		OnEnd:   func(e Event) { ended = append(ended, e) }}
	c, s := "198.51.100.7", "203.0.113.1"
	now := time.Unix(1_700_000_000, 0)
	tr.Observe(tcp(c, s, 50000, 9443, 2, 1000, 0, 0), now)
	tr.Observe(tcp(s, c, 9443, 50000, 18, 5000, 1001, 0), now.Add(10*time.Millisecond))
	tr.Observe(tcp(c, s, 50000, 9443, 16, 1001, 5001, 0), now.Add(20*time.Millisecond))
	tr.Observe(tcp(c, s, 50000, 9443, 24, 1001, 5001, 104), now.Add(21*time.Millisecond))
	seq := uint32(5001)
	at := now.Add(30 * time.Millisecond)
	for i := 0; i < 16; i++ {
		tr.Observe(tcp(s, c, 9443, 50000, 24, seq, 1105, 1024), at)
		seq += 1024
		tr.Observe(tcp(c, s, 50000, 9443, 16, 1105, seq, 0), at.Add(time.Millisecond))
		at = at.Add(5 * time.Millisecond)
	}
	// Дальше данные уходят, подтверждений нет, идут повторы.
	lost := seq
	tr.Observe(tcp(s, c, 9443, 50000, 24, lost, 1105, 1024), at)
	tr.Observe(tcp(s, c, 9443, 50000, 24, lost, 1105, 1024), at.Add(time.Second))
	events := tr.Observe(tcp(s, c, 9443, 50000, 24, lost, 1105, 1024), at.Add(3*time.Second))
	if len(events) == 0 || events[0].Stalls != 1 || events[0].StallDir != "to_client" {
		t.Fatalf("freeze not detected: %+v", events)
	}
	if got := events[0].StallAtBytes; got != 16*1024 {
		t.Fatalf("stall volume: want %d, got %d", 16*1024, got)
	}
	if events[0].Group != "AS12389 ROSTELECOM-AS" || events[0].ClientNet != "198.51.100.0/24" || events[0].Role != "inbound" || events[0].ServerPort != 9443 {
		t.Fatalf("classification: %+v", events[0])
	}
	tr.Observe(tcp(s, c, 9443, 50000, 4, lost, 0, 0), at.Add(10*time.Second))
	if len(ended) != 1 || ended[0].EndReason != "rst_by_server" || ended[0].StallMS < 10000 || ended[0].StallRecovered {
		t.Fatalf("final event: %+v", ended)
	}
	q := NewQualityAggregator(now)
	q.Add(ended[0])
	sums := q.Flush(at.Add(time.Minute))
	if len(sums) != 1 || sums[0].Stalled != 1 || sums[0].StallAtBytes["16-32K"] != 1 || sums[0].ResetByServer != 1 || sums[0].Service != "tcp:9443" {
		t.Fatalf("aggregate: %+v", sums)
	}
	if roll := q.Rolling(); len(roll) != 1 || roll[0].Flows != 1 {
		t.Fatalf("rolling: %+v", roll)
	}
	ev := QualityEvent("ru", sums[0])
	if ev.Kind != "netquality" || ev.Quality == nil {
		t.Fatalf("quality event: %+v", ev)
	}
}

func TestTrackerRecoveredStallAndOutboundRole(t *testing.T) {
	var ended []Event
	tr := Tracker{ServerPorts: map[uint16]bool{8443: true}, Local: map[string]bool{"203.0.113.1": true}, OnEnd: func(e Event) { ended = append(ended, e) }}
	me, exit := "203.0.113.1", "192.0.2.9"
	now := time.Unix(1_700_000_000, 0)
	tr.Observe(tcp(me, exit, 40000, 8443, 24, 100, 900, 500), now)
	tr.Observe(tcp(me, exit, 40000, 8443, 24, 100, 900, 500), now.Add(time.Second))
	ev := tr.Observe(tcp(me, exit, 40000, 8443, 24, 100, 900, 500), now.Add(2500*time.Millisecond))
	if ev[0].Stalls != 1 || ev[0].StallDir != "to_server" || ev[0].Role != "outbound" || ev[0].Group != "cascade 192.0.2.9" {
		t.Fatalf("outbound stall: %+v", ev[0])
	}
	tr.Observe(tcp(exit, me, 8443, 40000, 16, 900, 600, 0), now.Add(4*time.Second))
	tr.Observe(tcp(me, exit, 40000, 8443, 17, 600, 900, 0), now.Add(5*time.Second))
	tr.Observe(tcp(exit, me, 8443, 40000, 17, 900, 601, 0), now.Add(5*time.Second))
	if len(ended) != 1 || !ended[0].StallRecovered || ended[0].EndReason != "fin" || ended[0].StallMS < 3900 {
		t.Fatalf("recovered stall: %+v", ended)
	}
}

func TestASNLookup(t *testing.T) {
	p := filepath.Join(t.TempDir(), "asn.tsv")
	body := "1.0.0.0\t1.0.0.255\t13335\tUS\tCLOUDFLARENET\n" +
		"95.24.0.0\t95.31.255.255\t8402\tRU\tCORBINA-AS\n" +
		"2a00:1fa0::\t2a00:1fa3:ffff:ffff:ffff:ffff:ffff:ffff\t8359\tRU\tMTS\n" +
		"garbage line\n"
	if err := os.WriteFile(p, []byte(body), 0600); err != nil {
		t.Fatal(err)
	}
	d := OpenASN(p)
	if d.Len() != 3 {
		t.Fatalf("ranges: %d", d.Len())
	}
	if asn, org := d.Lookup("95.28.1.2"); asn != 8402 || org != "CORBINA-AS" {
		t.Fatalf("v4 lookup: %d %q", asn, org)
	}
	if asn, _ := d.Lookup("2a00:1fa1::5"); asn != 8359 {
		t.Fatalf("v6 lookup: %d", asn)
	}
	if asn, _ := d.Lookup("95.32.0.1"); asn != 0 {
		t.Fatalf("outside range must be unknown: %d", asn)
	}
	if asn, _ := (*ASNDB)(nil).Lookup("1.0.0.1"); asn != 0 {
		t.Fatal("nil db")
	}
}
