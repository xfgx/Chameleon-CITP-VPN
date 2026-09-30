package telemetry

import (
	"bytes"
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func tcpPacket(payload []byte) []byte {
	b := make([]byte, 40+len(payload))
	b[0] = 0x45
	binary.BigEndian.PutUint16(b[2:4], uint16(len(b)))
	b[8] = 64
	b[9] = 6
	copy(b[12:16], []byte{192, 0, 2, 10})
	copy(b[16:20], []byte{198, 51, 100, 2})
	binary.BigEndian.PutUint16(b[20:22], 32000)
	binary.BigEndian.PutUint16(b[22:24], 7443)
	b[32] = 0x50
	b[33] = 2
	copy(b[40:], payload)
	return b
}
func TestPayloadNeverInHeaderCapture(t *testing.T) {
	sentinel := []byte("USER-PAYLOAD-MUST-NOT-BE-STORED")
	packet, e := ParseHeaders(tcpPacket(sentinel))
	if e != nil {
		t.Fatal(e)
	}
	if len(packet.Header) != 40 || bytes.Contains(packet.Header, sentinel) {
		t.Fatal("payload entered metadata header")
	}
	dir := t.TempDir()
	id := ID()
	if e = WriteCapture(dir, id, []CapturedHeader{{time.Now(), packet.OriginalLen, packet.Header}}); e != nil {
		t.Fatal(e)
	}
	b, e := ReadCapture(dir, id)
	if e != nil || bytes.Contains(b, sentinel) || len(b) != 80 {
		t.Fatal("payload in pcap or bad size", e, len(b))
	}
}
func TestIPTCPOptionsExcluded(t *testing.T) {
	base := tcpPacket(nil)
	p := make([]byte, 68)
	copy(p[:20], base[:20])
	p[0] = 0x48
	binary.BigEndian.PutUint16(p[2:4], 68)
	copy(p[20:32], []byte("SECRET-IPOPT"))
	copy(p[32:52], base[20:40])
	p[44] = 0x90
	copy(p[52:68], []byte("SECRET-TCPOPT---"))
	packet, e := ParseHeaders(p)
	if e != nil {
		t.Fatal(e)
	}
	if len(packet.Header) != 40 || bytes.Contains(packet.Header, []byte("SECRET")) {
		t.Fatal("options stored")
	}
}
func TestFragmentsAndMalformedReject(t *testing.T) {
	for _, b := range [][]byte{nil, {0x45}, tcpPacket(nil)[:24]} {
		if _, e := ParseHeaders(b); e == nil {
			t.Fatal("short packet accepted")
		}
	}
	b := tcpPacket(nil)
	b[6] = 0x20
	if _, e := ParseHeaders(b); e == nil {
		t.Fatal("fragment accepted")
	}
}
func TestTCPVerdictsAreNotDPIProof(t *testing.T) {
	tracker := Tracker{Node: "ru", Interface: "eth0"}
	now := time.Now()
	p, _ := ParseHeaders(tcpPacket(nil))
	events := tracker.Observe(p, now)
	if events[0].Verdict != "unknown" {
		t.Fatal("unknown connection called normal")
	}
	p.Src, p.Dst = p.Dst, p.Src
	p.SrcPort, p.DstPort = p.DstPort, p.SrcPort
	p.Flags = 18
	tracker.Observe(p, now.Add(time.Millisecond))
	p.Src, p.Dst = p.Dst, p.Src
	p.SrcPort, p.DstPort = p.DstPort, p.SrcPort
	p.Flags = 16
	tracker.Observe(p, now.Add(2*time.Millisecond))
	p.Flags = 4
	p.TTL = 120
	events = tracker.Observe(p, now.Add(3*time.Millisecond))
	if len(events) != 1 || events[0].Verdict != "suspicious" || events[0].Confidence > 0.6 {
		t.Fatal("RST heuristic misclassified", events)
	}
}
func TestCursorPreservesAllRowsAndPartialTail(t *testing.T) {
	dir := t.TempDir()
	store := Store{Dir: dir}
	for i := 0; i < 6; i++ {
		if e := store.Append(Event{Node: "ru", Kind: "flow"}); e != nil {
			t.Fatal(e)
		}
	}
	b, e := Read(dir, "", 2)
	if e != nil || len(b.Records) != 2 || !b.More {
		t.Fatal(b, e)
	}
	b2, e := Read(dir, b.Cursor, 10)
	if e != nil || len(b2.Records) != 4 {
		t.Fatal(b2, e)
	}
	files, _ := filepath.Glob(filepath.Join(dir, "*.jsonl"))
	f, e := os.OpenFile(files[0], os.O_APPEND|os.O_WRONLY, 0600)
	if e != nil {
		t.Fatal(e)
	}
	_, _ = f.WriteString(`{"incomplete":`)
	_ = f.Close()
	b3, e := Read(dir, b2.Cursor, 10)
	if e != nil || len(b3.Records) != 0 || b3.Cursor != b2.Cursor {
		t.Fatal("partial tail consumed", b3, e)
	}
}
func TestTraversalAndExpiredCaptureRejected(t *testing.T) {
	if _, e := Read(t.TempDir(), encodeCursor(Cursor{"../private", 0}), 1); e == nil {
		t.Fatal("cursor traversal accepted")
	}
	if _, e := ReadCapture(t.TempDir(), "../../secret"); e == nil {
		t.Fatal("capture traversal accepted")
	}
	dir := t.TempDir()
	id := ID()
	p, _ := ParseHeaders(tcpPacket(nil))
	_ = WriteCapture(dir, id, []CapturedHeader{{time.Now(), p.OriginalLen, p.Header}})
	old := time.Now().Add(-2 * time.Hour)
	_ = os.Chtimes(filepath.Join(dir, id+".pcap"), old, old)
	if _, e := ReadCapture(dir, id); e == nil {
		t.Fatal("expired pcap available")
	}
}
func TestOversizedLineIsBoundedAndCursorAdvances(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "events-"+time.Now().UTC().Format("20060102-15")+".jsonl")
	b := append(bytes.Repeat([]byte("x"), 2<<20), '\n')
	b = append(b, []byte(`{"id":"valid-event","node":"ru","kind":"sensor","verdict":"unknown"}`+"\n")...)
	if err := os.WriteFile(path, b, 0600); err != nil {
		t.Fatal(err)
	}
	batch, err := Read(dir, "", 10)
	if err != nil || len(batch.Records) != 1 || !batch.Gap {
		t.Fatal("bad oversized-line handling", err, batch.Gap, len(batch.Records))
	}
	next, err := Read(dir, batch.Cursor, 10)
	if err != nil || len(next.Records) != 0 {
		t.Fatal("cursor failed to advance")
	}
}
