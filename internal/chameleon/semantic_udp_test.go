package chameleon

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"testing"
	"time"
)

func semanticUDPTestMux(t *testing.T) (*Mux, *Conn) {
	t.Helper()
	client, server := adaptivePipe(t)
	go ServeMuxWithPolicy(server, time.Second, NewPolicyEngine(DeclarativePolicy{MaxStreamsPerConn: 32}), nil)
	return NewMuxClient(client), client
}
func TestSemanticUDPRealRelayAndFragmentation(t *testing.T) {
	udp, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer udp.Close()
	go func() {
		buffer := make([]byte, 65535)
		for {
			n, peer, err := udp.ReadFrom(buffer)
			if err != nil {
				return
			}
			_, _ = udp.WriteTo(buffer[:n], peer)
		}
	}()
	mx, conn := semanticUDPTestMux(t)
	stream, err := mx.OpenUDP(udp.LocalAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer stream.Close()
	for _, size := range []int{1, 1200, 60000} {
		payload := bytes.Repeat([]byte{byte(size % 251)}, size)
		framed := binary.BigEndian.AppendUint16(nil, uint16(size))
		framed = append(framed, payload...)
		if _, err := stream.Write(framed[:1]); err != nil {
			t.Fatal(err)
		}
		if _, err := stream.Write(framed[1:]); err != nil {
			t.Fatal(err)
		}
		got := make([]byte, len(framed))
		if _, err := io.ReadFull(stream, got); err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, framed) {
			t.Fatalf("datagram %d changed", size)
		}
	}
	stats := conn.DatagramStats()
	if stats.Sent != 3 || stats.Received != 3 {
		t.Fatalf("objects did not drive real UDP: %+v", stats)
	}
}
func TestSemanticUDPQueueExpiryAndBudget(t *testing.T) {
	raw := &adaptiveRecordingConn{}
	conn := adaptiveTestConn(t, raw)
	m := newMux(conn)
	s := &Stream{m: m, id: 1, inCh: make(chan []byte, 1), udp: newSemanticUDP("1.1.1.1:53")}
	if s.udp.budget != 5*time.Second {
		t.Fatal("DNS budget")
	}
	if err := s.WriteDatagramWithDeadline([]byte("late"), time.Now().Add(-time.Second).UnixMilli()); !errors.Is(err, ErrObjectExpired) {
		t.Fatal(err)
	}
	if raw.writes.Load() != 0 || conn.sendNonce != 0 {
		t.Fatal("expired packet reached transport")
	}
	s.udp.input <- semanticDatagram{payload: []byte("expired"), expiry: time.Now().Add(-time.Second).UnixMilli()}
	s.udp.input <- semanticDatagram{payload: []byte("fresh"), expiry: time.Now().Add(time.Second).UnixMilli()}
	got, _, err := s.ReadDatagramWithDeadline()
	if err != nil || string(got) != "fresh" {
		t.Fatal("queue expiry failed", err)
	}
}
func TestSemanticUDPFragmentReplayAndBoundedQueue(t *testing.T) {
	conn := adaptiveTestConn(t, &adaptiveRecordingConn{})
	m := newMux(conn)
	s := &Stream{m: m, id: 1, inCh: make(chan []byte, 1), udp: newSemanticUDP("1.1.1.1:443")}
	expiry := time.Now().Add(time.Second).UnixMilli()
	for i := uint64(1); i <= 40; i++ {
		obj := &CITPObject{StreamID: 1, ObjectID: i, MonotonicSeq: i, Type: ObjTypeDatagramBatch, Mode: ModeExpiring, ExpiryUnixMs: expiry, Payload: []byte{0, 1, 'x'}}
		s.feedSemanticDatagram(obj)
		s.feedSemanticDatagram(obj)
	}
	if len(s.udp.input) != streamQueueDepth || conn.DatagramStats().QueueDropped != 24 {
		t.Fatalf("unbounded queue or replay admitted: %+v", conn.DatagramStats())
	}
}
func TestProtocolCapabilitiesNewPair(t *testing.T) {
	m, _ := semanticUDPTestMux(t)
	if err := m.RequireCapabilities(); err != nil {
		t.Fatal(err)
	}
}
func TestProtocolCapabilitiesRejectLegacyPeer(t *testing.T) {
	client, server := adaptivePipe(t)
	m := NewMuxClient(client)
	go func() {
		frame, err := server.ReadMessage()
		if err != nil {
			return
		}
		if frame[4] != smCapabilities {
			return
		}
		_ = server.WriteMessage(append(append([]byte{}, frame[:4]...), append([]byte{smCapabilitiesOK}, []byte{1, 1, 0}...)...))
	}()
	if err := m.RequireCapabilities(); !errors.Is(err, ErrProtocolUpgrade) {
		t.Fatalf("legacy accepted: %v", err)
	}
}
func TestSemanticUDPCascadePreservesDeadline(t *testing.T) {
	upClient, upServer := adaptivePipe(t)
	upstream := NewMuxClient(upClient)
	go ServeMuxWithPolicy(upServer, time.Second, NewPolicyEngine(DeclarativePolicy{MaxStreamsPerConn: 32}), nil)
	udp, _ := net.ListenPacket("udp", "127.0.0.1:0")
	defer udp.Close()
	go func() {
		buffer := make([]byte, 2048)
		n, peer, err := udp.ReadFrom(buffer)
		if err == nil {
			_, _ = udp.WriteTo(buffer[:n], peer)
		}
	}()
	entryClient, entryServer := adaptivePipe(t)
	go ServeMuxWithEgress(entryServer, time.Second, NewPolicyEngine(DeclarativePolicy{MaxStreamsPerConn: 32}), nil, nil, func(target string) (net.Conn, error) {
		s, err := upstream.OpenUDP(target)
		if err != nil {
			return nil, err
		}
		return &streamConn{Stream: s, peer: target}, nil
	})
	client := NewMuxClient(entryClient)
	s, err := client.OpenUDP(udp.LocalAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if err := s.WriteDatagramWithDeadline([]byte("cascade"), time.Now().Add(time.Second).UnixMilli()); err != nil {
		t.Fatal(err)
	}
	got, expiry, err := s.ReadDatagramWithDeadline()
	if err != nil || string(got) != "cascade" || expiry == 0 {
		t.Fatal("semantic cascade failed", err)
	}
	if entryServer.DatagramStats().Received != 1 || upClient.DatagramStats().Sent != 1 {
		t.Fatal("cascade did not use semantic API")
	}
}
