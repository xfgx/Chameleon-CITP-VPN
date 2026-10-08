package chameleon

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"
)

const semanticUDPMarker = 0xf1
const datagramFragmentBytes = 24 * 1024
const maxDatagramLifetime = 30 * time.Second

type semanticDatagram struct {
	payload []byte
	expiry  int64
}
type semanticUDPState struct {
	writeMu     sync.Mutex
	writeBuffer []byte
	sequence    uint64
	readMu      sync.Mutex
	readBuffer  []byte
	input       chan semanticDatagram
	budget      time.Duration
	rxMu        sync.Mutex
	rxSeq       uint64
	rxTotal     int
	rxExpiry    int64
	rxBuffer    []byte
}

func newSemanticUDP(hostport string) *semanticUDPState {
	_, port, _ := net.SplitHostPort(hostport)
	budget := 2 * time.Second
	if port == "53" {
		budget = 5 * time.Second
	}
	return &semanticUDPState{input: make(chan semanticDatagram, semanticUDPQueueDepth), budget: budget}
}

// OpenUDP retains the length-prefixed Stream API for SOCKS/TUN callers, but
// transports every datagram as expiring authenticated CITP objects. Ordinary
// UDP is never latest-only: unrelated DNS/QUIC/game packets cannot supersede it.
func (m *Mux) openSemanticUDP(hostport string) (*Stream, error) {
	if err := m.RequireCapabilities(); err != nil {
		return nil, err
	}
	host, port, err := net.SplitHostPort(hostport)
	if err != nil {
		return nil, err
	}
	if net.ParseIP(stringsTrimBrackets(host)) != nil {
		return m.OpenRaw(append([]byte{semanticUDPMarker}, []byte(hostport)...))
	}
	ro, err := m.Resolve(host)
	if err != nil {
		if errors.Is(err, errResolveViaUpstream) {
			return m.OpenRaw(append([]byte{semanticUDPMarker}, []byte(hostport)...))
		}
		return nil, fmt.Errorf("UDP DNS binding: %w", err)
	}
	var last error
	for _, addr := range ro.Addrs {
		encoded := append([]byte{semanticUDPMarker}, []byte(net.JoinHostPort(addr, port))...)
		body := ro.Encode()
		payload := binary.BigEndian.AppendUint16(nil, uint16(len(body)))
		payload = append(payload, body...)
		payload = append(payload, encoded...)
		stream, err := m.openRawAuth(payload)
		if err == nil {
			return stream, nil
		}
		last = err
	}
	if last == nil {
		last = errors.New("UDP resolution has no address")
	}
	return nil, last
}
func stringsTrimBrackets(s string) string {
	if len(s) > 1 && s[0] == '[' && s[len(s)-1] == ']' {
		return s[1 : len(s)-1]
	}
	return s
}

func (s *Stream) writeFramedDatagrams(p []byte) (int, error) {
	u := s.udp
	u.writeMu.Lock()
	defer u.writeMu.Unlock()
	total := len(p)
	for len(p) > 0 {
		room := 65537 - len(u.writeBuffer)
		if room <= 0 {
			return total - len(p), errors.New("UDP framing exceeds limit")
		}
		n := min(room, len(p))
		u.writeBuffer = append(u.writeBuffer, p[:n]...)
		p = p[n:]
		for len(u.writeBuffer) >= 2 {
			size := int(binary.BigEndian.Uint16(u.writeBuffer))
			if size == 0 {
				return total - len(p), errors.New("zero-length legacy UDP frame")
			}
			if len(u.writeBuffer) < size+2 {
				break
			}
			err := s.sendDatagramLocked(u.writeBuffer[2:size+2], time.Now().Add(u.budget).UnixMilli())
			u.writeBuffer = u.writeBuffer[size+2:]
			if err != nil && !errors.Is(err, ErrObjectExpired) {
				return total - len(p), err
			}
		}
	}
	return total, nil
}
func (s *Stream) readFramedDatagrams(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	u := s.udp
	u.readMu.Lock()
	defer u.readMu.Unlock()
	if len(u.readBuffer) == 0 {
		d, err := s.nextDatagram()
		if err != nil {
			return 0, err
		}
		u.readBuffer = binary.BigEndian.AppendUint16(nil, uint16(len(d.payload)))
		u.readBuffer = append(u.readBuffer, d.payload...)
	}
	n := copy(p, u.readBuffer)
	u.readBuffer = u.readBuffer[n:]
	return n, nil
}

func (s *Stream) WriteDatagramWithDeadline(payload []byte, expiry int64) error {
	if s.udp == nil {
		return errors.New("stream is not semantic UDP")
	}
	s.udp.writeMu.Lock()
	defer s.udp.writeMu.Unlock()
	return s.sendDatagramLocked(payload, expiry)
}
func (s *Stream) sendDatagramLocked(payload []byte, expiry int64) error {
	s.mu.Lock()
	closed := s.closed
	s.mu.Unlock()
	if closed || !s.m.Alive() {
		return io.ErrClosedPipe
	}
	if len(payload) == 0 || len(payload) > 65535 {
		return errors.New("UDP datagram must contain 1..65535 bytes")
	}
	now := time.Now().UnixMilli()
	if expiry <= now {
		s.m.conn.datagramsExpired.Add(1)
		return ErrObjectExpired
	}
	if expiry > now+maxDatagramLifetime.Milliseconds() {
		return errors.New("UDP deadline exceeds maximum lifetime")
	}
	if s.udp.sequence == ^uint64(0) {
		return errors.New("UDP sequence exhausted")
	}
	s.udp.sequence++
	seq := s.udp.sequence
	for offset := 0; offset < len(payload); {
		end := min(len(payload), offset+datagramFragmentBytes)
		fragment := binary.BigEndian.AppendUint16(nil, uint16(len(payload)))
		fragment = append(fragment, payload[offset:end]...)
		obj := &CITPObject{ObjectID: seq, StreamID: s.id, Type: ObjTypeDatagramBatch, Mode: ModeExpiring, Offset: uint64(offset), ExpiryUnixMs: expiry, MonotonicSeq: seq, Payload: fragment}
		if err := s.m.SendCITPObject(obj); err != nil {
			if errors.Is(err, ErrObjectExpired) {
				s.m.conn.datagramsExpired.Add(1)
			}
			return err
		}
		offset = end
	}
	s.m.conn.datagramsSent.Add(1)
	return nil
}

func (s *Stream) feedSemanticDatagram(obj *CITPObject) {
	u := s.udp
	if u == nil || obj.Mode != ModeExpiring || len(obj.Payload) < 3 || obj.MonotonicSeq == 0 || obj.ObjectID != obj.MonotonicSeq || obj.ExpiryUnixMs <= time.Now().UnixMilli() || obj.ExpiryUnixMs > time.Now().Add(maxDatagramLifetime).UnixMilli() {
		return
	}
	u.rxMu.Lock()
	defer u.rxMu.Unlock()
	total := int(binary.BigEndian.Uint16(obj.Payload))
	fragment := obj.Payload[2:]
	if total == 0 || obj.Offset > uint64(total) || len(fragment) > total-int(obj.Offset) {
		return
	}
	if obj.MonotonicSeq < u.rxSeq {
		return
	}
	if obj.MonotonicSeq > u.rxSeq {
		if obj.Offset != 0 {
			return
		}
		u.rxSeq = obj.MonotonicSeq
		u.rxTotal = total
		u.rxExpiry = obj.ExpiryUnixMs
		u.rxBuffer = make([]byte, 0, total)
	}
	if u.rxBuffer == nil || total != u.rxTotal || obj.ExpiryUnixMs != u.rxExpiry || obj.Offset != uint64(len(u.rxBuffer)) {
		return
	}
	u.rxBuffer = append(u.rxBuffer, fragment...)
	if len(u.rxBuffer) != total {
		return
	}
	packet := semanticDatagram{payload: u.rxBuffer, expiry: u.rxExpiry}
	u.rxBuffer = nil
	defer func() { _ = recover() }()
	select {
	case u.input <- packet:
		s.m.conn.datagramsReceived.Add(1)
	default:
		s.m.conn.datagramsDropped.Add(1)
	}
}

func (s *Stream) nextDatagram() (semanticDatagram, error) {
	timer := time.NewTimer(120 * time.Second)
	defer timer.Stop()
	for {
		select {
		case packet, ok := <-s.udp.input:
			if !ok {
				return semanticDatagram{}, io.EOF
			}
			if time.Now().UnixMilli() >= packet.expiry {
				s.m.conn.datagramsExpired.Add(1)
				continue
			}
			s.m.payloadReceived.Add(uint64(len(packet.payload)))
			return packet, nil
		case <-timer.C:
			return semanticDatagram{}, errors.New("UDP idle timeout")
		}
	}
}
func (s *Stream) ReadDatagramWithDeadline() ([]byte, int64, error) {
	if s.udp == nil {
		return nil, 0, errors.New("stream is not semantic UDP")
	}
	s.udp.readMu.Lock()
	defer s.udp.readMu.Unlock()
	packet, err := s.nextDatagram()
	return packet.payload, packet.expiry, err
}

type semanticDatagramConn interface {
	ReadDatagramWithDeadline() ([]byte, int64, error)
	WriteDatagramWithDeadline([]byte, int64) error
}

func (m *Mux) serveSemanticUDP(sid uint32, hostport string) {
	var uc net.Conn
	var err error
	if m.egressUDP != nil {
		uc, err = m.egressUDP(hostport)
	} else {
		uc, err = net.DialTimeout("udp", hostport, 10*time.Second)
	}
	if err != nil {
		_ = m.send(sid, smOpenErr, boundedText(err))
		return
	}
	upstream, semanticUpstream := uc.(semanticDatagramConn)
	if m.egressUDP != nil && !semanticUpstream {
		_ = uc.Close()
		_ = m.send(sid, smOpenErr, []byte(ErrProtocolUpgrade.Error()))
		return
	}
	s := &Stream{m: m, id: sid, inCh: make(chan []byte, streamQueueDepth), udp: newSemanticUDP(hostport)}
	if err := m.putStream(s); err != nil {
		_ = uc.Close()
		_ = m.send(sid, smOpenErr, boundedText(err))
		return
	}
	if err := m.send(sid, smOpenOK, nil); err != nil {
		_ = uc.Close()
		m.remove(sid)
		return
	}
	go func() {
		defer uc.Close()
		defer s.Close()
		for {
			packet, expiry, err := s.ReadDatagramWithDeadline()
			if err != nil {
				return
			}
			if time.Now().UnixMilli() >= expiry {
				m.conn.datagramsExpired.Add(1)
				continue
			}
			if semanticUpstream {
				err = upstream.WriteDatagramWithDeadline(packet, expiry)
			} else {
				_ = uc.SetWriteDeadline(time.UnixMilli(expiry))
				_, err = uc.Write(packet)
			}
			if errors.Is(err, ErrObjectExpired) {
				continue
			}
			if err != nil {
				return
			}
		}
	}()
	go func() {
		defer uc.Close()
		defer s.Close()
		buffer := make([]byte, 65535)
		for {
			var packet []byte
			var expiry int64
			var err error
			if semanticUpstream {
				packet, expiry, err = upstream.ReadDatagramWithDeadline()
			} else {
				_ = uc.SetReadDeadline(time.Now().Add(120 * time.Second))
				var n int
				n, err = uc.Read(buffer)
				packet = buffer[:n]
				expiry = time.Now().Add(s.udp.budget).UnixMilli()
			}
			if err != nil {
				return
			}
			err = s.WriteDatagramWithDeadline(packet, expiry)
			if errors.Is(err, ErrObjectExpired) {
				continue
			}
			if err != nil {
				return
			}
		}
	}()
}

type DatagramStats struct {
	Sent         uint64 `json:"sent"`
	Received     uint64 `json:"received"`
	Expired      uint64 `json:"expired"`
	QueueDropped uint64 `json:"queue_dropped"`
}

func (c *Conn) DatagramStats() DatagramStats {
	return DatagramStats{Sent: c.datagramsSent.Load(), Received: c.datagramsReceived.Load(), Expired: c.datagramsExpired.Load(), QueueDropped: c.datagramsDropped.Load()}
}
