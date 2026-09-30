// Package telemetry records network metadata only. It never accepts packet payload as an event field.
package telemetry

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net"
	"strings"
	"time"
)

type DNSMetadata struct {
	Name      string   `json:"name,omitempty"`
	Answers   []string `json:"answers,omitempty"`
	RCode     string   `json:"rcode,omitempty"`
	LatencyMS int64    `json:"latency_ms,omitempty"`
	Synthetic bool     `json:"synthetic"`
}
type TLSMetadata struct {
	SNI         string `json:"sni,omitempty"`
	ALPN        string `json:"alpn,omitempty"`
	Version     string `json:"version,omitempty"`
	Fingerprint string `json:"fingerprint,omitempty"`
	Synthetic   bool   `json:"synthetic"`
}
type Event struct {
	ID              string       `json:"id"`
	At              time.Time    `json:"at"`
	Node            string       `json:"node"`
	Kind            string       `json:"kind"`
	FlowID          string       `json:"flow_id,omitempty"`
	UserID          string       `json:"user_id,omitempty"`
	DeviceID        string       `json:"device_id,omitempty"`
	Interface       string       `json:"interface,omitempty"`
	SrcIP           string       `json:"src_ip,omitempty"`
	DstIP           string       `json:"dst_ip,omitempty"`
	SrcPort         uint16       `json:"src_port,omitempty"`
	DstPort         uint16       `json:"dst_port,omitempty"`
	Protocol        string       `json:"protocol,omitempty"`
	Phase           string       `json:"phase,omitempty"`
	Started         time.Time    `json:"started,omitempty"`
	DurationMS      int64        `json:"duration_ms,omitempty"`
	BytesUp         uint64       `json:"bytes_up"`
	BytesDown       uint64       `json:"bytes_down"`
	Packets         uint64       `json:"packets"`
	TCPFlags        string       `json:"tcp_flags,omitempty"`
	Seq             uint32       `json:"seq,omitempty"`
	Ack             uint32       `json:"ack,omitempty"`
	Window          uint16       `json:"window,omitempty"`
	TTL             uint8        `json:"ttl,omitempty"`
	MTU             int          `json:"mtu,omitempty"`
	Retransmissions uint64       `json:"retransmissions,omitempty"`
	RST             uint64       `json:"rst,omitempty"`
	FIN             uint64       `json:"fin,omitempty"`
	HandshakeMS     int64        `json:"handshake_ms,omitempty"`
	DNS             *DNSMetadata `json:"dns,omitempty"`
	TLS             *TLSMetadata `json:"tls,omitempty"`
	Verdict         string       `json:"verdict"`
	Confidence      float64      `json:"confidence"`
	Reasons         []string     `json:"reasons"`
	Missing         []string     `json:"unavailable,omitempty"`
	CaptureID       string       `json:"capture_id,omitempty"`
	Dropped         uint64       `json:"capture_drops,omitempty"`
	Observation     string       `json:"observation,omitempty"`
}

func ID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return fmt.Sprintf("%032x", time.Now().UnixNano())
	}
	return hex.EncodeToString(b)
}
func (e *Event) Normalize() {
	if e.ID == "" {
		e.ID = ID()
	}
	if e.At.IsZero() {
		e.At = time.Now().UTC()
	}
	if e.Verdict == "" {
		e.Verdict = "unknown"
	}
	if e.Reasons == nil {
		e.Reasons = []string{}
	}
	if e.Confidence < 0 {
		e.Confidence = 0
	}
	if e.Confidence > 1 {
		e.Confidence = 1
	}
}
func Flags(flags uint8) string {
	out := []string{}
	for _, f := range []struct {
		b uint8
		s string
	}{{2, "SYN"}, {16, "ACK"}, {4, "RST"}, {1, "FIN"}, {8, "PSH"}, {32, "URG"}, {64, "ECE"}, {128, "CWR"}} {
		if flags&f.b != 0 {
			out = append(out, f.s)
		}
	}
	return strings.Join(out, "|")
}
func SafeIP(s string) bool { return net.ParseIP(s) != nil }
