package telemetry

import (
	"encoding/binary"
	"errors"
	"net"
)

type Packet struct {
	Src, Dst                string
	SrcPort, DstPort        uint16
	Protocol                string
	Flags, TTL              uint8
	Seq, Ack                uint32
	Window                  uint16
	PayloadLen, OriginalLen int
	Header                  []byte
}

// ParseHeaders copies only the base IP and TCP/UDP headers. TCP/IP option bytes are
// excluded from PCAP: unusual options can themselves carry user-controlled data.
// IPv6 extension chains and fragments are intentionally not interpreted as complete flows.
func ParseHeaders(b []byte) (Packet, error) {
	var p Packet
	if len(b) < 1 {
		return p, errors.New("empty packet")
	}
	var ipLen, transport, protocol, total int
	switch b[0] >> 4 {
	case 4:
		if len(b) < 20 {
			return p, errors.New("short IPv4")
		}
		ipLen = int(b[0]&15) * 4
		if ipLen < 20 || ipLen > 60 || len(b) < ipLen {
			return p, errors.New("IPv4 header length")
		}
		total = int(binary.BigEndian.Uint16(b[2:4]))
		if total < ipLen {
			return p, errors.New("IPv4 total length")
		}
		if binary.BigEndian.Uint16(b[6:8])&0x3fff != 0 {
			return p, errors.New("fragment observation unavailable")
		}
		p.Src = net.IP(b[12:16]).String()
		p.Dst = net.IP(b[16:20]).String()
		p.TTL = b[8]
		protocol = int(b[9])
		p.Header = append([]byte(nil), b[:20]...)
		// Remove IP options and adjust the declared IHL. A truncated diagnostic capture
		// is not intended to be replayable and IP checksum is recomputed below.
		p.Header[0] = (p.Header[0] & 0xf0) | 5
	case 6:
		if len(b) < 40 {
			return p, errors.New("short IPv6")
		}
		ipLen = 40
		total = 40 + int(binary.BigEndian.Uint16(b[4:6]))
		protocol = int(b[6])
		p.Src = net.IP(b[8:24]).String()
		p.Dst = net.IP(b[24:40]).String()
		p.TTL = b[7]
		p.Header = append([]byte(nil), b[:40]...)
	default:
		return p, errors.New("not an IP packet")
	}
	transport = ipLen
	if total < transport || len(b) < transport+8 {
		return p, errors.New("short transport")
	}
	p.SrcPort = binary.BigEndian.Uint16(b[transport : transport+2])
	p.DstPort = binary.BigEndian.Uint16(b[transport+2 : transport+4])
	switch protocol {
	case 6:
		if len(b) < transport+20 || total < transport+20 {
			return p, errors.New("short TCP")
		}
		h := int(b[transport+12]>>4) * 4
		if h < 20 || h > 60 || len(b) < transport+h || total < transport+h {
			return p, errors.New("TCP header length")
		}
		p.Protocol = "tcp"
		p.Flags = b[transport+13]
		p.Seq = binary.BigEndian.Uint32(b[transport+4 : transport+8])
		p.Ack = binary.BigEndian.Uint32(b[transport+8 : transport+12])
		p.Window = binary.BigEndian.Uint16(b[transport+14 : transport+16])
		p.PayloadLen = total - transport - h
		p.Header = append(p.Header, b[transport:transport+20]...)
		p.Header[len(p.Header)-8] = (p.Header[len(p.Header)-8] & 15) | 0x50
	case 17:
		if total < transport+8 {
			return p, errors.New("short UDP")
		}
		length := int(binary.BigEndian.Uint16(b[transport+4 : transport+6]))
		if length < 8 || length > total-transport {
			return p, errors.New("UDP length")
		}
		p.Protocol = "udp"
		p.PayloadLen = length - 8
		p.Header = append(p.Header, b[transport:transport+8]...)
	default:
		return p, errors.New("unsupported or encrypted extension header")
	}
	p.OriginalLen = total
	if p.Header[0]>>4 == 4 {
		p.Header[10] = 0
		p.Header[11] = 0
		var sum uint32
		for i := 0; i < 20; i += 2 {
			sum += uint32(binary.BigEndian.Uint16(p.Header[i : i+2]))
		}
		for sum>>16 != 0 {
			sum = (sum & 65535) + (sum >> 16)
		}
		binary.BigEndian.PutUint16(p.Header[10:12], ^uint16(sum))
	}
	return p, nil
}
