// Package ksprobe emits a fixed synthetic root-DNS query inside the authenticated
// KS tunnel. It contains no user domain or traffic, and avoids depending on a
// node kernel's willingness to answer ICMP before capture routes are installed.
package ksprobe

import (
	"encoding/binary"
	"net"
)

const Port = 40000 // пример: задайте порт KS-probe своей инсталляции

func checksum(b []byte) uint16 {
	var n uint32
	for len(b) >= 2 {
		n += uint32(binary.BigEndian.Uint16(b))
		b = b[2:]
	}
	if len(b) > 0 {
		n += uint32(b[0]) << 8
	}
	for n>>16 != 0 {
		n = (n & 65535) + (n >> 16)
	}
	return ^uint16(n)
}
func DNS(src net.IP, seq uint16) []byte {
	q := []byte{0x43, 0x48, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 2, 0, 1} // root NS; fixed diagnostic only
	binary.BigEndian.PutUint16(q, seq)
	p := make([]byte, 28+len(q))
	p[0] = 0x45
	binary.BigEndian.PutUint16(p[2:], uint16(len(p)))
	p[8] = 64
	p[9] = 17
	copy(p[12:16], src.To4())
	copy(p[16:20], net.IPv4(8, 8, 8, 8).To4())
	binary.BigEndian.PutUint16(p[20:], Port)
	binary.BigEndian.PutUint16(p[22:], 53)
	binary.BigEndian.PutUint16(p[24:], uint16(8+len(q)))
	copy(p[28:], q)
	pseudo := make([]byte, 12+len(p)-20)
	copy(pseudo, p[12:20])
	pseudo[9] = 17
	binary.BigEndian.PutUint16(pseudo[10:], uint16(len(p)-20))
	copy(pseudo[12:], p[20:])
	c := checksum(pseudo)
	if c == 0 {
		c = 65535
	}
	binary.BigEndian.PutUint16(p[26:], c)
	binary.BigEndian.PutUint16(p[10:], checksum(p[:20]))
	return p
}
func IsReply(p []byte) bool {
	if len(p) < 40 || p[0]>>4 != 4 || p[9] != 17 {
		return false
	}
	h := int(p[0]&15) * 4
	return h >= 20 && len(p) >= h+20 && net.IP(p[12:16]).Equal(net.IPv4(8, 8, 8, 8)) && binary.BigEndian.Uint16(p[h:]) == 53 && binary.BigEndian.Uint16(p[h+2:]) == Port && p[h+10]&128 != 0
}
