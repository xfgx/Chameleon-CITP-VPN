//go:build linux

package main

import (
	"net"
	"testing"
)

func TestSlotMapping(t *testing.T) {
	ownAddr = net.ParseIP("10.96.0.1").To4()
	ctlPeerAddr = net.ParseIP("10.96.0.2").To4()
	_, userNet, _ = net.ParseCIDR("10.99.9.0/24")
	userBase = ip4u(userNet.IP)
	slotLo, slotHi = 11, 250
	cases := map[string]int{"10.96.0.1": 0, "10.96.0.2": 0, "10.99.9.11": 11, "10.99.9.250": 250,
		"10.99.9.5": -1, "10.99.9.255": -1, "8.8.8.8": -1, "10.99.8.20": -1}
	for ip, want := range cases {
		if got := slotFor(net.ParseIP(ip).To4()); got != want {
			t.Errorf("slotFor(%s)=%d want %d", ip, got, want)
		}
	}
}

func TestSlotKeysDistinct(t *testing.T) {
	m := make([]byte, 32)
	a, b := slotKey(m, 11), slotKey(m, 12)
	if string(a) == string(b) || len(a) != 32 {
		t.Fatal("slot keys must be distinct 32-byte keys")
	}
}
