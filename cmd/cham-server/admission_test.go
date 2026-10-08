package main

import (
	"testing"
	"time"
)

func TestAddrKeysGroupIPv6By64(t *testing.T) {
	a1, n1 := addrKeys("2001:db8:1:2:aaaa::1")
	a2, n2 := addrKeys("2001:db8:1:2:bbbb::2")
	if a1 != a2 || a1 != "2001:db8:1:2::/64" {
		t.Fatalf("IPv6 must be keyed by /64: %q %q", a1, a2)
	}
	if n1 != n2 || n1 != "2001:db8:1::/48" {
		t.Fatalf("IPv6 net must be /48: %q %q", n1, n2)
	}
	a, n := addrKeys("::ffff:198.51.100.7")
	if a != "198.51.100.7" || n != "198.51.100.0/24" {
		t.Fatalf("mapped IPv4: %q %q", a, n)
	}
}

func TestConnGateLimits(t *testing.T) {
	g := newConnGate(2, 5, 2, 3)
	x1, ok1 := g.admit("a", "n")
	_, ok2 := g.admit("a", "n")
	if !ok1 || !ok2 {
		t.Fatal("first two connections from one address must pass")
	}
	if _, ok := g.admit("a", "n"); ok {
		t.Fatal("per-address limit not enforced")
	}
	if _, ok := g.admit("b", "n"); !ok {
		t.Fatal("other address in same net must pass until net limit")
	}
	if _, ok := g.admit("c", "n"); ok {
		t.Fatal("per-net limit not enforced")
	}
	// CDN-фронт: без ключей адреса, только общий предел.
	w1, okw1 := g.admit("", "")
	_, okw2 := g.admit("", "")
	if !okw1 || !okw2 {
		t.Fatal("front connections must pass under global limit")
	}
	if _, ok := g.admit("", ""); ok {
		t.Fatal("global pending limit not enforced")
	}
	// Успешное рукопожатие освобождает слот ожидания.
	if !x1.promote() {
		t.Fatal("promote must succeed while session slots are free")
	}
	if _, ok := g.admit("", ""); !ok {
		t.Fatal("promoted connection must free its pending slot")
	}
	if !w1.promote() {
		t.Fatal("second session slot must be available")
	}
	x3, ok := g.admit("d", "m")
	if !ok {
		t.Fatal("pending slot expected")
	}
	if x3.promote() {
		t.Fatal("promote must fail when all session slots are taken")
	}
	x3.done()
	x1.done()
	w1.done()
	if len(g.sessions) != 0 {
		t.Fatalf("session slots leaked: %d", len(g.sessions))
	}
}

func TestConnGateHoldShrinksUnderPressure(t *testing.T) {
	g := newConnGate(1, 4, 10, 10)
	a, _ := g.admit("a", "n")
	if got := a.holdFor(45 * time.Second); got != 45*time.Second {
		t.Fatalf("hold without pressure: %v", got)
	}
	g.admit("b", "n")
	g.admit("c", "n")
	if got := a.holdFor(45 * time.Second); got != 5*time.Second {
		t.Fatalf("hold under pressure: %v", got)
	}
}
