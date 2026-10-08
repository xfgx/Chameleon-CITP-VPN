package rudirect

import (
	"net/netip"
	"testing"
)

func TestDataset(t *testing.T) {
	if n := len(Prefixes()); n < 2000 || n > 4000 {
		t.Fatalf("direct list size %d out of range", n)
	}
	if n := len(TunnelPrefixes()); n < 2000 || n > 3500 {
		t.Fatalf("complement list size %d out of range", n)
	}
	for _, p := range Prefixes() {
		if p.Addr().IsPrivate() || p.Addr().IsLoopback() || p.Bits() < 8 {
			t.Fatalf("suspicious direct prefix %v", p)
		}
	}
}

func TestContains(t *testing.T) {
	ru := []string{"77.88.8.8", "77.88.55.88", "5.255.255.242", "87.240.132.72", "94.100.180.200", "213.180.193.3"}
	foreign := []string{"8.8.8.8", "1.1.1.1", "142.250.74.14", "140.82.121.4", "149.154.167.99", "10.0.0.1", "192.168.1.1", "104.18.32.47"}
	for _, s := range ru {
		if !Contains(netip.MustParseAddr(s)) {
			t.Errorf("%s should be direct", s)
		}
	}
	for _, s := range foreign {
		if Contains(netip.MustParseAddr(s)) {
			t.Errorf("%s must stay in tunnel", s)
		}
	}
	if Contains(netip.MustParseAddr("2a02:6b8::2:242")) {
		t.Error("IPv6 is never direct")
	}
}

// The complement (Android < 13) list is coarser: CDN/hosting networks shared
// with foreign customers stay in the tunnel, but core Russian services must be
// direct and foreign services must be tunnelled.
func TestComplement(t *testing.T) {
	in := func(s string) bool {
		a := netip.MustParseAddr(s)
		for _, p := range TunnelPrefixes() {
			if p.Contains(a) {
				return true
			}
		}
		return false
	}
	for _, s := range []string{"77.88.55.88", "5.255.255.242", "87.240.132.72"} {
		if in(s) {
			t.Errorf("%s should be direct on Android < 13", s)
		}
	}
	for _, s := range []string{"8.8.8.8", "142.250.74.14", "149.154.167.99", "104.18.32.47", "140.82.121.4"} {
		if !in(s) {
			t.Errorf("%s must be tunnelled on Android < 13", s)
		}
	}
}

func TestIsRussianDomain(t *testing.T) {
	yes := []string{"yandex.ru", "www.gosuslugi.ru.", "VK.COM", "sun9-1.userapi.com", "xn--d1abbgf6aiiy.xn--p1ai", "mail.ru", "habr.com", "x.su", "wildberries.ru", "api.ozon.com"}
	no := []string{"google.com", "youtube.com", "ru.wikipedia.org", "telegram.org", "notvk.com", "vk.com.evil.io", "github.com", "", "ru"}
	for _, d := range yes {
		if !IsRussianDomain(d) {
			t.Errorf("%q should be Russian", d)
		}
	}
	for _, d := range no {
		if d == "ru" {
			continue
		}
		if IsRussianDomain(d) {
			t.Errorf("%q should not be Russian", d)
		}
	}
}

func TestQuestionName(t *testing.T) {
	msg := []byte{0x12, 0x34, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0,
		3, 'w', 'w', 'w', 6, 'y', 'a', 'n', 'd', 'e', 'x', 2, 'r', 'u', 0, 0, 1, 0, 1}
	n, err := QuestionName(msg)
	if err != nil || n != "www.yandex.ru" {
		t.Fatalf("got %q %v", n, err)
	}
	if _, err := QuestionName(msg[:15]); err == nil {
		t.Fatal("truncated message accepted")
	}
}
