package main

import (
	"errors"
	"strings"
	"syscall"
	"testing"
)

func TestSafeStageDetails(t *testing.T) {
	for _, stage := range []string{"activation", "citp.handshake", "dns.bind", "firewall", "wintun.start", "ks.handshake"} {
		code, detail := productErrorDetails(productFailure(stage, errors.New("SECRET_TOKEN payload.example")))
		if code != "vpn."+stage || strings.Contains(detail, "SECRET") || strings.Contains(detail, "example") {
			t.Fatal(code, detail)
		}
	}
}
func TestNumericOSFailure(t *testing.T) {
	_, d := productErrorDetails(productFailure("wintun.start", syscall.Errno(5)))
	if !strings.Contains(d, "Windows error: 5") {
		t.Fatal(d)
	}
}
