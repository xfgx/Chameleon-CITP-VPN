//go:build unix

package mobilecore

import (
	"syscall"
	"testing"
	"time"
)

// Отключение должно отпускать tun-fd сразу и не зависеть от разборки стека.
func TestReleaseVPNStackClosesTunQuickly(t *testing.T) {
	fds, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_DGRAM, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer syscall.Close(fds[1])
	if err := startVPNStack(int32(fds[0])); err != nil {
		t.Fatal(err)
	}
	t0 := time.Now()
	stopVPNStack()
	if d := time.Since(t0); d > 3*time.Second {
		t.Fatalf("stopVPNStack took %v", d)
	}
	if _, err := syscall.Write(fds[1], make([]byte, 40)); err == nil {
		// peer closed → write on a SOCK_DGRAM pair fails with ECONNREFUSED/EPIPE
		t.Fatal("tun fd still open after stopVPNStack")
	}
	tunnelMu.Lock()
	defer tunnelMu.Unlock()
	if vpnStack != nil || vpnDev != nil {
		t.Fatal("globals not cleared")
	}
}

func TestStopWhenIdleReturns(t *testing.T) {
	done := make(chan struct{})
	go func() { Stop(); close(done) }()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Stop blocked")
	}
}
