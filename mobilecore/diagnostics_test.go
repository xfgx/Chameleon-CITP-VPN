package mobilecore

import (
	"os"
	"path/filepath"
	"testing"
)

func TestReleaseDiagnosticsDoNotWrite(t *testing.T) {
	defer SetDiagnosticsEnabled(true)
	path := filepath.Join(t.TempDir(), "private-diagnostics.log")
	SetLogPath(path)
	SetDiagnosticsEnabled(false)
	logf("sensitive target fixture")
	AddTrafficSample("up", 42, "tcp", "private-destination.invalid", false)
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("release log written")
	}
	if Logs() != "" || CompressedLogs() != "" {
		t.Fatal("release diagnostics retained")
	}
}
