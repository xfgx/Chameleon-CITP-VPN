package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestApplyAndUndo(t *testing.T) {
	root := t.TempDir()
	os.WriteFile(filepath.Join(root, "go.mod"), []byte("module x\n"), 0o644)
	os.MkdirAll(filepath.Join(root, "cfg"), 0o755)
	orig := "node 192.0.2.10:4500\nexit 198.51.100.10\n-listen 51830\ntoken=\"<REDACTED>\"\n"
	f := filepath.Join(root, "cfg", "a.conf")
	os.WriteFile(f, []byte(orig), 0o644)
	doc := filepath.Join(root, "README.md")
	os.WriteFile(doc, []byte("secrets are <REDACTED>; node 192.0.2.10\n"), 0o644)
	a := Answers{RUNode: "45.1.2.3", ExitNode: "91.4.5.6", AdminIPs: "45.1.2.3", HubPort: 40001, UserPorts: 56000, RelayPorts: 52000, MaxUsers: 100}
	if err := apply(root, a, false); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(f)
	s := string(b)
	for _, want := range []string{"45.1.2.3:4500", "exit 91.4.5.6", "-listen 40001"} {
		if !strings.Contains(s, want) {
			t.Fatalf("missing %q in %q", want, s)
		}
	}
	if strings.Contains(s, "<REDACTED>") {
		t.Fatal("secret placeholder not replaced")
	}
	d, _ := os.ReadFile(doc)
	if !strings.Contains(string(d), "<REDACTED>") || !strings.Contains(string(d), "45.1.2.3") {
		t.Fatalf("doc handling wrong: %q", d)
	}
	if _, err := os.Stat(filepath.Join(root, "secrets", "relay-master.key")); err != nil {
		t.Fatal("no relay key")
	}
	if err := doUndo(root); err != nil {
		t.Fatal(err)
	}
	b, _ = os.ReadFile(f)
	if string(b) != orig {
		t.Fatalf("undo failed: %q", b)
	}
}

func TestValidHost(t *testing.T) {
	for v, ok := range map[string]bool{"1.2.3.4": true, "::1": true, "node.example.net": true, "": false, "a b": false, "localhost": false, "1.2.3.4:80": false} {
		if validHost(v) != ok {
			t.Errorf("validHost(%q) != %v", v, ok)
		}
	}
}
