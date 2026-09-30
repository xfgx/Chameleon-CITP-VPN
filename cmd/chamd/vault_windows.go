//go:build windows

package main

import (
	"chameleon/internal/clientactivation"
	"encoding/json"
	"fmt"
	"golang.org/x/sys/windows"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"unsafe"
)

func vaultPath() string {
	return filepath.Join(os.Getenv("LOCALAPPDATA"), "ChameleonVPN", "activation.dpapi")
}
func loadCredentials() (clientactivation.Credentials, error) {
	var result clientactivation.Credentials
	b, e := os.ReadFile(vaultPath())
	if os.IsNotExist(e) {
		created, e := clientactivation.NewCredentials()
		if e != nil {
			return result, e
		}
		if e = saveCredentials(created); e != nil {
			return result, e
		}
		return created, nil
	}
	if e != nil || len(b) < 1 || len(b) > 32768 {
		return result, fmt.Errorf("vault unavailable")
	}
	input := windows.DataBlob{Size: uint32(len(b)), Data: &b[0]}
	var output windows.DataBlob
	if e = windows.CryptUnprotectData(&input, nil, nil, 0, nil, windows.CRYPTPROTECT_UI_FORBIDDEN, &output); e != nil {
		return result, e
	}
	defer func() { _, _ = windows.LocalFree(windows.Handle(uintptr(unsafe.Pointer(output.Data)))) }()
	plain := unsafe.Slice(output.Data, output.Size)
	if e = json.Unmarshal(plain, &result); e != nil {
		return result, e
	}
	return result, nil
}
func saveCredentials(c clientactivation.Credentials) error {
	b, e := json.Marshal(c)
	if e != nil {
		return e
	}
	input := windows.DataBlob{Size: uint32(len(b)), Data: &b[0]}
	var output windows.DataBlob
	if e = windows.CryptProtectData(&input, nil, nil, 0, nil, windows.CRYPTPROTECT_UI_FORBIDDEN, &output); e != nil {
		return e
	}
	defer func() { _, _ = windows.LocalFree(windows.Handle(uintptr(unsafe.Pointer(output.Data)))) }()
	p := vaultPath()
	if e = os.MkdirAll(filepath.Dir(p), 0700); e != nil {
		return e
	}
	temporary := p + ".new"
	if e = os.WriteFile(temporary, unsafe.Slice(output.Data, output.Size), 0600); e != nil {
		return e
	}
	return os.Rename(temporary, p)
}
func tokenFromURI(value string) string {
	if len(value) > 8192 {
		return ""
	}
	u, e := url.Parse(value)
	if e != nil {
		return ""
	}
	if !(u.Scheme == "chameleon-vpn" && u.Host == "activate") && !(u.Scheme == "https" && u.Host == "vpn.example.com" && u.Path == "/vpn/activate") {
		return ""
	}
	token := strings.TrimPrefix(u.Fragment, "token=")
	if len(token) > 6000 || !strings.Contains(token, ".") || strings.ContainsAny(token, " \r\n\t") {
		return ""
	}
	return token
}
