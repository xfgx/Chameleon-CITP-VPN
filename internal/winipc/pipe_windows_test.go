//go:build windows

package winipc

import (
	"fmt"
	"golang.org/x/sys/windows"
	"os"
	"testing"
	"time"
)

// Uses a separate, random test pipe: no ChameleonBroker/adapter/firewall changes.
func TestIdentityAfterBoundedFrameRead(t *testing.T) {
	path := fmt.Sprintf(`\\.\pipe\Chameleon.Identity.Test.%d.%d`, os.Getpid(), time.Now().UnixNano())
	h, e := newPipeAt(path, true)
	if e != nil {
		t.Fatal(e)
	}
	server := &Conn{Handle: h}
	defer server.Close()
	token, e := windows.OpenCurrentProcessToken()
	if e != nil {
		t.Fatal(e)
	}
	defer token.Close()
	user, e := token.GetTokenUser()
	if e != nil {
		t.Fatal(e)
	}
	expected := user.User.Sid.String()
	result := make(chan error, 1)
	go func() {
		if e := windows.ConnectNamedPipe(h, nil); e != nil && e != windows.ERROR_PIPE_CONNECTED {
			result <- e
			return
		}
		var request struct {
			Version int `json:"version"`
		}
		if e := server.Receive(&request); e != nil {
			result <- e
			return
		}
		sid, e := server.ClientSID()
		if e != nil {
			result <- e
			return
		}
		if sid != expected {
			result <- fmt.Errorf("unexpected Windows identity (SID not logged)")
			return
		}
		result <- server.Send(struct {
			OK bool `json:"ok"`
		}{true})
	}()
	name, _ := windows.UTF16PtrFromString(path)
	handle, e := windows.CreateFile(name, windows.GENERIC_READ|windows.GENERIC_WRITE, 0, nil, windows.OPEN_EXISTING, windows.SECURITY_SQOS_PRESENT|windows.SECURITY_IDENTIFICATION, 0)
	if e != nil {
		t.Fatal(e)
	}
	client := &Conn{Handle: handle}
	defer client.Close()
	timer := time.AfterFunc(5*time.Second, func() { client.Close(); server.Close() })
	defer timer.Stop()
	if e = client.Send(struct {
		Version int `json:"version"`
	}{1}); e != nil {
		t.Fatal(e)
	}
	var response struct {
		OK bool `json:"ok"`
	}
	if e = client.Receive(&response); e != nil {
		t.Fatal(e)
	}
	if !response.OK {
		t.Fatal("identity handshake failed")
	}
	select {
	case e = <-result:
		if e != nil {
			t.Fatal(e)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("test pipe timeout")
	}
}
