//go:build windows

// Package winipc confines the privileged broker to local, kernel-identified users.
package winipc

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"golang.org/x/sys/windows"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"
	"unsafe"
)

const ServiceName = "ChameleonBroker"
const pipeName = `\\.\pipe\ChameleonFreeVPN.v1`

var kernel = windows.NewLazySystemDLL("kernel32.dll")
var advapi = windows.NewLazySystemDLL("advapi32.dll")

type Conn struct {
	Handle windows.Handle
	once   sync.Once
}

func (c *Conn) Close() {
	c.once.Do(func() { _ = windows.CancelIoEx(c.Handle, nil); _ = windows.CloseHandle(c.Handle) })
}
func (c *Conn) Read(b []byte) (int, error) {
	var n uint32
	e := windows.ReadFile(c.Handle, b, &n, nil)
	if e == nil && n == 0 {
		e = io.EOF
	}
	return int(n), e
}
func (c *Conn) Write(b []byte) (int, error) {
	var n uint32
	e := windows.WriteFile(c.Handle, b, &n, nil)
	return int(n), e
}
func (c *Conn) Send(value any) error {
	b, e := json.Marshal(value)
	if e != nil || len(b) > 16384 {
		return errors.New("IPC frame rejected")
	}
	header := make([]byte, 4)
	binary.LittleEndian.PutUint32(header, uint32(len(b)))
	for _, part := range [][]byte{header, b} {
		for len(part) > 0 {
			n, e := c.Write(part)
			if e != nil {
				return e
			}
			if n == 0 {
				return io.ErrShortWrite
			}
			part = part[n:]
		}
	}
	return nil
}
func (c *Conn) Receive(value any) error {
	header := make([]byte, 4)
	if _, e := io.ReadFull(c, header); e != nil {
		return e
	}
	size := binary.LittleEndian.Uint32(header)
	if size < 2 || size > 16384 {
		return errors.New("IPC frame size rejected")
	}
	b := make([]byte, size)
	if _, e := io.ReadFull(c, b); e != nil {
		return e
	}
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if e := d.Decode(value); e != nil {
		return e
	}
	if d.Decode(new(any)) != io.EOF {
		return errors.New("trailing IPC data")
	}
	return nil
}
func clientSID(handle windows.Handle) (string, error) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	ok, _, callError := advapi.NewProc("ImpersonateNamedPipeClient").Call(uintptr(handle))
	if ok == 0 {
		return "", &Failure{Stage: "client_identity", Cause: fmt.Errorf("ImpersonateNamedPipeClient: %w", callError)}
	}
	defer advapi.NewProc("RevertToSelf").Call()
	var token windows.Token
	if e := windows.OpenThreadToken(windows.CurrentThread(), windows.TOKEN_QUERY, true, &token); e != nil {
		return "", e
	}
	defer token.Close()
	user, e := token.GetTokenUser()
	if e != nil {
		return "", e
	}
	return user.User.Sid.String(), nil
}
func newPipe(first bool) (windows.Handle, error) { return newPipeAt(pipeName, first) }

func newPipeAt(pipePath string, first bool) (windows.Handle, error) {
	name, e := windows.UTF16PtrFromString(pipePath)
	if e != nil {
		return 0, e
	}
	descriptor, e := windows.SecurityDescriptorFromString("D:P(A;;GA;;;SY)(A;;GRGW;;;IU)")
	if e != nil {
		return 0, e
	}
	attributes := windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: descriptor}
	mode := uint32(3)
	if first {
		mode |= 0x00080000
	}
	return windows.CreateNamedPipe(name, mode, 0x00000008, 16, 16388, 16388, 10000, &attributes)
}
func (c *Conn) ClientSID() (string, error) { return clientSID(c.Handle) }

// Ready closes only once the first local pipe instance has been created.
func Listen(ctx context.Context, ready chan<- struct{}, handler func(context.Context, *Conn)) error {
	pending, e := newPipe(true)
	if e != nil {
		return e
	}
	if ready != nil {
		close(ready)
	}
	var mu sync.Mutex
	current := pending
	go func() {
		<-ctx.Done()
		mu.Lock()
		h := current
		current = 0
		mu.Unlock()
		if h != 0 {
			_ = windows.CancelIoEx(h, nil)
			_ = windows.CloseHandle(h)
		}
	}()
	semaphore := make(chan struct{}, 8)
	for ctx.Err() == nil {
		e = windows.ConnectNamedPipe(pending, nil)
		if e != nil && e != windows.ERROR_PIPE_CONNECTED {
			if ctx.Err() != nil {
				return nil
			}
			_ = windows.CloseHandle(pending)
			return e
		}
		next, createError := newPipe(false)
		if createError != nil {
			_ = windows.CloseHandle(pending)
			return createError
		}
		accepted := pending
		pending = next
		mu.Lock()
		current = pending
		mu.Unlock()
		select {
		case semaphore <- struct{}{}:
			go func(h windows.Handle) {
				defer func() { <-semaphore }()
				c := &Conn{Handle: h}
				defer c.Close()
				requestContext, cancel := context.WithTimeout(ctx, 90*time.Second)
				defer cancel()
				timer := time.AfterFunc(95*time.Second, c.Close)
				defer timer.Stop()
				handler(requestContext, c)
			}(accepted)
		default:
			_ = windows.CloseHandle(accepted)
		}
	}
	return nil
}

type serviceStatus struct{ Type, State, Controls, Exit, SpecificExit, Checkpoint, Wait, PID, Flags uint32 }

// Allow interactive clients to verify this LocalSystem process, and nothing more.
// Merge with the existing DACL: no VM_READ, VM_WRITE, termination or token access.
func AllowBrokerIdentityQuery() error {
	h, e := windows.OpenProcess(windows.READ_CONTROL|windows.WRITE_DAC, false, uint32(os.Getpid()))
	if e != nil {
		return e
	}
	defer windows.CloseHandle(h)
	sd, e := windows.GetSecurityInfo(h, windows.SE_KERNEL_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if e != nil {
		return e
	}
	old, _, e := sd.DACL()
	if e != nil || old == nil {
		return errors.New("broker process DACL unavailable")
	}
	sid, e := windows.StringToSid("S-1-5-4")
	if e != nil {
		return e
	}
	acl, e := windows.ACLFromEntries([]windows.EXPLICIT_ACCESS{{AccessPermissions: windows.PROCESS_QUERY_LIMITED_INFORMATION, AccessMode: windows.GRANT_ACCESS, Trustee: windows.TRUSTEE{TrusteeForm: windows.TRUSTEE_IS_SID, TrusteeType: windows.TRUSTEE_IS_WELL_KNOWN_GROUP, TrusteeValue: windows.TrusteeValueFromSID(sid)}}}, old)
	if e != nil {
		return e
	}
	return windows.SetSecurityInfo(h, windows.SE_KERNEL_OBJECT, windows.DACL_SECURITY_INFORMATION, nil, nil, acl, nil)
}

func trustedServer(handle windows.Handle) error {
	var pipePID uint32
	ok, _, _ := kernel.NewProc("GetNamedPipeServerProcessId").Call(uintptr(handle), uintptr(unsafe.Pointer(&pipePID)))
	if ok == 0 || pipePID == 0 {
		return errors.New("broker identity unavailable")
	}
	scm, _, _ := advapi.NewProc("OpenSCManagerW").Call(0, 0, 1)
	if scm == 0 {
		return errors.New("service manager unavailable")
	}
	defer advapi.NewProc("CloseServiceHandle").Call(scm)
	name, _ := windows.UTF16PtrFromString(ServiceName)
	service, _, _ := advapi.NewProc("OpenServiceW").Call(scm, uintptr(unsafe.Pointer(name)), 4)
	if service == 0 {
		return errors.New("broker is not installed")
	}
	defer advapi.NewProc("CloseServiceHandle").Call(service)
	var status serviceStatus
	var needed uint32
	ok, _, _ = advapi.NewProc("QueryServiceStatusEx").Call(service, 0, uintptr(unsafe.Pointer(&status)), unsafe.Sizeof(status), uintptr(unsafe.Pointer(&needed)))
	if ok == 0 || status.PID != pipePID || status.State != 4 {
		return errors.New("pipe does not belong to the registered running service")
	}
	process, e := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pipePID)
	if e != nil {
		return fmt.Errorf("broker process cannot be verified: %w", e)
	}
	defer windows.CloseHandle(process)
	buffer := make([]uint16, 1024)
	length := uint32(len(buffer))
	if e = windows.QueryFullProcessImageName(process, 0, &buffer[0], &length); e != nil {
		return e
	}
	pf, e := windows.KnownFolderPath(windows.FOLDERID_ProgramFiles, 0)
	if e != nil {
		return e
	}
	exe := filepath.Join(pf, "Chameleon VPN", "ChameleonBroker.exe")
	actual := filepath.Clean(windows.UTF16ToString(buffer[:length]))
	if !strings.EqualFold(actual, filepath.Clean(exe)) {
		return errors.New("broker executable is not the protected installed client")
	}
	return nil
}

// Failure is safe diagnostic metadata: never includes IPC requests or credentials.
type Failure struct {
	Stage string
	Cause error
}

func (e *Failure) Error() string { return fmt.Sprintf("%s: %v", e.Stage, e.Cause) }
func (e *Failure) Unwrap() error { return e.Cause }
func Describe(e error) (string, string) {
	var f *Failure
	if errors.As(e, &f) {
		return "ipc." + f.Stage, f.Cause.Error()
	}
	return "ipc.protocol", e.Error()
}
func Call(ctx context.Context, request, response any) error {
	name, e := windows.UTF16PtrFromString(pipeName)
	if e != nil {
		return e
	}
	deadline := time.Now().Add(4 * time.Second)
	var handle windows.Handle
	for {
		handle, e = windows.CreateFile(name, windows.GENERIC_READ|windows.GENERIC_WRITE, 0, nil, windows.OPEN_EXISTING, windows.SECURITY_SQOS_PRESENT|windows.SECURITY_IDENTIFICATION, 0)
		if e == nil {
			break
		}
		if !(errors.Is(e, windows.ERROR_PIPE_BUSY) || errors.Is(e, windows.ERROR_FILE_NOT_FOUND)) || time.Now().After(deadline) {
			return &Failure{Stage: "open_pipe", Cause: e}
		}
		select {
		case <-ctx.Done():
			return &Failure{Stage: "open_pipe", Cause: ctx.Err()}
		case <-time.After(100 * time.Millisecond):
		}
	}
	c := &Conn{Handle: handle}
	defer c.Close()
	if e = trustedServer(handle); e != nil {
		return &Failure{Stage: "server_identity", Cause: e}
	}
	done := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			c.Close()
		case <-done:
		}
	}()
	defer close(done)
	if e = c.Send(request); e != nil {
		return &Failure{Stage: "send", Cause: e}
	}
	if e = c.Receive(response); e != nil {
		return &Failure{Stage: "receive", Cause: e}
	}
	return nil
}
