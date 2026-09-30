//go:build windows

package main

import (
	"chameleon/internal/clientactivation"
	"chameleon/internal/winipc"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"io"
	"log"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"
)

var wintunSHA256 string // Set from the verified vendor DLL during the build-host build.
type brokerRequest struct {
	Version     int                           `json:"version"`
	Protocol    string                        `json:"protocol,omitempty"`
	Command     string                        `json:"command"`
	Credentials *clientactivation.Credentials `json:"credentials,omitempty"`
}
type brokerResponse struct {
	Version int    `json:"version"`
	Code    string `json:"code,omitempty"`
	State   string `json:"state"`
	Message string `json:"message"`
	Mode    string `json:"mode,omitempty"`
	Up      uint64 `json:"up_bytes"`
	Down    uint64 `json:"down_bytes"`
}
type productSession struct {
	ks          *productKS
	mode        string
	manager     *Manager
	tun         *TunDevice
	socks       net.Listener
	dns         net.PacketConn
	expiry      int64
	cancel      context.CancelFunc
	connections sync.Map
}

func (s *productSession) stop() {
	if s == nil {
		return
	}
	if s.ks != nil {
		s.ks.stop()
		ksResolver.CloseIdleConnections()
	}
	if s.cancel != nil {
		s.cancel()
	}
	if s.dns != nil {
		_ = s.dns.Close()
	}
	if s.socks != nil {
		_ = s.socks.Close()
	}
	s.connections.Range(func(key, value any) bool { _ = key.(net.Conn).Close(); return true })
	if s.manager != nil {
		s.manager.Disconnect()
	}
	if s.tun != nil {
		s.tun.Stop()
	}
	removeProductGuards()
}

var productOperation sync.Mutex
var broker = struct {
	sync.Mutex
	owner          string
	state, message string
	code           string
	session        *productSession
	cancel         context.CancelFunc
}{state: "disconnected"}

func verifyWintun() error {
	exe, e := os.Executable()
	if e != nil {
		return e
	}
	path := filepath.Join(filepath.Dir(exe), "wintun.dll")
	f, e := os.Open(path)
	if e != nil {
		return errors.New("Wintun is not installed")
	}
	defer f.Close()
	h := sha256.New()
	if _, e = io.Copy(h, f); e != nil {
		return e
	}
	if len(wintunSHA256) != 64 || !strings.EqualFold(hex.EncodeToString(h.Sum(nil)), wintunSHA256) {
		return errors.New("Wintun integrity check failed")
	}
	return nil
}

// autoPreferred remembers the transport that last worked in AUTO mode (memory only).
var autoPreferred atomic.Value

// beginAutoSession tries the last working transport first, then the other one.
// Each attempt fully tears down its adapter, routes and guards before the next.
func beginAutoSession(ctx context.Context, credentials clientactivation.Credentials) (*productSession, error) {
	order := []string{"ks", "citp"}
	if last, _ := autoPreferred.Load().(string); last == "citp" {
		order = []string{"citp", "ks"}
	}
	var first error
	for _, candidate := range order {
		if ctx.Err() != nil {
			break
		}
		broker.Lock()
		broker.message = "AUTO: проверяем " + strings.ToUpper(candidate)
		broker.Unlock()
		session, e := beginProductSession(ctx, credentials, candidate)
		if e == nil {
			autoPreferred.Store(candidate)
			session.mode = "AUTO · " + session.mode
			return session, nil
		}
		first = e // report the last attempted transport
		if isActivationFailure(e) {
			return nil, e
		}
	}
	if first == nil {
		first = productFailure("profile", ctx.Err())
	}
	return nil, first
}

func beginProductSession(ctx context.Context, credentials clientactivation.Credentials, protocol string) (*productSession, error) {
	if protocol == "auto" {
		return beginAutoSession(ctx, credentials)
	}
	if e := verifyWintun(); e != nil {
		return nil, productFailure("wintun.integrity", e)
	}
	profile, e := clientactivation.Fetch(ctx, credentials)
	if e != nil {
		return nil, productFailure("activation", e)
	}
	if protocol == "ks" {
		var selected *clientactivation.Server
		for i := range profile.Servers {
			if profile.Servers[i].Mode == "ks" {
				selected = &profile.Servers[i]
				break
			}
		}
		if selected == nil {
			return nil, productFailure("profile", errors.New("KS profile unavailable"))
		}
		session := &productSession{expiry: profile.ExpiresAt, mode: "KS"}
		succeeded := false
		defer func() {
			if !succeeded {
				session.stop()
			}
		}()
		session.dns, e = net.ListenPacket("udp4", "127.0.0.1:53")
		if e != nil {
			return nil, productFailure("dns.bind", e)
		}
		session.ks, e = startProductKS(ctx, *selected)
		if e != nil {
			return nil, e
		}
		sessionContext, cancel := context.WithCancel(context.Background())
		session.cancel = cancel
		go session.acceptDNS(sessionContext)
		succeeded = true
		return session, nil
	}
	// Restore the CITP adapter addressing after a previous KS session.
	tunIP, tunGW = "10.66.0.2", "10.66.0.1"
	store := &Store{}
	for _, p := range profile.Servers {
		if p.Mode == "citp" {
			store.Servers = append(store.Servers, ServerEntry{Name: p.Name, Addr: p.Address, PubKey: p.PublicKey})
		}
	}
	if len(store.Servers) == 0 {
		return nil, productFailure("profile", errors.New("CITP profile unavailable"))
	}
	m := NewManager(store, 8*time.Second, 40*time.Millisecond, "auto", credentials.TransportPrivate, nil)
	m.quiet = true
	m.semanticRequired = true
	// Preserve the audited Chameleon/CITP transport and semantic UDP. Do not run
	// legacy per-target logging, a local admin WebView or background third-party analytics.
	for index := range store.Servers {
		if e = m.Connect(index); e == nil {
			break
		}
	}
	if e != nil {
		return nil, productFailure("citp.handshake", e)
	}
	session := &productSession{manager: m, expiry: profile.ExpiresAt, mode: "CITP"}
	succeeded := false
	defer func() {
		if !succeeded {
			session.stop()
		}
	}()
	session.socks, e = net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		return nil, e
	}
	session.dns, e = net.ListenPacket("udp", "127.0.0.1:53")
	if e != nil {
		return nil, productFailure("dns.bind", e)
	}
	tunName = "ChameleonFree"
	session.tun = NewTun(m)
	session.tun.SetSocks(session.socks.Addr().String())
	sessionContext, cancel := context.WithCancel(context.Background())
	session.cancel = cancel
	go session.acceptSOCKS(sessionContext)
	go session.acceptDNS(sessionContext)
	if e = addProductGuards(); e != nil {
		return nil, productFailure("firewall", e)
	}
	if e = session.tun.Start(); e != nil {
		return nil, productFailure("wintun.start", e)
	}
	succeeded = true
	return session, nil
}
func (s *productSession) acceptSOCKS(ctx context.Context) {
	slots := make(chan struct{}, 256)
	for {
		conn, e := s.socks.Accept()
		if e != nil {
			return
		}
		select {
		case slots <- struct{}{}:
			s.connections.Store(conn, true)
			go func() { defer func() { s.connections.Delete(conn); <-slots }(); handleSOCKS(conn, s.manager) }()
		default:
			_ = conn.Close()
		}
		if ctx.Err() != nil {
			return
		}
	}
}
func (s *productSession) acceptDNS(ctx context.Context) {
	slots := make(chan struct{}, 64)
	buffer := make([]byte, 4096)
	for {
		n, src, e := s.dns.ReadFrom(buffer)
		if e != nil {
			return
		}
		query := append([]byte(nil), buffer[:n]...)
		select {
		case slots <- struct{}{}:
			go func() {
				defer func() { <-slots }()
				if s.ks != nil {
					handleKSDNS(s.dns, src, query)
				} else {
					handleDNS(s.dns, src, query, s.manager)
				}
			}()
		default:
		}
		if ctx.Err() != nil {
			return
		}
	}
}
func brokerStatus(sid string) brokerResponse {
	broker.Lock()
	defer broker.Unlock()
	response := brokerResponse{Version: 1, State: broker.state, Message: broker.message, Code: broker.code}
	if broker.owner != "" && broker.owner != sid {
		response.State = "in_use"
		response.Message = "VPN используется другим пользователем Windows"
		return response
	}
	if s := broker.session; s != nil {
		response.Mode = s.mode
		if s.ks != nil {
			response.Up, response.Down = s.ks.up.Load(), s.ks.down.Load()
		} else {
			st := s.manager.Status()
			response.Up, response.Down = st.UpBytes, st.DownBytes
		}
	}
	return response
}
func disconnectProduct(sid string, force bool) error {
	broker.Lock()
	if !force && broker.owner != "" && broker.owner != sid {
		broker.Unlock()
		return errors.New("session belongs to another Windows user")
	}
	if broker.cancel != nil {
		broker.cancel()
	}
	broker.Unlock()
	productOperation.Lock()
	defer productOperation.Unlock()
	broker.Lock()
	if !force && broker.owner != "" && broker.owner != sid {
		broker.Unlock()
		return errors.New("session belongs to another Windows user")
	}
	if broker.cancel != nil {
		broker.cancel()
	}
	session := broker.session
	broker.session = nil
	broker.state = "disconnecting"
	broker.Unlock()
	session.stop()
	broker.Lock()
	broker.owner = ""
	broker.state = "disconnected"
	broker.message = ""
	broker.code = ""
	broker.Unlock()
	return nil
}
func connectProduct(ctx context.Context, sid string, credentials clientactivation.Credentials, protocol string) error {
	if protocol == "" {
		protocol = "citp"
	}
	if protocol != "citp" && protocol != "ks" && protocol != "auto" {
		return productFailure("profile", errors.New("invalid protocol"))
	}
	productOperation.Lock()
	defer productOperation.Unlock()
	if ctx.Err() != nil {
		return ctx.Err()
	}
	broker.Lock()
	if broker.state != "disconnected" && broker.state != "error" {
		broker.Unlock()
		return errors.New("connection already active")
	}
	if broker.owner != "" && broker.owner != sid {
		broker.Unlock()
		return errors.New("another Windows user owns the session")
	}
	ctx, cancel := context.WithCancel(ctx)
	broker.cancel = cancel
	broker.owner = sid
	broker.state = "connecting"
	broker.code = ""
	broker.message = "Проверяем персональный доступ и маршруты"
	broker.Unlock()
	session, e := beginProductSession(ctx, credentials, protocol)
	broker.Lock()
	if e != nil || ctx.Err() != nil {
		broker.state = "error"
		if e == nil {
			e = ctx.Err()
		}
		broker.code, broker.message = productErrorDetails(e)
		broker.cancel = nil
		broker.Unlock()
		session.stop()
		cancel()
		return errors.New("connection failed")
	}
	broker.session = session
	broker.cancel = nil
	broker.state = "connected"
	broker.code = ""
	broker.message = "Подключено · " + session.mode
	broker.Unlock()
	cancel()
	go monitorProductSession(sid, session)
	return nil
}
func monitorProductSession(sid string, s *productSession) {
	ticker := time.NewTicker(3 * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		broker.Lock()
		current := broker.session == s
		broker.Unlock()
		if !current {
			return
		}
		if time.Now().Unix() >= s.expiry {
			_ = disconnectProduct(sid, false)
			broker.Lock()
			broker.state = "error"
			broker.code = "vpn.activation.expired"
			broker.message = "Срок ключа истёк. Получите новый QR."
			broker.Unlock()
			return
		}
		var e error
		if s.ks != nil {
			if time.Now().Unix()-s.ks.lastRx.Load() > 15 {
				e = errors.New("KS peer silent")
			}
		} else {
			_, e = s.manager.ensureMux()
		}
		broker.Lock()
		if broker.session != s {
			broker.Unlock()
			return
		}
		if e != nil {
			broker.state = "reconnecting"
			broker.message = "Туннель остаётся поднят; восстанавливаем сеанс"
		} else {
			broker.state = "connected"
			broker.code = ""
			broker.message = "Подключено · " + s.mode
		}
		broker.Unlock()
	}
}
func handleBroker(ctx context.Context, c *winipc.Conn) {
	var request brokerRequest
	if c.Receive(&request) != nil || request.Version != 1 {
		_ = c.Send(brokerResponse{Version: 1, State: "error", Message: "Запрос отклонён"})
		return
	}
	// Windows impersonation uses the last READ pipe message. Authenticate only
	// after the bounded strict frame read, but before any status/access/action.
	sid, identityError := c.ClientSID()
	if identityError != nil {
		_ = c.Send(brokerResponse{Version: 1, State: "error", Code: "ipc.client_identity", Message: "Windows не подтвердил идентичность клиента после чтения сообщения"})
		return
	}
	switch request.Command {
	case "status":
	case "connect":
		if request.Credentials == nil {
			_ = c.Send(brokerResponse{Version: 1, State: "error", Message: "Нет персонального ключа"})
			return
		}
		_ = connectProduct(ctx, sid, *request.Credentials, request.Protocol)
	case "disconnect":
		if disconnectProduct(sid, false) != nil {
			_ = c.Send(brokerResponse{Version: 1, State: "in_use", Message: "VPN используется другим пользователем"})
			return
		}
	default:
		_ = c.Send(brokerResponse{Version: 1, State: "error", Message: "Неизвестное действие"})
		return
	}
	_ = c.Send(brokerStatus(sid))
}

type productService struct{}

func (productService) Execute(args []string, requests <-chan svc.ChangeRequest, status chan<- svc.Status) (bool, uint32) {
	status <- svc.Status{State: svc.StartPending}
	log.SetOutput(io.Discard)
	exe, e := os.Executable()
	if e != nil {
		return false, 1
	}
	_ = os.Chdir(filepath.Dir(exe))
	kernel32 := windows.NewLazySystemDLL("kernel32.dll")
	_, _, _ = kernel32.NewProc("SetDefaultDllDirectories").Call(0x00001000)
	path, _ := windows.UTF16PtrFromString(filepath.Dir(exe))
	_, _, _ = kernel32.NewProc("SetDllDirectoryW").Call(uintptr(unsafe.Pointer(path)))
	if e := winipc.AllowBrokerIdentityQuery(); e != nil {
		return false, 4
	}
	removeProductGuards()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	errors := make(chan error, 1)
	ready := make(chan struct{})
	go func() { errors <- winipc.Listen(ctx, ready, handleBroker) }()
	select {
	case <-ready:
	case <-errors:
		return false, 2
	case <-time.After(15 * time.Second):
		return false, 3
	}
	status <- svc.Status{State: svc.Running, Accepts: svc.AcceptStop | svc.AcceptShutdown}
	for {
		select {
		case change := <-requests:
			switch change.Cmd {
			case svc.Interrogate:
				status <- change.CurrentStatus
			case svc.Stop, svc.Shutdown:
				status <- svc.Status{State: svc.StopPending}
				cancel()
				_ = disconnectProduct("", true)
				return false, 0
			}
		case <-errors:
			cancel()
			_ = disconnectProduct("", true)
			return false, 1
		}
	}
}
func platformProductMode(gui, service bool, activation string) bool {
	if service {
		if e := svc.Run(winipc.ServiceName, productService{}); e != nil {
			os.Exit(1)
		}
		return true
	}
	if gui {
		runProductGUI(activation)
		return true
	}
	return false
}
