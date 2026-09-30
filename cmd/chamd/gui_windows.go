//go:build windows

// Native desktop interface. Shared scene geometry is used by the visual previews.
package main

import (
	"chameleon/internal/clientactivation"
	"chameleon/internal/desktopui"
	"chameleon/internal/winipc"
	"context"
	"encoding/json"
	"fmt"
	"golang.org/x/sys/windows"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"
)

var user32 = windows.NewLazySystemDLL("user32.dll")
var gdi32 = windows.NewLazySystemDLL("gdi32.dll")
var shell32 = windows.NewLazySystemDLL("shell32.dll")

const guiMessage = 0x8001
const idConnect = desktopui.ConnectID
const idSave = desktopui.SaveID
const idHelp = desktopui.QRID

type rectangle struct{ Left, Top, Right, Bottom int32 }
type point struct{ X, Y int32 }
type minmax struct{ Reserved, MaximumSize, MaximumPosition, MinimumTrack, MaximumTrack point }
type windowClass struct {
	Size, Style                   uint32
	Procedure                     uintptr
	ClassExtra, WindowExtra       int32
	Instance, Icon, Cursor, Brush windows.Handle
	MenuName, ClassName           *uint16
	SmallIcon                     windows.Handle
}
type winMessage struct {
	Window         windows.Handle
	Message        uint32
	WParam, LParam uintptr
	Time           uint32
	X, Y           int32
	Private        uint32
}
type paintInfo struct {
	DC              windows.Handle
	Erase           int32
	Rect            rectangle
	Restore, Update int32
	Reserved        [32]byte
}
type drawItem struct {
	Type, ID, ItemID, Action, State uint32
	Window, DC                      windows.Handle
	Rect                            rectangle
	Data                            uintptr
}
type scrollInfo struct {
	Size, Mask      uint32
	Min, Max        int32
	Page            uint32
	Position, Track int32
}

var productGUI = struct {
	sync.Mutex
	hwnd                                     windows.Handle
	credentials                              clientactivation.Credentials
	response                                 brokerResponse
	model                                    desktopui.Model
	pendingToken                             string
	busy                                     atomic.Bool
	statusBusy                               atomic.Bool
	controls                                 map[int]windows.Handle
	styles                                   map[int]desktopui.Control
	fonts                                    map[string]windows.Handle
	brush                                    windows.Handle
	dpi, scroll, contentHeight, clientHeight int
	layoutScroll, layoutDPI                  int
}{model: desktopui.Model{Page: "home", State: "disconnected"}, response: brokerResponse{State: "disconnected"}, controls: map[int]windows.Handle{}, styles: map[int]desktopui.Control{}, fonts: map[string]windows.Handle{}, dpi: 96}

func utf(s string) *uint16 { v, _ := windows.UTF16PtrFromString(s); return v }
func text(h windows.Handle, s string) {
	user32.NewProc("SetWindowTextW").Call(uintptr(h), uintptr(unsafe.Pointer(utf(s))))
}
func px(n int) int32 { return int32((n*productGUI.dpi + 48) / 96) }
func color(hex string) uintptr {
	n, _ := strconv.ParseUint(strings.TrimPrefix(hex, "#"), 16, 32)
	return uintptr((n>>16)&255 | n&0xff00 | (n&255)<<16)
}
func rect(x, y, w, h int) rectangle { return rectangle{px(x), px(y), px(x + w), px(y + h)} }
func font(size int, bold bool) windows.Handle {
	key := fmt.Sprintf("%d/%t/%d", size, bold, productGUI.dpi)
	if h := productGUI.fonts[key]; h != 0 {
		return h
	}
	weight := 400
	if bold {
		weight = 600
	}
	height := -px(size)
	h, _, _ := gdi32.NewProc("CreateFontW").Call(uintptr(height), 0, 0, 0, uintptr(weight), 0, 0, 0, 1, 0, 0, 5, 0, uintptr(unsafe.Pointer(utf("Segoe UI"))))
	productGUI.fonts[key] = windows.Handle(h)
	return windows.Handle(h)
}
func snapshot() desktopui.Model {
	productGUI.Lock()
	defer productGUI.Unlock()
	m := productGUI.model
	m.Busy = productGUI.busy.Load()
	return m
}
func postGUI() { user32.NewProc("PostMessageW").Call(uintptr(productGUI.hwnd), guiMessage, 0, 0) }
func navigate(page string) {
	productGUI.Lock()
	productGUI.model.Page = page
	productGUI.Unlock()
	productGUI.scroll = 0
	guiLayout()
	postGUI()
}
func paintRect(dc windows.Handle, r rectangle, radius int, fill, stroke string) {
	brush, _, _ := gdi32.NewProc("CreateSolidBrush").Call(color(fill))
	defer gdi32.NewProc("DeleteObject").Call(brush)
	penColor := fill
	if stroke != "" {
		penColor = stroke
	}
	pen, _, _ := gdi32.NewProc("CreatePen").Call(0, uintptr(px(1)), color(penColor))
	defer gdi32.NewProc("DeleteObject").Call(pen)
	oldBrush, _, _ := gdi32.NewProc("SelectObject").Call(uintptr(dc), brush)
	defer gdi32.NewProc("SelectObject").Call(uintptr(dc), oldBrush)
	oldPen, _, _ := gdi32.NewProc("SelectObject").Call(uintptr(dc), pen)
	defer gdi32.NewProc("SelectObject").Call(uintptr(dc), oldPen)
	if radius == 0 {
		gdi32.NewProc("Rectangle").Call(uintptr(dc), uintptr(r.Left), uintptr(r.Top), uintptr(r.Right), uintptr(r.Bottom))
	} else {
		gdi32.NewProc("RoundRect").Call(uintptr(dc), uintptr(r.Left), uintptr(r.Top), uintptr(r.Right), uintptr(r.Bottom), uintptr(px(2*radius)), uintptr(px(2*radius)))
	}
}
func paintText(dc windows.Handle, r rectangle, value, fill string, size int, bold bool, flags uintptr) {
	old, _, _ := gdi32.NewProc("SelectObject").Call(uintptr(dc), uintptr(font(size, bold)))
	defer gdi32.NewProc("SelectObject").Call(uintptr(dc), old)
	gdi32.NewProc("SetBkMode").Call(uintptr(dc), 1)
	gdi32.NewProc("SetTextColor").Call(uintptr(dc), color(fill))
	user32.NewProc("DrawTextW").Call(uintptr(dc), uintptr(unsafe.Pointer(utf(value))), uintptr(^uint32(0)), uintptr(unsafe.Pointer(&r)), flags|0x800)
}
func paintScene(dc windows.Handle, s desktopui.Scene) {
	for _, e := range s.Elements {
		r := rect(e.X, e.Y, e.W, e.H)
		switch e.Kind {
		case "rect":
			paintRect(dc, r, e.R, e.Fill, e.Stroke)
		case "text":
			flags := uintptr(0x10)
			if e.Align == "center" {
				flags |= 1
			}
			paintText(dc, r, e.Text, e.Fill, e.Size, e.Bold, flags)
		case "logo":
			paintRect(dc, r, 8, "#73DBC2", "")
			paintText(dc, r, "C", "#16283D", 25, true, 1|4|0x20)
		case "power":
			paintRect(dc, r, 34, "#253B53", "")
			pen, _, _ := gdi32.NewProc("CreatePen").Call(0, uintptr(px(3)), color(e.Fill))
			old, _, _ := gdi32.NewProc("SelectObject").Call(uintptr(dc), pen)
			gdi32.NewProc("Arc").Call(uintptr(dc), uintptr(px(e.X+18)), uintptr(px(e.Y+18)), uintptr(px(e.X+50)), uintptr(px(e.Y+50)), uintptr(px(e.X+23)), uintptr(px(e.Y+25)), uintptr(px(e.X+45)), uintptr(px(e.Y+25)))
			gdi32.NewProc("MoveToEx").Call(uintptr(dc), uintptr(px(e.X+34)), uintptr(px(e.Y+17)), 0)
			gdi32.NewProc("LineTo").Call(uintptr(dc), uintptr(px(e.X+34)), uintptr(px(e.Y+35)))
			gdi32.NewProc("SelectObject").Call(uintptr(dc), old)
			gdi32.NewProc("DeleteObject").Call(pen)
		}
	}
}

// Render at 2x into an offscreen bitmap, then downsample once. No erase/frame flicker.
func bufferedDraw(target windows.Handle, width, height int32, draw func(windows.Handle)) {
	if width <= 0 || height <= 0 {
		return
	}
	dc, _, _ := gdi32.NewProc("CreateCompatibleDC").Call(uintptr(target))
	if dc == 0 {
		return
	}
	defer gdi32.NewProc("DeleteDC").Call(dc)
	bitmap, _, _ := gdi32.NewProc("CreateCompatibleBitmap").Call(uintptr(target), uintptr(width*2), uintptr(height*2))
	if bitmap == 0 {
		return
	}
	old, _, _ := gdi32.NewProc("SelectObject").Call(dc, bitmap)
	defer func() { gdi32.NewProc("SelectObject").Call(dc, old); gdi32.NewProc("DeleteObject").Call(bitmap) }()
	gdi32.NewProc("SetMapMode").Call(dc, 8)
	gdi32.NewProc("SetWindowExtEx").Call(dc, uintptr(width), uintptr(height), 0)
	gdi32.NewProc("SetViewportExtEx").Call(dc, uintptr(width*2), uintptr(height*2), 0)
	draw(windows.Handle(dc))
	gdi32.NewProc("SetViewportOrgEx").Call(dc, 0, 0, 0)
	gdi32.NewProc("SetMapMode").Call(dc, 1)
	oldMode, _, _ := gdi32.NewProc("SetStretchBltMode").Call(uintptr(target), 4)
	defer gdi32.NewProc("SetStretchBltMode").Call(uintptr(target), oldMode)
	gdi32.NewProc("SetBrushOrgEx").Call(uintptr(target), 0, 0, 0)
	gdi32.NewProc("StretchBlt").Call(uintptr(target), 0, 0, uintptr(width), uintptr(height), dc, 0, 0, uintptr(width*2), uintptr(height*2), 0x00cc0020)
}
func drawButton(item drawItem) {
	width, height := item.Rect.Right-item.Rect.Left, item.Rect.Bottom-item.Rect.Top
	bufferedDraw(item.DC, width, height, func(dc windows.Handle) { item.DC = dc; drawButtonContent(item) })
}
func drawButtonContent(item drawItem) {
	c, ok := productGUI.styles[int(item.ID)]
	if !ok {
		return
	}
	// Owner-drawn rounded buttons must fill the rectangle behind their corners.
	background := "#1B2636"
	if c.Style == "nav" || c.Style == "selected" {
		background = "#171F2C"
	}
	if c.ID == desktopui.ManageID {
		background = "#171F2C"
	}
	paintRect(item.DC, item.Rect, 0, background, "")
	fill, stroke := "#233247", "#425772"
	if c.Style == "nav" {
		fill = "#171F2C"
		stroke = fill
	}
	if c.Style == "selected" {
		fill = "#233B56"
		stroke = fill
	}
	if c.Style == "primary" {
		fill = "#216CB6"
		stroke = fill
	}
	foreground := "#FFFFFF"
	if item.State&4 != 0 {
		fill = "#24334A"
		foreground = "#AAB7CA"
	}
	if item.State&1 != 0 {
		fill = "#174D82"
	}
	paintRect(item.DC, item.Rect, 8, fill, stroke)
	if item.State&16 != 0 {
		focus := item.Rect
		focus.Left += px(3)
		focus.Top += px(3)
		focus.Right -= px(3)
		focus.Bottom -= px(3)
		user32.NewProc("DrawFocusRect").Call(uintptr(item.DC), uintptr(unsafe.Pointer(&focus)))
	}
	paintText(item.DC, item.Rect, c.Label, foreground, 14, true, 1|4|0x20)
}
func clientRect() rectangle {
	var r rectangle
	user32.NewProc("GetClientRect").Call(uintptr(productGUI.hwnd), uintptr(unsafe.Pointer(&r)))
	return r
}
func guiLayout() {
	if productGUI.hwnd == 0 {
		return
	}
	r := clientRect()
	w := int(r.Right) * 96 / productGUI.dpi
	h := int(r.Bottom) * 96 / productGUI.dpi
	productGUI.clientHeight = h
	productGUI.contentHeight = max(h, 680)
	productGUI.scroll = min(productGUI.scroll, max(0, productGUI.contentHeight-h))
	m := snapshot()
	scene := desktopui.Build(w, productGUI.contentHeight, m)
	previous := productGUI.styles
	productGUI.styles = map[int]desktopui.Control{}
	for _, c := range scene.Controls {
		handle := productGUI.controls[c.ID]
		productGUI.styles[c.ID] = c
		if c.Style != "edit" && previous[c.ID].Label != c.Label {
			text(handle, c.Label)
		}
		old := previous[c.ID]
		if old.X != c.X || old.Y != c.Y || old.W != c.W || old.H != c.H || productGUI.layoutScroll != productGUI.scroll || productGUI.layoutDPI != productGUI.dpi {
			user32.NewProc("MoveWindow").Call(uintptr(handle), uintptr(px(c.X)), uintptr(px(c.Y-productGUI.scroll)), uintptr(px(c.W)), uintptr(px(c.H)), 0)
		}
		if productGUI.layoutDPI != productGUI.dpi || old.ID == 0 {
			user32.NewProc("SendMessageW").Call(uintptr(handle), 0x30, uintptr(font(14, true)), 0)
		}
		if old != c || productGUI.layoutDPI != productGUI.dpi || productGUI.layoutScroll != productGUI.scroll {
			user32.NewProc("InvalidateRect").Call(uintptr(handle), 0, 0)
		}
		enabled := uintptr(1)
		if c.Disabled {
			enabled = 0
		}
		user32.NewProc("EnableWindow").Call(uintptr(handle), enabled)
		if _, visible := previous[c.ID]; !visible {
			user32.NewProc("ShowWindow").Call(uintptr(handle), 5)
		}
	}
	for id, handle := range productGUI.controls {
		if _, exists := productGUI.styles[id]; !exists {
			if _, visible := previous[id]; visible {
				user32.NewProc("ShowWindow").Call(uintptr(handle), 0)
			}
		}
	}
	info := scrollInfo{Size: uint32(unsafe.Sizeof(scrollInfo{})), Mask: 7, Min: 0, Max: int32(productGUI.contentHeight - 1), Page: uint32(h), Position: int32(productGUI.scroll)}
	user32.NewProc("SetScrollInfo").Call(uintptr(productGUI.hwnd), 1, uintptr(unsafe.Pointer(&info)), 1)
	productGUI.layoutScroll, productGUI.layoutDPI = productGUI.scroll, productGUI.dpi
	user32.NewProc("InvalidateRect").Call(uintptr(productGUI.hwnd), 0, 0)
}
func scrollTo(n int) {
	productGUI.scroll = max(0, min(n, productGUI.contentHeight-productGUI.clientHeight))
	guiLayout()
}
func guiRequest(request brokerRequest) {
	if request.Command == "status" {
		if productGUI.busy.Load() || !productGUI.statusBusy.CompareAndSwap(false, true) {
			return
		}
	} else {
		if !productGUI.busy.CompareAndSwap(false, true) {
			return
		}
	}
	productGUI.Lock()
	if request.Command == "connect" {
		productGUI.model.State = "connecting"
	}
	if request.Command == "disconnect" {
		productGUI.model.State = "disconnecting"
	}
	productGUI.Unlock()
	if request.Command != "status" {
		postGUI()
	}
	go func() {
		defer func() {
			if request.Command == "status" {
				productGUI.statusBusy.Store(false)
			} else {
				productGUI.busy.Store(false)
			}
			postGUI()
		}()
		timeout := 85 * time.Second
		if request.Command == "status" {
			timeout = 8 * time.Second
		}
		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		defer cancel()
		var response brokerResponse
		e := winipc.Call(ctx, request, &response)
		productGUI.Lock()
		defer productGUI.Unlock()
		if request.Command == "status" && productGUI.busy.Load() {
			return
		}
		productGUI.model.Checked = time.Now().Format("15:04:05")
		if e != nil {
			code, reason := winipc.Describe(e)
			productGUI.model.IssueCode = code
			productGUI.model.IssueDetail = reason
			productGUI.model.BrokerReady = false
			productGUI.model.State = "error"
			return
		}
		if response.Version != 1 {
			productGUI.model.IssueCode = "ipc.version"
			productGUI.model.IssueDetail = "Версия протокола службы несовместима с приложением."
			productGUI.model.BrokerReady = false
			return
		}
		productGUI.response = response
		productGUI.model.State = response.State
		productGUI.model.Up = response.Up
		productGUI.model.Down = response.Down
		productGUI.model.Mode = response.Mode
		productGUI.model.BrokerReady = !strings.HasPrefix(response.Code, "ipc.")
		productGUI.model.IssueCode = response.Code
		productGUI.model.IssueDetail = ""
		if response.Code != "" {
			productGUI.model.IssueDetail = response.Message
		}
		if response.State == "error" && response.Code == "" {
			productGUI.model.IssueCode = "vpn.connection"
			productGUI.model.IssueDetail = response.Message
		}
	}()
}
func saveGUIKey() {
	handle := productGUI.controls[desktopui.TokenID]
	n, _, _ := user32.NewProc("GetWindowTextLengthW").Call(uintptr(handle))
	if n > 6000 {
		return
	}
	b := make([]uint16, n+1)
	user32.NewProc("GetWindowTextW").Call(uintptr(handle), uintptr(unsafe.Pointer(&b[0])), uintptr(len(b)))
	value := strings.TrimSpace(windows.UTF16ToString(b))
	if token := tokenFromURI(value); token != "" {
		value = token
	}
	if value == "" || len(value) > 6000 || !strings.Contains(value, ".") || strings.ContainsAny(value, " \r\n\t") {
		productGUI.Lock()
		productGUI.model.NoticeError = true
		productGUI.model.Notice = "Вставьте подписанный ключ или QR-ссылку из бота."
		productGUI.Unlock()
		postGUI()
		return
	}
	productGUI.Lock()
	credentials := productGUI.credentials
	credentials.Token = value
	active := productGUI.model.State == "connected" || productGUI.model.State == "reconnecting"
	productGUI.Unlock()
	if active {
		return
	}
	e := saveCredentials(credentials)
	productGUI.Lock()
	if e != nil {
		productGUI.model.NoticeError = true
		productGUI.model.Notice = "Не удалось сохранить ключ в защищённом хранилище Windows."
	} else {
		productGUI.model.NoticeError = false
		productGUI.credentials = credentials
		productGUI.model.AccessReady = true
		productGUI.model.Notice = "Ключ сохранён. Теперь откройте «Подключение» и нажмите «Подключить VPN»."
	}
	productGUI.Unlock()
	if e == nil {
		text(handle, "")
	}
	postGUI()
}
func clipboardReport() {
	m := snapshot()
	report := fmt.Sprintf("Chameleon %s\nWindows IPC diagnostics\nBrokerReady: %t\nState: %s\nChecked: %s\nCode: %s\nDetail: %s\nCredentials/tokens/traffic: not included\n", desktopui.Version, m.BrokerReady, m.State, m.Checked, m.IssueCode, m.IssueDetail)
	b, _ := windows.UTF16FromString(report)
	opened, _, _ := user32.NewProc("OpenClipboard").Call(uintptr(productGUI.hwnd))
	if opened == 0 {
		return
	}
	defer user32.NewProc("CloseClipboard").Call()
	user32.NewProc("EmptyClipboard").Call()
	h, _, _ := windows.NewLazySystemDLL("kernel32.dll").NewProc("GlobalAlloc").Call(2, uintptr(len(b)*2))
	if h == 0 {
		return
	}
	p, _, _ := windows.NewLazySystemDLL("kernel32.dll").NewProc("GlobalLock").Call(h)
	if p == 0 {
		windows.NewLazySystemDLL("kernel32.dll").NewProc("GlobalFree").Call(h)
		return
	}
	windows.NewLazySystemDLL("ntdll.dll").NewProc("RtlMoveMemory").Call(p, uintptr(unsafe.Pointer(&b[0])), uintptr(len(b)*2))
	windows.NewLazySystemDLL("kernel32.dll").NewProc("GlobalUnlock").Call(h)
	result, _, _ := user32.NewProc("SetClipboardData").Call(13, h)
	if result == 0 {
		windows.NewLazySystemDLL("kernel32.dll").NewProc("GlobalFree").Call(h)
	}
}
func newControls(hwnd uintptr) {
	for _, id := range []int{desktopui.ConnectID, desktopui.SaveID, desktopui.QRID, desktopui.HomeID, desktopui.AccessID, desktopui.DiagnosticsID, desktopui.CheckID, desktopui.CopyID, desktopui.TokenID, desktopui.ManageID, desktopui.ProtocolID, desktopui.CITPID, desktopui.KSID} {
		class := "BUTTON"
		style := uintptr(0x40000000 | 0x00010000 | 0x0b)
		exstyle := uintptr(0)
		if id == desktopui.TokenID {
			class = "EDIT"
			style = 0x40000000 | 0x00010000 | 0x00000080 | 0x00000020
			exstyle = 0
		}
		h, _, _ := user32.NewProc("CreateWindowExW").Call(exstyle, uintptr(unsafe.Pointer(utf(class))), uintptr(unsafe.Pointer(utf(""))), style, 0, 0, 1, 1, hwnd, uintptr(id), 0, 0)
		productGUI.controls[id] = windows.Handle(h)
		if id == desktopui.TokenID {
			user32.NewProc("SendMessageW").Call(h, 0x00c5, 6000, 0)
			user32.NewProc("SendMessageW").Call(h, 0x1501, 1, uintptr(unsafe.Pointer(utf("Ключ или QR-ссылка"))))
			text(windows.Handle(h), "")
		}
	}
}
func nativeCopy(destination unsafe.Pointer, source uintptr, size uintptr) {
	windows.NewLazySystemDLL("ntdll.dll").NewProc("RtlMoveMemory").Call(uintptr(destination), source, size)
}
func windowProcedure(hwnd uintptr, message uint32, wparam, lparam uintptr) uintptr {
	switch message {
	case 0x0024:
		if lparam != 0 {
			minimum := point{px(780), px(550)}
			var layout minmax
			windows.NewLazySystemDLL("ntdll.dll").NewProc("RtlMoveMemory").Call(lparam+unsafe.Offsetof(layout.MinimumTrack), uintptr(unsafe.Pointer(&minimum)), unsafe.Sizeof(minimum))
		}
		return 0
	case 0x0001:
		productGUI.hwnd = windows.Handle(hwnd)
		dpi, _, _ := user32.NewProc("GetDpiForWindow").Call(hwnd)
		if dpi > 0 {
			productGUI.dpi = int(dpi)
		}
		newControls(hwnd)
		if productGUI.pendingToken != "" {
			text(productGUI.controls[desktopui.TokenID], productGUI.pendingToken)
			saveGUIKey()
			productGUI.pendingToken = ""
			productGUI.model.Page = "access"
		}
		guiLayout()
		user32.NewProc("SetTimer").Call(hwnd, 1, 3000, 0)
		return 0
	case 0x0005:
		guiLayout()
		return 0
	case 0x000f:
		var info paintInfo
		dc, _, _ := user32.NewProc("BeginPaint").Call(hwnd, uintptr(unsafe.Pointer(&info)))
		r := clientRect()
		w := int(r.Right) * 96 / productGUI.dpi
		bufferedDraw(windows.Handle(dc), r.Right, r.Bottom, func(buffer windows.Handle) {
			paintRect(buffer, r, 0, "#111722", "")
			gdi32.NewProc("SetViewportOrgEx").Call(uintptr(buffer), 0, uintptr(-px(productGUI.scroll)*2), 0)
			paintScene(buffer, desktopui.Build(w, productGUI.contentHeight, snapshot()))
		})
		user32.NewProc("EndPaint").Call(hwnd, uintptr(unsafe.Pointer(&info)))
		return 0
	case 0x0014:
		return 1
	case 0x002b:
		var item drawItem
		nativeCopy(unsafe.Pointer(&item), lparam, unsafe.Sizeof(item))
		drawButton(item)
		return 1
	case 0x0111:
		if (wparam >> 16) != 0 {
			return 0
		}
		id := int(wparam & 0xffff)
		switch id {
		case desktopui.HomeID:
			navigate("home")
		case desktopui.AccessID, desktopui.ManageID:
			navigate("access")
		case desktopui.DiagnosticsID:
			navigate("diagnostics")
		case desktopui.ProtocolID:
			navigate("protocol")
		case desktopui.CITPID, desktopui.KSID:
			m := snapshot()
			if m.Busy || m.State == "connected" || m.State == "reconnecting" || m.State == "connecting" || m.State == "disconnecting" {
				return 0
			}
			mode := "citp"
			if id == desktopui.KSID {
				mode = "ks"
			}
			if e := saveProtocol(mode); e == nil {
				productGUI.Lock()
				productGUI.model.Protocol = mode
				productGUI.Unlock()
				postGUI()
			}
		case desktopui.SaveID:
			saveGUIKey()
		case desktopui.QRID:
			shell32.NewProc("ShellExecuteW").Call(hwnd, uintptr(unsafe.Pointer(utf("open"))), uintptr(unsafe.Pointer(utf(clientactivation.Website+"#activation"))), 0, 0, 1)
		case desktopui.CheckID:
			guiRequest(brokerRequest{Version: 1, Command: "status"})
		case desktopui.CopyID:
			clipboardReport()
		case desktopui.ConnectID:
			m := snapshot()
			if strings.HasPrefix(m.IssueCode, "ipc.") {
				navigate("diagnostics")
				guiRequest(brokerRequest{Version: 1, Command: "status"})
				return 0
			}
			if !m.AccessReady {
				navigate("access")
				return 0
			}
			productGUI.Lock()
			credentials := productGUI.credentials
			productGUI.Unlock()
			command := "connect"
			if m.State == "connected" || m.State == "reconnecting" || m.State == "connecting" {
				command = "disconnect"
			}
			request := brokerRequest{Version: 1, Command: command}
			if command == "connect" {
				request.Credentials = &credentials
				request.Protocol = m.Protocol
			}
			guiRequest(request)
		}
		return 0
	case 0x0113:
		if !productGUI.busy.Load() {
			guiRequest(brokerRequest{Version: 1, Command: "status"})
		}
		return 0
	case guiMessage:
		guiLayout()
		return 0
	case 0x0115:
		code := wparam & 0xffff
		switch code {
		case 0:
			scrollTo(productGUI.scroll - 32)
		case 1:
			scrollTo(productGUI.scroll + 32)
		case 2:
			scrollTo(productGUI.scroll - productGUI.clientHeight/2)
		case 3:
			scrollTo(productGUI.scroll + productGUI.clientHeight/2)
		case 4, 5:
			scrollTo(int(wparam >> 16))
		case 6:
			scrollTo(0)
		case 7:
			scrollTo(productGUI.contentHeight)
		}
		return 0
	case 0x020a:
		scrollTo(productGUI.scroll - int(int16(wparam>>16))/120*48)
		return 0
	case 0x02e0:
		productGUI.dpi = int(wparam & 0xffff)
		var recommended rectangle
		nativeCopy(unsafe.Pointer(&recommended), lparam, unsafe.Sizeof(recommended))
		user32.NewProc("SetWindowPos").Call(hwnd, 0, uintptr(recommended.Left), uintptr(recommended.Top), uintptr(recommended.Right-recommended.Left), uintptr(recommended.Bottom-recommended.Top), 0x14)
		guiLayout()
		return 0
	case 0x0133:
		gdi32.NewProc("SetTextColor").Call(wparam, color("#F5F7FB"))
		gdi32.NewProc("SetBkColor").Call(wparam, color("#111722"))
		return uintptr(productGUI.brush)
	case 0x0010:
		user32.NewProc("DestroyWindow").Call(hwnd)
		return 0
	case 0x0002:
		for _, f := range productGUI.fonts {
			gdi32.NewProc("DeleteObject").Call(uintptr(f))
		}
		user32.NewProc("PostQuitMessage").Call(0)
		return 0
	}
	result, _, _ := user32.NewProc("DefWindowProcW").Call(hwnd, uintptr(message), wparam, lparam)
	return result
}
func runProductGUI(activationURI string) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	credentials, e := loadCredentials()
	if e != nil {
		user32.NewProc("MessageBoxW").Call(0, uintptr(unsafe.Pointer(utf("Не удалось открыть DPAPI-хранилище. Личный ключ не удалялся. Обратитесь к диагностике Windows."))), uintptr(unsafe.Pointer(utf("Chameleon"))), 0x10)
		return
	}
	productGUI.credentials = credentials
	productGUI.model.AccessReady = credentials.Token != ""
	productGUI.model.Protocol = loadProtocol()
	productGUI.pendingToken = tokenFromURI(activationURI)
	dpi, _, _ := user32.NewProc("GetDpiForSystem").Call()
	if dpi > 0 {
		productGUI.dpi = int(dpi)
	}
	brush, _, _ := gdi32.NewProc("CreateSolidBrush").Call(color("#111722"))
	productGUI.brush = windows.Handle(brush)
	instance, _, _ := windows.NewLazySystemDLL("kernel32.dll").NewProc("GetModuleHandleW").Call(0)
	cursor, _, _ := user32.NewProc("LoadCursorW").Call(0, 32512)
	largeIcon, _, _ := user32.NewProc("LoadImageW").Call(instance, 2, 1, uintptr(px(32)), uintptr(px(32)), 0)
	smallIcon, _, _ := user32.NewProc("LoadImageW").Call(instance, 2, 1, uintptr(px(16)), uintptr(px(16)), 0)
	class := windowClass{Style: 0, Procedure: windows.NewCallback(windowProcedure), Instance: windows.Handle(instance), Icon: windows.Handle(largeIcon), SmallIcon: windows.Handle(smallIcon), Cursor: windows.Handle(cursor), Brush: productGUI.brush, ClassName: utf("ChameleonFreeVPN.Native.V430")}
	class.Size = uint32(unsafe.Sizeof(class))
	user32.NewProc("RegisterClassExW").Call(uintptr(unsafe.Pointer(&class)))
	var work rectangle
	user32.NewProc("SystemParametersInfoW").Call(0x30, 0, uintptr(unsafe.Pointer(&work)), 0)
	width := min(px(880), work.Right-work.Left)
	height := min(px(740), work.Bottom-work.Top)
	left := work.Left + (work.Right-work.Left-width)/2
	top := work.Top + (work.Bottom-work.Top-height)/2
	hwnd, _, _ := user32.NewProc("CreateWindowExW").Call(0, uintptr(unsafe.Pointer(class.ClassName)), uintptr(unsafe.Pointer(utf("Chameleon VPN"))), 0x00cf0000|0x10000000|0x00200000|0x02000000, uintptr(left), uintptr(top), uintptr(width), uintptr(height), 0, 0, instance, 0)
	if hwnd == 0 {
		return
	}
	productGUI.hwnd = windows.Handle(hwnd)
	// Native title bar matches the application surface on supported Windows builds.
	dark := int32(1)
	windows.NewLazySystemDLL("dwmapi.dll").NewProc("DwmSetWindowAttribute").Call(hwnd, 20, uintptr(unsafe.Pointer(&dark)), 4)
	postGUI()
	go func() { time.Sleep(150 * time.Millisecond); guiRequest(brokerRequest{Version: 1, Command: "status"}) }()
	var message winMessage
	for {
		result, _, _ := user32.NewProc("GetMessageW").Call(uintptr(unsafe.Pointer(&message)), 0, 0, 0)
		if int32(result) <= 0 {
			break
		}
		handled, _, _ := user32.NewProc("IsDialogMessageW").Call(hwnd, uintptr(unsafe.Pointer(&message)))
		if handled == 0 {
			user32.NewProc("TranslateMessage").Call(uintptr(unsafe.Pointer(&message)))
			user32.NewProc("DispatchMessageW").Call(uintptr(unsafe.Pointer(&message)))
		}
	}
}

// Non-secret protocol preference is separate from the DPAPI activation vault.
func preferencePath() string {
	p := vaultPath()
	if p == "" {
		return ""
	}
	return filepath.Join(filepath.Dir(p), "preferences.json")
}
func loadProtocol() string {
	b, e := os.ReadFile(preferencePath())
	if e != nil || len(b) > 256 {
		return "citp"
	}
	var p struct{ Protocol string }
	if json.Unmarshal(b, &p) == nil && p.Protocol == "ks" {
		return "ks"
	}
	return "citp"
}
func saveProtocol(mode string) error {
	if mode != "ks" && mode != "citp" {
		return fmt.Errorf("invalid protocol")
	}
	b, _ := json.Marshal(struct{ Protocol string }{mode})
	p := preferencePath()
	if p == "" {
		return fmt.Errorf("preference path unavailable")
	}
	if e := os.MkdirAll(filepath.Dir(p), 0700); e != nil {
		return e
	}
	return os.WriteFile(p, b, 0600)
}
