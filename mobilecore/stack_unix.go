//go:build unix

package mobilecore

// Ручная сборка стека tun2socks БЕЗ engine.Start(): engine при любой ошибке
// вызывает log.Fatalf, что на Android убивает весь процесс приложения —
// отсюда были «вылеты» при нажатии «Подключиться». Здесь любая ошибка
// (включая панику gVisor) превращается в строку и возвращается в UI.

import (
	"fmt"
	"strconv"
	"sync"
	"syscall"
	"time"

	"gvisor.dev/gvisor/pkg/tcpip/stack"

	"github.com/xjasonlyu/tun2socks/v2/core"
	"github.com/xjasonlyu/tun2socks/v2/core/device"
	"github.com/xjasonlyu/tun2socks/v2/core/device/fdbased"
	"github.com/xjasonlyu/tun2socks/v2/core/option"
	"github.com/xjasonlyu/tun2socks/v2/proxy/socks5"
	"github.com/xjasonlyu/tun2socks/v2/tunnel"
)

var (
	vpnDev        device.Device
	vpnStack      *stack.Stack
	tunnelMu      sync.Mutex
	tunnelRunning bool
)

// startVPNStack поднимает gVisor-стек на fd туннеля и направляет весь
// трафик в локальный SOCKS5 (который уже умеет ходить через ноду).
func startVPNStack(tunFd int32) (err error) {
	var dev device.Device
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("сбой сетевого стека: %v", r)
		}
		if err != nil {
			if dev != nil {
				dev.Close()
			} else {
				_ = syscall.Close(int(tunFd))
			}
		}
	}()

	dev, err = fdbased.Open(strconv.Itoa(int(tunFd)), 1500, 0)
	if err != nil {
		return fmt.Errorf("tun-устройство: %w", err)
	}
	px, err := socks5.New("127.0.0.1:11080", "", "")
	if err != nil {
		return fmt.Errorf("proxy: %w", err)
	}

	tunnelMu.Lock()
	tunnel.T().SetProxy(px)
	if !tunnelRunning {
		tunnel.T().ProcessAsync()
		tunnelRunning = true
	}
	tunnelMu.Unlock()

	st, err := core.CreateStack(&core.Config{
		LinkEndpoint:     dev,
		TransportHandler: tunnel.T(),
		Options: []option.Option{
			option.WithTCPModerateReceiveBuffer(true),
			option.WithTCPSendBufferSize(4 << 20),
			option.WithTCPReceiveBufferSize(4 << 20),
		},
	})
	if err != nil {
		return fmt.Errorf("create stack: %w", err)
	}
	tunnelMu.Lock()
	vpnDev, vpnStack = dev, st
	tunnelMu.Unlock()
	dev = nil // ownership transferred to vpnDev
	return nil
}

// stopVPNStack отпускает TUN немедленно и не ждёт gVisor-стек.
func stopVPNStack() {
	releaseVPNStack(detachVPNStack())
}

// vpnStackHandle — снятый с глобальных переменных стек, который ещё нужно
// разобрать. Разборка идёт вне mu/tunnelMu.
type vpnStackHandle struct {
	st  *stack.Stack
	dev device.Device
}

// detachVPNStack забирает текущий стек под tunnelMu (вызывать можно под mu:
// порядок блокировок mu → tunnelMu). Новый Start не пострадает от старой
// разборки — ему достанутся уже чистые переменные.
func detachVPNStack() vpnStackHandle {
	tunnelMu.Lock()
	h := vpnStackHandle{st: vpnStack, dev: vpnDev}
	vpnStack, vpnDev = nil, nil
	tunnelMu.Unlock()
	return h
}

// nicDetachGrace — сколько ждём штатного снятия NIC (остановка читателя fd).
const nicDetachGrace = 1500 * time.Millisecond

// releaseVPNStack разбирает стек за ограниченное время.
//
// Раньше здесь было vpnStack.Close(); vpnStack.Wait(); vpnDev.Close() под
// глобальными блокировками. Stack.Wait() ждёт завершения ВСЕХ TCP-эндпоинтов
// и только в самом конце снимает NIC и закрывает дубликат tun-fd. После
// долгого сеанса (сотни соединений, зависшие relay/FIN-обмены через уже
// мёртвый сеанс) Wait мог не вернуться никогда: fd оставался открытым,
// Android держал VPN-интерфейс, а mu/tunnelMu оставались захвачены —
// «Отключить» переставала работать. Сразу после подключения эндпоинтов нет,
// поэтому там отключение срабатывало.
//
// Теперь: 1) снимаем NIC (останавливает читателя fd и закрывает fd через
// FD.Close), ждём не дольше nicDetachGrace; 2) закрываем fd в любом случае;
// 3) Abort/Wait эндпоинтов — только в фоне, никого не блокируя.
func releaseVPNStack(h vpnStackHandle) {
	if h.st == nil && h.dev == nil {
		return
	}
	t0 := time.Now()
	if h.st != nil {
		detached := make(chan struct{})
		go func() {
			defer close(detached)
			defer func() { _ = recover() }()
			for id := range h.st.NICInfo() {
				_ = h.st.RemoveNIC(id)
			}
		}()
		select {
		case <-detached:
		case <-time.After(nicDetachGrace):
			logf("стек: снятие NIC не уложилось в %v — закрываем tun принудительно", nicDetachGrace)
		}
	}
	if h.dev != nil {
		func() {
			defer func() { _ = recover() }()
			h.dev.Close() // идемпотентно: FD.Close уже мог вызвать RemoveNIC
		}()
	}
	logf("стек: tun закрыт за %d мс", time.Since(t0).Milliseconds())
	if h.st != nil {
		st := h.st
		go func() {
			defer func() { _ = recover() }()
			st.Close()
			done := make(chan struct{})
			go func() {
				defer func() { _ = recover() }()
				st.Wait()
				close(done)
			}()
			select {
			case <-done:
			case <-time.After(30 * time.Second):
				logf("стек: эндпоинты не завершились за 30 с (фоновая разборка, туннель уже отпущен)")
			}
		}()
	}
	// tunnel.T() остаётся запущенным (ProcessAsync один на процесс):
	// повторный ProcessAsync без Close плодил бы обработчики.
}
