package main

import (
	"errors"
	"fmt"
	"strings"
	"syscall"
)

type productStageError struct {
	stage string
	cause error
}

func (e *productStageError) Error() string           { return e.stage }
func (e *productStageError) Unwrap() error           { return e.cause }
func productFailure(stage string, cause error) error { return &productStageError{stage, cause} }
func productErrorDetails(err error) (string, string) {
	stage := "connection"
	var e *productStageError
	if errors.As(err, &e) {
		stage = e.stage
	}
	messages := map[string]string{
		"connection":       "Соединение отменено или не завершилось вовремя.",
		"wintun.integrity": "Wintun отсутствует или не прошёл проверку. Восстановите приложение установщиком.",
		"activation":       "Сервер активации не подтвердил доступ. Проверьте ключ, срок и доступность сети.",
		"profile":          "Для выбранного протокола сервер не выдал профиль. Выберите другой протокол или обновите доступ.",
		"citp.handshake":   "CITP-сервер не подтвердил защищённое рукопожатие. Проверьте сеть и повторите.",
		"ks.clock":         "Системное время отличается от HTTPS-сервера. Откройте Параметры Windows → Время и язык → Синхронизировать. KS использует 8-секундные эпохи.",
		"ks.udp_send":      "Windows не смогла отправить UDP-запрос KS. Проверьте маршрут и локальные сетевые ограничения.",
		"ks.udp_read":      "Windows вернула ошибку при получении UDP-ответа KS. Проверьте доступность UDP-порта ноды.",
		"ks.auth":          "UDP-ответы пришли, но не прошли проверку KS. Проверьте время и персональный доступ.",
		"ks.handshake":     "Нет подтверждённого ответа KS-ноды. Проверьте UDP-доступность и персональный доступ.",
		"dns.bind":         "Локальный DNS-порт 53 занят. Закройте конфликтующий DNS/VPN-сервис и повторите.",
		"firewall":         "Не удалось включить защитные правила Windows Firewall. Проверьте службу брандмауэра.",
		"wintun.start":     "Не удалось поднять адаптер или маршруты Wintun. Восстановите установку и повторите.",
	}
	detail, ok := messages[stage]
	if !ok {
		stage = "connection"
		detail = messages[stage]
	}
	var guard *guardFailure
	if stage == "firewall" && errors.As(err, &guard) {
		detail = guardDetail(guard)
	}
	var probe *ksHandshakeFailure
	if errors.As(err, &probe) {
		detail += fmt.Sprintf(" Диагностические пробы: отправлено=%d, UDP-ответов=%d, отклонено=%d.", probe.sent, probe.received, probe.rejected)
	}
	var errno syscall.Errno
	if errors.As(err, &errno) {
		detail += fmt.Sprintf(" Windows error: %d.", uint32(errno))
	}
	// Only these controlled activation classifications are safe to disclose.
	if stage == "activation" && err != nil {
		for _, v := range []string{"activation HTTP 401", "activation HTTP 403", "activation HTTP 409", "activation HTTP 429", "activation HTTP 502", "activation HTTP 503", "profile validation failed", "device challenge rejected", "invalid installation key"} {
			if strings.Contains(errStringCause(err), v) {
				detail += " [" + v + "]"
				break
			}
		}
	}
	return "vpn." + stage, detail
}
func errStringCause(e error) string {
	for errors.Unwrap(e) != nil {
		e = errors.Unwrap(e)
	}
	return e.Error()
}

// isActivationFailure reports errors that the other transport cannot fix.
func isActivationFailure(err error) bool {
	var e *productStageError
	return errors.As(err, &e) && (e.stage == "activation" || e.stage == "wintun.integrity")
}
