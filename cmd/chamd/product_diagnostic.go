package main

import "fmt"

type guardFailure struct{ stage, number string }

func (e *guardFailure) Error() string { return "firewall guard failed" }
func guardDetail(e *guardFailure) string {
	if e.stage == "service" {
		return "Служба BFE или MpsSvc не запущена. Включите Windows Firewall штатными средствами Windows; защиту приложение не отключает."
	}
	if e.stage == "disabled" {
		return "Брандмауэр отключён для активного сетевого профиля. Включите его в «Безопасность Windows» и повторите."
	}
	return fmt.Sprintf("Не удалось создать/проверить защитные правила: этап %s, HRESULT %s. Правила других приложений не изменялись.", e.stage, e.number)
}

type ksHandshakeFailure struct{ sent, received, rejected uint64 }

func (e *ksHandshakeFailure) Error() string { return "no authenticated KS reply" }
func ksHandshakeStage(received uint64) string {
	if received > 0 {
		return "ks.auth"
	}
	return "ks.handshake"
}
