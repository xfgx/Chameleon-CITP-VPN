package main

import (
	"chameleon/internal/desktopui"
	"os"
	"path/filepath"
)

func main() {
	out := os.Args[1]
	os.MkdirAll(out, 0700)
	samples := map[string]desktopui.Model{
		"protocol":     {Page: "protocol", State: "disconnected", AccessReady: true, Protocol: "ks"},
		"connected-ks": {Page: "home", State: "connected", AccessReady: true, BrokerReady: true, Mode: "KS", Up: 9437184, Down: 46137344},
		"connect":      {Page: "home", State: "disconnected", AccessReady: true, BrokerReady: true},
		"connected":    {Page: "home", State: "connected", AccessReady: true, BrokerReady: true, Up: 9437184, Down: 46137344, Mode: "CITP"},
		"access":       {Page: "access", State: "disconnected", AccessReady: true, Notice: "Ключ сохранён. Теперь откройте «Подключение» и нажмите «Подключить VPN»."},
		"diagnostics":  {Page: "diagnostics", State: "error", IssueCode: "ipc.receive", IssueDetail: "Соединение со службой закрыто до ответа. Повторите проверку после обновления приложения и службы.", Checked: "12:34:56"},
		"error":        {Page: "home", State: "error", AccessReady: true, IssueCode: "ipc.receive", IssueDetail: "Соединение со службой закрыто до ответа."},
		"activation":   {Page: "home", State: "disconnected"},
	}
	for name, m := range samples {
		os.WriteFile(filepath.Join(out, name+".svg"), []byte(desktopui.Build(840, 720, m).SVG()), 0600)
	}
	os.WriteFile(filepath.Join(out, "compact.svg"), []byte(desktopui.Build(760, 680, samples["connect"]).SVG()), 0600)
}
