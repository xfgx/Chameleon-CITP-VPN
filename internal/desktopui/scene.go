// Package desktopui is the shared, platform-independent desktop layout model.
package desktopui

import (
	"fmt"
	"html"
	"strings"
	"unicode/utf8"
)

const Version = "4.3.0 beta"
const (
	ConnectID     = 101
	SaveID        = 102
	QRID          = 103
	HomeID        = 104
	AccessID      = 105
	DiagnosticsID = 106
	CheckID       = 107
	CopyID        = 108
	TokenID       = 109
	ManageID      = 110
	ProtocolID    = 111
	CITPID        = 112
	KSID          = 113
)

type Model struct {
	Page, State, Notice, IssueCode, IssueDetail, Checked string
	AccessReady, Busy, BrokerReady, NoticeError          bool
	Up, Down                                             uint64
	Mode                                                 string
	Protocol                                             string
}
type Element struct {
	Kind               string
	X, Y, W, H, R      int
	Fill, Stroke, Text string
	Size               int
	Bold               bool
	Align              string
}
type Control struct {
	ID           int
	Label, Style string
	X, Y, W, H   int
	Disabled     bool
}
type Scene struct {
	Width, Height int
	Elements      []Element
	Controls      []Control
}

func bytes(n uint64) string {
	if n < 1024 {
		return fmt.Sprintf("%d Б", n)
	}
	if n < 1048576 {
		return fmt.Sprintf("%.1f КиБ", float64(n)/1024)
	}
	return fmt.Sprintf("%.1f МиБ", float64(n)/1048576)
}
func Build(w, h int, m Model) Scene {
	s := Scene{Width: w, Height: h}
	if m.Page == "" {
		m.Page = "home"
	}
	state := m.State
	rect := func(x, y, w, h, r int, fill, stroke string) {
		s.Elements = append(s.Elements, Element{Kind: "rect", X: x, Y: y, W: w, H: h, R: r, Fill: fill, Stroke: stroke})
	}
	text := func(x, y, w, h, size int, value, color string, bold bool, align string) {
		s.Elements = append(s.Elements, Element{Kind: "text", X: x, Y: y, W: w, H: h, Size: size, Text: value, Fill: color, Bold: bold, Align: align})
	}
	button := func(id, x, y, w, h int, label, style string, disabled bool) {
		s.Controls = append(s.Controls, Control{id, label, style, x, y, w, h, disabled})
	}
	rect(0, 0, w, h, 0, "#111722", "")
	rect(0, 0, 180, h, 0, "#171F2C", "")
	s.Elements = append(s.Elements, Element{Kind: "logo", X: 22, Y: 28, W: 32, H: 32})
	text(64, 29, 106, 26, 18, "Chameleon", "#F5F7FB", true, "left")
	text(24, 74, 132, 24, 12, "ПЕРСОНАЛЬНЫЙ VPN", "#AAB7CA", false, "left")
	for i, item := range []struct {
		ID          int
		Label, Page string
	}{{HomeID, "Подключение", "home"}, {AccessID, "Мой доступ", "access"}, {ProtocolID, "Протокол", "protocol"}, {DiagnosticsID, "Диагностика", "diagnostics"}} {
		style := "nav"
		if m.Page == item.Page {
			style = "selected"
		}
		button(item.ID, 16, 122+i*56, 148, 44, item.Label, style, false)
	}
	text(24, h-70, 132, 24, 12, "WINDOWS · X64", "#AAB7CA", false, "left")
	text(24, h-44, 132, 24, 13, "v"+Version, "#AAB7CA", false, "left")
	x := 204
	cw := w - x - 24
	title, subtitle := "Ваше подключение", "Одна кнопка. Сервер выбирается автоматически."
	if m.Page == "access" {
		title = "Персональный доступ"
		subtitle = "Ваш ключ — только на этом компьютере."
	}
	if m.Page == "protocol" {
		title = "Протокол VPN"
		subtitle = "Выберите транспорт для следующего подключения."
	}
	if m.Page == "diagnostics" {
		title = "Диагностика"
		subtitle = "Проверка связи с локальной службой VPN."
	}
	text(x, 28, cw, 38, 26, title, "#F5F7FB", true, "left")
	text(x, 72, cw, 30, 14, subtitle, "#AAB7CA", false, "left")
	switch m.Page {
	case "home":
		rect(x, 116, cw, 300, 12, "#1B2636", "#304158")
		color := "#8FBFF7"
		label := "Готов к подключению"
		detail := "Подключение ещё не установлено. Ваш трафик не защищён VPN."
		action := "Подключить VPN"
		switch state {
		case "connected":
			color = "#8AE0BC"
			label = "Соединение защищено"
			detail = "VPN подключён · " + m.Mode
			action = "Отключить VPN"
		case "connecting":
			label = "Подключаемся…"
			detail = "Проверяем доступ и устанавливаем соединение."
			action = "Подключение…"
		case "reconnecting":
			label = "Восстанавливаем связь"
			detail = "Повторно подключаемся к VPN-серверу."
			action = "Отключить VPN"
		case "disconnecting":
			label = "Отключаемся…"
			detail = "Завершаем VPN-сеанс."
			action = "Отключение…"
		case "in_use":
			color = "#EAC26B"
			label = "VPN занят"
			detail = "Соединение используется другим пользователем Windows."
		case "error":
			color = "#FFACA6"
			label = "Не удалось подключиться"
			detail = "Откройте диагностику: там есть причина и код ошибки."
			action = "Повторить подключение"
		}
		if !m.AccessReady && state != "connected" {
			label = "Добавьте персональный ключ"
			detail = "Получите QR-ссылку в боте и сохраните ключ в разделе «Мой доступ»."
			action = "Активировать доступ"
		}
		if m.IssueCode != "" {
			color = "#FFACA6"
			label = "Соединение не установлено"
			if strings.HasPrefix(m.IssueCode, "ipc.") {
				label = "Нет связи со службой"
			}
			detail = "" + m.IssueCode + " · подробности в диагностике"
			if strings.HasPrefix(m.IssueCode, "ipc.") {
				action = "Повторить проверку"
			} else {
				action = "Повторить подключение"
			}
		}
		s.Elements = append(s.Elements, Element{Kind: "power", X: x + cw/2 - 34, Y: 146, W: 68, H: 68, Fill: color})
		text(x+16, 231, cw-32, 34, 24, label, "#F5F7FB", true, "center")
		text(x+32, 278, cw-64, 42, 14, detail, "#AAB7CA", false, "center")
		button(ConnectID, x+24, 340, cw-48, 52, action, "primary", m.Busy || state == "in_use")
		rect(x, 432, cw, 84, 12, "#171F2C", "#29364A")
		mw := (cw - 48) / 3
		for i, v := range []struct{ A, B string }{{"СЕРВЕР", "Автовыбор"}, {"ОТПРАВЛЕНО", bytes(m.Up)}, {"ПОЛУЧЕНО", bytes(m.Down)}} {
			text(x+24+i*mw, 449, mw-8, 20, 11, v.A, "#AAB7CA", false, "left")
			text(x+24+i*mw, 476, mw-8, 25, 17, v.B, "#F5F7FB", true, "left")
		}
		rect(x, 532, cw, 96, 12, "#171F2C", "#29364A")
		text(x+24, 549, cw-210, 24, 16, "Персональный доступ", "#F5F7FB", true, "left")
		access := "Ключ пока не добавлен"
		if m.AccessReady {
			access = "Ключ сохранён · проверяется при подключении"
		}
		text(x+24, 580, cw-210, 38, 13, access, "#AAB7CA", false, "left")
		button(ManageID, x+cw-164, 558, 140, 44, "Мой доступ", "secondary", false)
	case "protocol":
		selected := m.Protocol
		if selected == "" {
			selected = "citp"
		}
		rect(x, 116, cw, 188, 12, "#1B2636", "#304158")
		text(x+24, 136, cw-48, 30, 21, "CITP", "#F5F7FB", true, "left")
		text(x+24, 177, cw-48, 44, 15, "Защищённый мультиплексированный транспорт. Текущий режим по умолчанию.", "#AAB7CA", false, "left")
		label, style := "Выбрать CITP", "secondary"
		if selected == "citp" {
			label = "Выбран CITP"
			style = "primary"
		}
		locked := m.Busy || state == "connected" || state == "reconnecting" || state == "connecting" || state == "disconnecting"
		button(CITPID, x+24, 238, cw-48, 44, label, style, locked)
		rect(x, 320, cw, 188, 12, "#1B2636", "#304158")
		text(x+24, 340, cw-48, 30, 21, "KS", "#F5F7FB", true, "left")
		text(x+24, 381, cw-48, 44, 15, "KS через UDP. Нужны персональный KS-профиль и доступность UDP в вашей сети.", "#AAB7CA", false, "left")
		label, style = "Выбрать KS", "secondary"
		if selected == "ks" {
			label = "Выбран KS"
			style = "primary"
		}
		button(KSID, x+24, 442, cw-48, 44, label, style, locked)
		text(x+8, 530, cw-16, 72, 14, "Выбор сохраняется. Сначала отключите VPN для смены протокола. Приложение не переключается на другой транспорт незаметно.", "#AAB7CA", false, "left")
	case "access":
		rect(x, 116, cw, 290, 12, "#1B2636", "#304158")
		text(x+24, 139, cw-48, 28, 19, "Ключ активации", "#F5F7FB", true, "left")
		status := "Вставьте ключ или полную QR-ссылку из бота."
		if m.AccessReady {
			status = "Ключ сохранён. Чтобы заменить его, вставьте новый."
		}
		text(x+24, 178, cw-48, 30, 14, status, "#AAB7CA", false, "left")
		rect(x+23, 217, cw-46, 46, 8, "#111722", "#425772")
		s.Controls = append(s.Controls, Control{TokenID, "Персональный ключ или QR-ссылка", "edit", x + 24, 218, cw - 48, 44, m.Busy || state == "connected" || state == "reconnecting"})
		text(x+24, 276, cw-48, 40, 13, "Поле скрывает ключ. Адрес сервера и порты вводить не нужно.", "#AAB7CA", false, "left")
		button(SaveID, x+24, 334, (cw-60)/2, 48, "Сохранить ключ", "primary", m.Busy || state == "connected" || state == "reconnecting")
		button(QRID, x+36+(cw-60)/2, 334, (cw-60)/2, 48, "Получить QR", "secondary", false)
		rect(x, 426, cw, 112, 12, "#171F2C", "#29364A")
		text(x+24, 446, cw-48, 26, 17, "Защищённое хранение", "#F5F7FB", true, "left")
		text(x+24, 484, cw-48, 42, 14, "Ключ шифруется Windows DPAPI и привязан к вашему пользователю. В общую папку приложения он не записывается.", "#AAB7CA", false, "left")
		if m.Notice != "" {
			noticeColor := "#8AE0BC"
			if m.NoticeError {
				noticeColor = "#FFACA6"
			}
			text(x+8, 555, cw-16, 58, 14, m.Notice, noticeColor, false, "left")
		}
	case "diagnostics":
		rect(x, 116, cw, 350, 12, "#1B2636", "#304158")
		summary := "Ожидает проверки"
		color := "#AAB7CA"
		if m.BrokerReady {
			summary = "Связь со службой установлена"
			color = "#8AE0BC"
		}
		if m.IssueCode != "" {
			summary = "Не удалось установить VPN-соединение"
			if strings.HasPrefix(m.IssueCode, "ipc.") {
				summary = "Служба не отвечает или проверка отклонена"
			}
			color = "#FFACA6"
		}
		text(x+24, 141, cw-48, 52, 18, summary, color, true, "left")
		checked := m.Checked
		if checked == "" {
			checked = "ещё не выполнялась"
		}
		text(x+24, 205, cw-48, 24, 13, "Последняя проверка: "+checked, "#AAB7CA", false, "left")
		code := m.IssueCode
		if code == "" {
			code = "—"
		}
		text(x+24, 242, cw-48, 24, 14, "Код: "+code, "#F5F7FB", true, "left")
		cause := m.IssueDetail
		if cause == "" {
			cause = "Проверяются PID службы, путь установленного EXE и идентичность клиента. Защита не отключается."
		}
		text(x+24, 280, cw-48, 108, 14, cause, "#AAB7CA", false, "left")
		button(CheckID, x+24, 398, (cw-60)/2, 44, "Проверить службу", "primary", m.Busy)
		button(CopyID, x+36+(cw-60)/2, 398, (cw-60)/2, 44, "Копировать отчёт", "secondary", false)
		text(x+8, 491, cw-16, 78, 14, "Отчёт не содержит ключей, токенов или истории трафика. Запускайте приложение из установленного каталога, не из копии EXE.", "#AAB7CA", false, "left")
	}
	text(x, h-44, cw, 26, 12, "Без рекламы и аналитических SDK · Chameleon", "#AAB7CA", false, "left")
	return s
}
func (s Scene) SVG() string {
	var b strings.Builder
	fmt.Fprintf(&b, `<svg xmlns="http://www.w3.org/2000/svg" width="%d" height="%d" viewBox="0 0 %d %d">`, s.Width, s.Height, s.Width, s.Height)
	for _, e := range s.Elements {
		switch e.Kind {
		case "rect":
			fmt.Fprintf(&b, `<rect x="%d" y="%d" width="%d" height="%d" rx="%d" fill="%s" stroke="%s"/>`, e.X, e.Y, e.W, e.H, e.R, e.Fill, none(e.Stroke))
		case "logo":
			fmt.Fprintf(&b, `<rect x="%d" y="%d" width="32" height="32" rx="8" fill="#73DBC2"/><text x="%d" y="%d" fill="#16283D" font-family="Arial" font-weight="700" font-size="25">C</text>`, e.X, e.Y, e.X+6, e.Y+25)
		case "power":
			fmt.Fprintf(&b, `<circle cx="%d" cy="%d" r="34" fill="#253B53"/><path d="M %d %d A 16 16 0 1 0 %d %d M %d %d V %d" fill="none" stroke="%s" stroke-width="3" stroke-linecap="round"/>`, e.X+34, e.Y+34, e.X+23, e.Y+25, e.X+45, e.Y+25, e.X+34, e.Y+17, e.Y+35, e.Fill)
		case "text":
			weight := "400"
			if e.Bold {
				weight = "600"
			}
			anchor := "start"
			tx := e.X
			if e.Align == "center" {
				anchor = "middle"
				tx += e.W / 2
			}
			words := strings.Fields(e.Text)
			lines := []string{}
			line := ""
			max := float64(e.W) / (float64(e.Size) * .55)
			for _, v := range words {
				if line != "" && float64(utf8.RuneCountInString(line+" "+v)) > max {
					lines = append(lines, line)
					line = v
				} else {
					if line != "" {
						line += " "
					}
					line += v
				}
			}
			if line != "" {
				lines = append(lines, line)
			}
			for i, line := range lines {
				if i*(e.Size+5)+e.Size > e.H {
					break
				}
				fmt.Fprintf(&b, `<text x="%d" y="%d" fill="%s" font-family="Arial, sans-serif" font-size="%d" font-weight="%s" text-anchor="%s">%s</text>`, tx, e.Y+e.Size+i*(e.Size+5), e.Fill, e.Size, weight, anchor, html.EscapeString(line))
			}
		}
	}
	for _, c := range s.Controls {
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
		if c.Style == "edit" {
			fill = "#111722"
		}
		fmt.Fprintf(&b, `<rect x="%d" y="%d" width="%d" height="%d" rx="8" fill="%s" stroke="%s"/>`, c.X, c.Y, c.W, c.H, fill, stroke)
		if c.Style != "edit" {
			fmt.Fprintf(&b, `<text x="%d" y="%d" text-anchor="middle" fill="#FFFFFF" font-family="Arial" font-size="14" font-weight="600">%s</text>`, c.X+c.W/2, c.Y+c.H/2+5, html.EscapeString(c.Label))
		} else {
			fmt.Fprintf(&b, `<text x="%d" y="%d" fill="#AAB7CA" font-family="Arial" font-size="14">Ключ или QR-ссылка</text>`, c.X+12, c.Y+27)
		}
	}
	b.WriteString("</svg>")
	return b.String()
}
func none(s string) string {
	if s == "" {
		return "none"
	}
	return s
}
