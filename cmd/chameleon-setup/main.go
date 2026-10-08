// chameleon-setup — мастер первичной настройки: задаёт пару вопросов
// (адреса нод, порты auto/custom, число пользователей, домен) и заменяет
// все плейсхолдеры репозитория на ваши значения. Работает на Linux и Windows.
//
//	chameleon-setup                 интерактивно, в текущем каталоге репозитория
//	chameleon-setup -repo D:\chameleon -dry-run   только показать, что изменится
//	chameleon-setup -answers my.json -yes         без вопросов (CI / повторная установка)
//	chameleon-setup -undo                          откатить последнюю замену
//
// Оригиналы изменённых файлов сохраняются в .chameleon-setup/backup/<время>/.
// Секреты генерируются локально (crypto/rand) и пишутся только в secrets/ (0600).
package main

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"
)

const version = "chameleon-setup 1.0 (2026-10-08)"

// Плейсхолдеры, которые встречаются в репозитории (RFC 5737 / RFC 2606).
const (
	phRU      = "192.0.2.10"
	phRU2     = "192.0.2.11"
	phExit    = "198.51.100.10"
	phNode    = "your-node.example.com"
	phDomain  = "vpn.example.com"
	phBot     = "your_activation_bot"
	phSecret  = "<REDACTED>"
	defHubPrt = 51830
)

type Answers struct {
	RUNode      string `json:"ru_node"`
	ExitNode    string `json:"exit_node"`
	AdminIPs    string `json:"admin_ips"`
	HubPort     int    `json:"hub_port"`
	UserPorts   int    `json:"user_portbase"`  // 0 = выкл.
	RelayPorts  int    `json:"relay_portbase"` // плечо RU↔выход
	MaxUsers    int    `json:"max_users"`
	Domain      string `json:"domain"`
	Bot         string `json:"activation_bot"`
	WANIf       string `json:"wan_if"`
	GeneratedAt string `json:"generated_at"`
}

var (
	in      = bufio.NewReader(os.Stdin)
	assumeY bool
)

func main() {
	repo := flag.String("repo", ".", "корень репозитория Chameleon")
	dry := flag.Bool("dry-run", false, "ничего не менять, только показать план")
	ansFile := flag.String("answers", "", "JSON с ответами (поля как в .chameleon-setup/answers.json)")
	flag.BoolVar(&assumeY, "yes", false, "не задавать вопросов: брать значения по умолчанию / из -answers")
	undo := flag.Bool("undo", false, "откатить последнюю замену")
	ver := flag.Bool("version", false, "версия")
	flag.Parse()
	if *ver {
		fmt.Println(version)
		return
	}
	root, err := filepath.Abs(*repo)
	must(err)
	if _, err := os.Stat(filepath.Join(root, "go.mod")); err != nil {
		fail("%s не похож на репозиторий Chameleon (нет go.mod). Укажите -repo", root)
	}
	if *undo {
		must(doUndo(root))
		return
	}
	fmt.Printf("\n  %s — настройка за пару минут\n  Репозиторий: %s\n  Enter = значение в [скобках]\n\n", version, root)

	a := Answers{}
	if *ansFile != "" {
		b, err := os.ReadFile(*ansFile)
		must(err)
		must(json.Unmarshal(b, &a))
	}
	ask(&a)
	a.GeneratedAt = time.Now().UTC().Format(time.RFC3339)
	summary(a)
	if !confirm("Применить?", true) {
		fmt.Println("Отменено, ничего не изменено.")
		return
	}
	must(apply(root, a, *dry))
}

// ---------------------------------------------------------------- вопросы

func ask(a *Answers) {
	pub := ""
	if a.RUNode == "" {
		pub = detectPublicIP()
	}
	a.RUNode = askHost("1/8  RU-нода (вход): публичный IP или домен", a.RUNode, pub)
	a.ExitNode = askHost("2/8  Зарубежная нода (выход): IP или домен", a.ExitNode, "")
	if a.AdminIPs == "" {
		a.AdminIPs = a.RUNode
	}
	a.AdminIPs = askStr("3/8  IP, с которых разрешена админка (через запятую)", a.AdminIPs)
	a.HubPort = askPort("4/8  UDP-порт хаба для клиентов", a.HubPort, defHubPrt, 0)
	if a.MaxUsers == 0 {
		a.MaxUsers = 240
	}
	a.MaxUsers = askInt("5/8  Сколько пользователей максимум", a.MaxUsers, 1, 4000)
	a.UserPorts = askPortBase("6/8  Персональные порты пользователей на RU-ноде (порт = база + слот)", a.UserPorts, 56000, a.MaxUsers, true)
	a.RelayPorts = askPortBase("7/8  Персональные порты плеча RU↔выход (порт = база + слот)", a.RelayPorts, 52000, a.MaxUsers, false)
	a.Domain = askStr("8/8  Домен сайта/консоли (пусто = без домена)", a.Domain)
	if a.Domain != "" {
		a.Bot = askStr("     Telegram-бот активации (без @, пусто = нет)", a.Bot)
	}
	if a.WANIf == "" {
		a.WANIf = detectWAN()
	}
}

func prompt(q, def string) string {
	if assumeY {
		return def
	}
	if def != "" {
		fmt.Printf("%s [%s]: ", q, def)
	} else {
		fmt.Printf("%s: ", q)
	}
	s, err := in.ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		fail("ввод: %v", err)
	}
	s = strings.TrimSpace(s)
	if s == "" {
		return def
	}
	return s
}

func askStr(q, cur string) string { return prompt(q, cur) }

func askHost(q, cur, hint string) string {
	def := cur
	if def == "" {
		def = hint
	}
	for {
		v := prompt(q, def)
		if validHost(v) {
			return v
		}
		if assumeY {
			fail("%s: не задано (нужен -answers)", q)
		}
		fmt.Println("  ✗ нужен IPv4/IPv6 или домен, например 203.0.113.5 или node.example.net")
	}
}

func validHost(v string) bool {
	if net.ParseIP(v) != nil {
		return true
	}
	if v == "" || strings.ContainsAny(v, " /:") {
		return false
	}
	return strings.Contains(v, ".") && !strings.HasPrefix(v, ".") && !strings.HasSuffix(v, ".")
}

func askInt(q string, cur, lo, hi int) int {
	for {
		v := prompt(q, strconv.Itoa(cur))
		n, err := strconv.Atoi(v)
		if err == nil && n >= lo && n <= hi {
			return n
		}
		if assumeY {
			fail("%s: %q вне %d..%d", q, v, lo, hi)
		}
		fmt.Printf("  ✗ число от %d до %d\n", lo, hi)
	}
}

// askPort: auto (свободный случайный), default или custom.
func askPort(q string, cur, def, _ int) int {
	d := "default"
	if cur > 0 {
		d = strconv.Itoa(cur)
	}
	for {
		v := strings.ToLower(prompt(q+fmt.Sprintf(" — auto / default(%d) / число", def), d))
		switch v {
		case "default", "d":
			return def
		case "auto", "a":
			p := freeUDP(40000, 60000)
			fmt.Printf("  → выбран свободный порт %d\n", p)
			return p
		}
		if n, err := strconv.Atoi(v); err == nil && n >= 1024 && n <= 65535 {
			return n
		}
		if assumeY {
			fail("%s: %q", q, v)
		}
		fmt.Println("  ✗ auto, default или число 1024..65535")
	}
}

func askPortBase(q string, cur, def, users int, allowOff bool) int {
	d := "auto"
	if cur > 0 {
		d = strconv.Itoa(cur)
	}
	opts := " — auto / число-база"
	if allowOff {
		opts = " — auto / off / число-база"
	}
	for {
		v := strings.ToLower(prompt(q+opts, d))
		if v == "off" && allowOff {
			return 0
		}
		if v == "auto" || v == "a" {
			v = strconv.Itoa(def)
		}
		n, err := strconv.Atoi(v)
		if err == nil && n >= 1024 && n+users+11 <= 65535 {
			fmt.Printf("  → порты %d…%d\n", n+11, n+10+users)
			return n
		}
		if assumeY {
			fail("%s: %q не помещается в 1024..65535 для %d пользователей", q, v, users)
		}
		fmt.Printf("  ✗ база + %d пользователей должна помещаться в 1024..65535\n", users)
	}
}

func confirm(q string, def bool) bool {
	d := "Д/н"
	if !def {
		d = "д/Н"
	}
	v := strings.ToLower(prompt(q+" ("+d+")", ""))
	if v == "" {
		return def
	}
	return strings.HasPrefix(v, "д") || strings.HasPrefix(v, "y")
}

func freeUDP(lo, hi int) int {
	var b [2]byte
	for i := 0; i < 200; i++ {
		_, _ = rand.Read(b[:])
		p := lo + (int(b[0])<<8|int(b[1]))%(hi-lo)
		if c, err := net.ListenPacket("udp", ":"+strconv.Itoa(p)); err == nil {
			c.Close()
			return p
		}
	}
	return defHubPrt
}

func detectPublicIP() string {
	cl := &http.Client{Timeout: 3 * time.Second}
	r, err := cl.Get("https://api.ipify.org")
	if err != nil {
		return ""
	}
	defer r.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(r.Body, 64))
	if ip := net.ParseIP(strings.TrimSpace(string(b))); ip != nil {
		return ip.String()
	}
	return ""
}

func detectWAN() string {
	if runtime.GOOS != "linux" {
		return ""
	}
	b, err := os.ReadFile("/proc/net/route")
	if err != nil {
		return ""
	}
	for _, l := range strings.Split(string(b), "\n")[1:] {
		f := strings.Fields(l)
		if len(f) > 2 && f[1] == "00000000" {
			return f[0]
		}
	}
	return ""
}

func summary(a Answers) {
	up := "выкл. (все на общем порту)"
	if a.UserPorts > 0 {
		up = fmt.Sprintf("%d…%d", a.UserPorts+11, a.UserPorts+10+a.MaxUsers)
	}
	fmt.Printf(`
  ─────────────────────────────────────────────
  RU-нода (вход)       %s
  Выход                %s
  Админка с IP         %s
  Порт хаба            udp/%d
  Пользователей        до %d
  Порты пользователей  %s
  Порты плеча          %d…%d
  Домен / бот          %s / %s
  WAN-интерфейс        %s
  ─────────────────────────────────────────────
`, a.RUNode, a.ExitNode, a.AdminIPs, a.HubPort, a.MaxUsers, up,
		a.RelayPorts+11, a.RelayPorts+10+a.MaxUsers, dash(a.Domain), dash(a.Bot), dash(a.WANIf))
}

func dash(s string) string {
	if s == "" {
		return "—"
	}
	return s
}

// ---------------------------------------------------------------- замена

var skipDirs = map[string]bool{".git": true, "node_modules": true, "research": true, "experiments": true,
	"backups": true, ".chameleon-setup": true, "secrets": true, "testdata": true, "dist": true, "build": true, ".gradle": true}

var textExt = map[string]bool{".go": true, ".md": true, ".txt": true, ".sh": true, ".ps1": true, ".bat": true,
	".cmd": true, ".json": true, ".toml": true, ".yaml": true, ".yml": true, ".conf": true, ".service": true,
	".py": true, ".js": true, ".html": true, ".kt": true, ".xml": true, ".nsi": true, ".env": true, ".example": true, ".gradle": true, ".properties": true}

func replacements(a Answers, secret string) [][2]string {
	adm := strings.Split(a.AdminIPs, ",")
	adm2 := a.RUNode
	if len(adm) > 1 {
		adm2 = strings.TrimSpace(adm[1])
	}
	nodeName := a.RUNode
	if a.Domain != "" {
		nodeName = a.Domain
	}
	r := [][2]string{{phRU, a.RUNode}, {phRU2, adm2}, {phExit, a.ExitNode}, {phNode, nodeName},
		{"-listen 51830", fmt.Sprintf("-listen %d", a.HubPort)}, {"HUB_PORT:-51830", fmt.Sprintf("HUB_PORT:-%d", a.HubPort)}}
	if a.Domain != "" {
		r = append(r, [2]string{phDomain, a.Domain})
	}
	if a.Bot != "" {
		r = append(r, [2]string{phBot, a.Bot})
	}
	r = append(r, [2]string{phSecret, secret})
	return r
}

func apply(root string, a Answers, dry bool) error {
	secret := randHex(24)
	rep := replacements(a, secret)
	stamp := time.Now().Format("20060102-150405")
	bdir := filepath.Join(root, ".chameleon-setup", "backup", stamp)
	type change struct {
		path string
		n    int
	}
	var changes []change
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			if skipDirs[d.Name()] && p != root {
				return filepath.SkipDir
			}
			return nil
		}
		name := d.Name()
		if strings.HasSuffix(name, "_test.go") || !textExt[strings.ToLower(filepath.Ext(name))] {
			return nil
		}
		if fi, _ := d.Info(); fi == nil || fi.Size() > 2<<20 {
			return nil
		}
		b, err := os.ReadFile(p)
		if err != nil || bytes.IndexByte(b, 0) >= 0 {
			return nil
		}
		nb, n := b, 0
		isDoc := strings.HasSuffix(name, ".md")
		for _, kv := range rep {
			if kv[0] == phSecret && isDoc { // в документации <REDACTED> — пояснение, не секрет
				continue
			}
			if c := bytes.Count(nb, []byte(kv[0])); c > 0 {
				n += c
				nb = bytes.ReplaceAll(nb, []byte(kv[0]), []byte(kv[1]))
			}
		}
		if n == 0 {
			return nil
		}
		rel, _ := filepath.Rel(root, p)
		changes = append(changes, change{rel, n})
		if dry {
			return nil
		}
		bp := filepath.Join(bdir, rel)
		if err := os.MkdirAll(filepath.Dir(bp), 0o700); err != nil {
			return err
		}
		if err := os.WriteFile(bp, b, 0o600); err != nil {
			return err
		}
		fi, _ := d.Info()
		return os.WriteFile(p, nb, fi.Mode().Perm())
	})
	if err != nil {
		return err
	}
	sort.Slice(changes, func(i, j int) bool { return changes[i].path < changes[j].path })
	total := 0
	for _, c := range changes {
		total += c.n
	}
	fmt.Printf("\n  Замен: %d в %d файлах\n", total, len(changes))
	for i, c := range changes {
		if i == 12 {
			fmt.Printf("    … и ещё %d (полный список: .chameleon-setup/changes.txt)\n", len(changes)-12)
			break
		}
		fmt.Printf("    %-60s %d\n", c.path, c.n)
	}
	if dry {
		fmt.Println("\n  -dry-run: файлы не изменены.")
		return nil
	}
	sd := filepath.Join(root, ".chameleon-setup")
	var lst strings.Builder
	for _, c := range changes {
		fmt.Fprintf(&lst, "%s\t%d\n", c.path, c.n)
	}
	_ = os.WriteFile(filepath.Join(sd, "changes.txt"), []byte(lst.String()), 0o600)
	_ = os.WriteFile(filepath.Join(sd, "last"), []byte(stamp), 0o600)
	aj, _ := json.MarshalIndent(a, "", "  ")
	_ = os.WriteFile(filepath.Join(sd, "answers.json"), aj, 0o600)

	// секреты
	sec := filepath.Join(root, "secrets")
	must(os.MkdirAll(sec, 0o700))
	writeOnce(filepath.Join(sec, "relay-master.key"), randKey())
	writeOnce(filepath.Join(sec, "bridge-token.txt"), secret+"\n")

	// .env.chameleon (в .gitignore по маске .env.*) и bench/bench.env
	env := fmt.Sprintf("# сгенерировано %s\nRU_NODE=%s\nEXIT_NODE=%s\nADMIN_IPS=%s\nHUB_PORT=%d\nUSER_PORTBASE=%d\nRELAY_PORTBASE=%d\nMAX_USERS=%d\nDOMAIN=%s\nBOT=%s\nWAN_IF=%s\n",
		version, a.RUNode, a.ExitNode, a.AdminIPs, a.HubPort, a.UserPorts, a.RelayPorts, a.MaxUsers, a.Domain, a.Bot, a.WANIf)
	_ = os.WriteFile(filepath.Join(root, ".env.chameleon"), []byte(env), 0o600)
	if _, err := os.Stat(filepath.Join(root, "bench")); err == nil {
		be := fmt.Sprintf("NODE_IP=%s\nNODE_SSH=\"ssh root@%s\"\nHUB_PORT=51899\nPORTBASE=%d\nKEYS=1000\n", a.RUNode, a.RUNode, a.UserPorts)
		writeOnce(filepath.Join(root, "bench", "bench.env"), be)
	}
	must(os.WriteFile(filepath.Join(sd, "RUN.md"), []byte(runbook(a)), 0o600))
	fmt.Printf(`
  ✓ Готово.
    .env.chameleon            ваши параметры
    secrets/relay-master.key  ключ плеча RU↔выход (скопируйте на обе ноды в /etc/ks-relay/master.key, 0600)
    .chameleon-setup/RUN.md   готовые команды запуска для RU-ноды и выхода
    откат:                    chameleon-setup -undo
`)
	return nil
}

func runbook(a Answers) string {
	slotsHi := 10 + a.MaxUsers
	pb := ""
	if a.UserPorts > 0 {
		pb = fmt.Sprintf(" -portbase %d", a.UserPorts)
	}
	return fmt.Sprintf(`# Запуск (сгенерировано %s)

## RU-нода %s

`+"```bash"+`
make node                    # bin/ks-hub, bin/ks-relay (или скачайте релиз)
install -m600 secrets/relay-master.key /etc/ks-relay/master.key
# хаб клиентов: общий порт udp/%d%s
ks-hub -keydir /etc/ks-hub/users -tun kshub0 -innerself 10.99.9.2/24 -listen %d%s -maxusers %d
# плечо к выходу: персональный порт на каждого пользователя
ks-relay -role entry -slots 11-%d -portbase %d -tunip 10.96.0.1/30 -ctlpeer 10.96.0.2
`+"```"+`

Откройте в фаерволе: udp/%d%s и udp/%d…%d (плечо).

## Выход %s

`+"```bash"+`
install -m600 secrets/relay-master.key /etc/ks-relay/master.key
ks-relay -role exit -peer %s -slots 11-%d -portbase %d -tunip 10.96.0.2/30 -ctlpeer 10.96.0.1
ip route add 10.99.9.0/24 dev ksr0
iptables -t nat -A POSTROUTING -s 10.99.9.0/24 -o %s -j MASQUERADE
`+"```"+`

Выходу входящие порты не нужны: он сам открывает сеансы к RU-ноде.
`, a.GeneratedAt, a.RUNode, a.HubPort, userPortsNote(a), a.HubPort, pb, a.MaxUsers,
		slotsHi, a.RelayPorts, a.HubPort, userPortsNote(a), a.RelayPorts, a.RelayPorts+slotsHi,
		a.ExitNode, a.RUNode, slotsHi, a.RelayPorts, orStr(a.WANIf, "eth0"))
}

func userPortsNote(a Answers) string {
	if a.UserPorts == 0 {
		return ""
	}
	return fmt.Sprintf(" + персональные udp/%d…%d", a.UserPorts+11, a.UserPorts+10+a.MaxUsers)
}

func orStr(s, d string) string {
	if s == "" {
		return d
	}
	return s
}

func doUndo(root string) error {
	sd := filepath.Join(root, ".chameleon-setup")
	st, err := os.ReadFile(filepath.Join(sd, "last"))
	if err != nil {
		return fmt.Errorf("нечего откатывать: %w", err)
	}
	bdir := filepath.Join(sd, "backup", strings.TrimSpace(string(st)))
	n := 0
	err = filepath.WalkDir(bdir, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		rel, _ := filepath.Rel(bdir, p)
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		dst := filepath.Join(root, rel)
		mode := os.FileMode(0o644)
		if fi, err := os.Stat(dst); err == nil {
			mode = fi.Mode().Perm()
		}
		n++
		return os.WriteFile(dst, b, mode)
	})
	if err != nil {
		return err
	}
	_ = os.Remove(filepath.Join(sd, "last"))
	fmt.Printf("Откат: восстановлено %d файлов из %s\n", n, bdir)
	return nil
}

func writeOnce(p, content string) {
	if _, err := os.Stat(p); err == nil {
		fmt.Printf("  · %s уже есть — оставляю как есть\n", p)
		return
	}
	must(os.WriteFile(p, []byte(content), 0o600))
}

func randKey() string {
	b := make([]byte, 32)
	_, err := rand.Read(b)
	must(err)
	return base64.StdEncoding.EncodeToString(b) + "\n"
}

func randHex(n int) string {
	b := make([]byte, n)
	_, err := rand.Read(b)
	must(err)
	return hex.EncodeToString(b)
}

func must(err error) {
	if err != nil {
		fail("%v", err)
	}
}

func fail(f string, a ...any) {
	fmt.Fprintf(os.Stderr, "✗ "+f+"\n", a...)
	if runtime.GOOS == "windows" && !assumeY {
		fmt.Fprint(os.Stderr, "Нажмите Enter…")
		_, _ = in.ReadString('\n')
	}
	os.Exit(1)
}
