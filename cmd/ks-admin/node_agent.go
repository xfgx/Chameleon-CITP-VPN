//go:build linux

package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"chameleon/internal/chameleon"
	"chameleon/internal/telemetry"
)

type nodePolicy struct {
	ID            string   `json:"id"`
	TelemetryDir  string   `json:"telemetry_dir,omitempty"`
	CaptureDir    string   `json:"capture_dir,omitempty"`
	CaptureWindow string   `json:"capture_window,omitempty"`
	AllowFile     string   `json:"allow_file"`
	CHAMUnit      string   `json:"cham_unit"`
	HubKeyDir     string   `json:"hub_key_dir,omitempty"`
	HubUnit       string   `json:"hub_unit,omitempty"`
	HubStatus     string   `json:"hub_status,omitempty"`
	Units         []string `json:"units"`
}

type nodeRequest struct {
	Action    string `json:"action"`
	Cursor    string `json:"cursor,omitempty"`
	CaptureID string `json:"capture_id,omitempty"`
	Seconds   int    `json:"seconds,omitempty"`
	Device    string `json:"device,omitempty"`
	PublicKey string `json:"public_key,omitempty"`
	Since     int    `json:"since,omitempty"`
	Limit     int    `json:"limit,omitempty"`
}
type nodeResponse struct {
	Error        string           `json:"error,omitempty"`
	Resources    *hostResources   `json:"resources,omitempty"`
	Telemetry    *telemetry.Batch `json:"telemetry,omitempty"`
	Capture      string           `json:"capture,omitempty"`
	CaptureUntil int64            `json:"capture_until,omitempty"`
	Version      string           `json:"version,omitempty"`
	Active       bool             `json:"active,omitempty"`
	AllowedCount int              `json:"allowed_count"`
	Logs         []logRecord      `json:"logs,omitempty"`
	Slot         int              `json:"slot,omitempty"`
	MasterKey    string           `json:"master_key,omitempty"`
}

func runNodeAgent() error {
	var policy nodePolicy
	if err := readStrictJSON(*fNodeConfig, &policy, 65536); err != nil {
		return err
	}
	var request nodeRequest
	if err := decodeStrictJSON(io.LimitReader(os.Stdin, 8193), &request); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	response, err := executeNode(ctx, policy, request)
	if err != nil {
		response.Error = redactLog(err.Error())
	}
	return json.NewEncoder(os.Stdout).Encode(response)
}
func validPublicKey(value string) bool {
	key, err := chameleon.ParseNodePubKey(value)
	if err != nil || !safeSingleLine(value) {
		return false
	}
	return base64.RawURLEncoding.EncodeToString(key.Bytes()) == strings.TrimRight(value, "=")
}
func normalizePublicKey(value string) string { return strings.TrimRight(strings.TrimSpace(value), "=") }

func executeNode(ctx context.Context, p nodePolicy, r nodeRequest) (nodeResponse, error) {
	var out nodeResponse
	if !validID(p.ID) || p.AllowFile == "" || p.CHAMUnit == "" {
		return out, errors.New("политика ноды не настроена")
	}
	if r.Action == "status" {
		b, err := os.ReadFile(p.AllowFile)
		if err != nil {
			return out, err
		}
		for _, ln := range strings.Split(string(b), "\n") {
			if validPublicKey(strings.TrimSpace(ln)) {
				out.AllowedCount++
			}
		}
		active, err := commandOutput(ctx, nil, "systemctl", "is-active", p.CHAMUnit)
		out.Active = err == nil && strings.TrimSpace(string(active)) == "active"
		out.Version = adminVersion
		out.Resources, _ = readHostResources()
		return out, nil
	}
	if p.TelemetryDir == "" {
		p.TelemetryDir = "/var/log/chameleon/telemetry"
	}
	if p.CaptureDir == "" {
		p.CaptureDir = "/run/chameleon/captures"
	}
	if p.CaptureWindow == "" {
		p.CaptureWindow = "/run/chameleon/capture-enabled-until"
	}
	if r.Action == "telemetry" {
		if len(r.Cursor) > 512 {
			return out, errors.New("cursor too long")
		}
		batch, err := telemetry.Read(p.TelemetryDir, r.Cursor, max(1, min(500, r.Limit)))
		out.Telemetry = &batch
		return out, err
	}
	if r.Action == "capture" {
		b, err := telemetry.ReadCapture(p.CaptureDir, r.CaptureID)
		if err != nil {
			return out, err
		}
		out.Capture = base64.StdEncoding.EncodeToString(b)
		return out, nil
	}
	if r.Action == "capture-window" {
		if r.Seconds < 0 || r.Seconds > 900 {
			return out, errors.New("invalid capture window")
		}
		out.CaptureUntil = time.Now().Unix() + int64(r.Seconds)
		if err := atomicPrivateFile(p.CaptureWindow, []byte(strconv.FormatInt(out.CaptureUntil, 10)+"\n")); err != nil {
			return out, err
		}
		return out, nil
	}
	if r.Action == "logs" {
		logs, err := nodeJournal(ctx, p, r)
		out.Logs = logs
		return out, err
	}
	if !validID(r.Device) || len(r.Device) < 12 {
		return out, errors.New("некорректный идентификатор устройства")
	}
	lock, err := os.OpenFile(p.AllowFile+".console.lock", os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return out, err
	}
	defer lock.Close()
	if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		return out, errors.New("другая операция ноды ещё выполняется")
	}
	defer syscall.Flock(int(lock.Fd()), syscall.LOCK_UN)
	switch r.Action {
	case "grant", "revoke":
		return out, updateAllowlist(ctx, p, r)
	case "ks-add", "ks-revoke", "ks-profile":
		return updateKS(ctx, p, r)
	default:
		return out, errors.New("действие запрещено политикой агента")
	}
}

func mutateAllowlist(before []byte, device, pub string, revoke bool) ([]byte, error) {
	if !validID(device) || !validPublicKey(pub) {
		return nil, errors.New("некорректный ключ или идентификатор")
	}
	pub = normalizePublicKey(pub)
	marker := "# console-device " + device
	lines := strings.Split(strings.TrimRight(string(before), "\n"), "\n")
	out := make([]string, 0, len(lines)+2)
	own := false
	for i := 0; i < len(lines); i++ {
		ln := strings.TrimSpace(lines[i])
		if ln == marker {
			if i+1 >= len(lines) || normalizePublicKey(lines[i+1]) != pub {
				return nil, errors.New("управляемая запись повреждена")
			}
			own = true
			if !revoke {
				out = append(out, marker, pub)
			}
			i++
			continue
		}
		if normalizePublicKey(ln) == pub && !strings.HasPrefix(ln, "#") {
			return nil, errors.New("этот ключ уже выдан вне данной записи панели")
		}
		out = append(out, lines[i])
	}
	if !own && !revoke {
		out = append(out, marker, pub)
	}
	return []byte(strings.TrimSpace(strings.Join(out, "\n")) + "\n"), nil
}

func updateAllowlist(ctx context.Context, p nodePolicy, r nodeRequest) error {
	before, err := os.ReadFile(p.AllowFile)
	if err != nil {
		return err
	}
	if len(before) > 1<<20 {
		return errors.New("allowlist exceeds limit")
	}
	after, err := mutateAllowlist(before, r.Device, r.PublicKey, r.Action == "revoke")
	if err != nil {
		return err
	}
	if err := atomicPrivateFile(p.AllowFile, after); err != nil {
		return err
	}
	if err := reloadCHAM(ctx, p, after); err != nil {
		restoreErr := atomicPrivateFile(p.AllowFile, before)
		if restoreErr == nil {
			_ = reloadCHAM(ctx, p, before)
		}
		if restoreErr != nil {
			return fmt.Errorf("reload failed; restore failed: %w", restoreErr)
		}
		return err
	}
	return nil
}

func reloadCHAM(ctx context.Context, p nodePolicy, body []byte) error {
	if _, err := commandOutput(ctx, nil, "systemctl", "kill", "--kill-who=main", "--signal=HUP", p.CHAMUnit); err != nil {
		return err
	}
	sum := sha256.Sum256(body)
	want := hex.EncodeToString(sum[:])
	timer := time.NewTimer(4 * time.Second)
	defer timer.Stop()
	tick := time.NewTicker(50 * time.Millisecond)
	defer tick.Stop()
	for {
		var status struct {
			SHA256 string    `json:"sha256"`
			Count  int       `json:"count"`
			At     time.Time `json:"at"`
		}
		if readStrictJSON(p.AllowFile+".status.json", &status, 8192) == nil && status.SHA256 == want {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-timer.C:
			return errors.New("нода не подтвердила обновление ключей; изменения отменены")
		case <-tick.C:
		}
	}
}

func updateKS(ctx context.Context, p nodePolicy, r nodeRequest) (nodeResponse, error) {
	var out nodeResponse
	if p.HubKeyDir == "" || p.HubUnit == "" || p.HubStatus == "" {
		return out, errors.New("KS-хаб на этой ноде не настроен")
	}
	entries, err := os.ReadDir(p.HubKeyDir)
	if err != nil {
		return out, err
	}
	used := map[int]bool{}
	found := ""
	count := 0
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".key") {
			continue
		}
		parts := strings.SplitN(e.Name(), "-", 2)
		slot, _ := strconv.Atoi(parts[0])
		used[slot] = true
		count++
		if len(parts) == 2 && parts[1] == "adm-"+r.Device+".key" {
			found = filepath.Join(p.HubKeyDir, e.Name())
			out.Slot = slot
		}
	}
	if r.Action == "ks-profile" {
		if found == "" {
			return out, errors.New("ключ устройства не найден")
		}
		b, err := os.ReadFile(found)
		if err != nil {
			return out, err
		}
		out.MasterKey = strings.TrimSpace(string(b))
		return out, nil
	}
	if r.Action == "ks-add" && found == "" {
		if count >= 64 {
			return out, errors.New("достигнут лимит 64 пользователей хаба")
		}
		// ks-hub accepts slots 11..250 only; slot 10 would be skipped by the hub.
		for slot := 11; slot <= 250; slot++ {
			if !used[slot] {
				out.Slot = slot
				break
			}
		}
		if out.Slot == 0 {
			return out, errors.New("нет свободных внутренних адресов")
		}
		key := make([]byte, 32)
		if _, err := rand.Read(key); err != nil {
			return out, err
		}
		found = filepath.Join(p.HubKeyDir, fmt.Sprintf("%03d-adm-%s.key", out.Slot, r.Device))
		if err := atomicPrivateFile(found, []byte(base64.StdEncoding.EncodeToString(key)+"\n")); err != nil {
			return out, err
		}
	}
	if r.Action == "ks-revoke" && found != "" {
		if err := os.Rename(found, found+".revoked"); err != nil {
			return out, err
		}
	}
	if _, err := commandOutput(ctx, nil, "systemctl", "kill", "--kill-who=main", "--signal=HUP", p.HubUnit); err != nil {
		return out, err
	}
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		var hub hubStatus
		if b, err := os.ReadFile(p.HubStatus); err == nil && json.Unmarshal(b, &hub) == nil {
			present := false
			for _, user := range hub.Users {
				if user.Name == "adm-"+r.Device {
					present = true
				}
			}
			if present == (r.Action == "ks-add") {
				return out, nil
			}
		}
		select {
		case <-ctx.Done():
			return out, ctx.Err()
		case <-time.After(100 * time.Millisecond):
		}
	}
	return out, errors.New("хаб не подтвердил обновление; повторите применение")
}

func nodeJournal(ctx context.Context, p nodePolicy, r nodeRequest) ([]logRecord, error) {
	limit := max(1, min(500, r.Limit))
	since := max(60, min(604800, r.Since))
	args := []string{"--no-pager", "-o", "json", "--output-fields=MESSAGE,PRIORITY,_SYSTEMD_UNIT,__REALTIME_TIMESTAMP", "--since", time.Now().Add(-time.Duration(since) * time.Second).UTC().Format("2006-01-02 15:04:05 UTC"), "-n", strconv.Itoa(limit)}
	for _, unit := range p.Units {
		if unit != "" {
			args = append(args, "-u", unit)
		}
	}
	if len(p.Units) == 0 {
		return nil, errors.New("journal unit scope is empty")
	}
	b, err := commandOutput(ctx, nil, "journalctl", args...)
	if err != nil {
		return nil, err
	}
	rows := make([]logRecord, 0)
	scanner := bufio.NewScanner(bytes.NewReader(b))
	scanner.Buffer(make([]byte, 8192), 1<<20)
	for scanner.Scan() {
		var record map[string]json.RawMessage
		if json.Unmarshal(scanner.Bytes(), &record) != nil {
			continue
		}
		text := func(key string) string { var s string; _ = json.Unmarshal(record[key], &s); return s }
		msg := redactLog(text("MESSAGE"))
		if msg == "" {
			continue
		}
		stamp, _ := strconv.ParseInt(text("__REALTIME_TIMESTAMP"), 10, 64)
		priority, _ := strconv.Atoi(text("PRIORITY"))
		level := "INFO"
		if priority <= 3 {
			level = "ERROR"
		} else if priority == 4 {
			level = "WARN"
		} else if priority >= 7 {
			level = "DEBUG"
		}
		if classified := classify(msg); classified != "" {
			level = classified
		}
		rows = append(rows, logRecord{At: time.UnixMicro(stamp).UTC(), Level: level, Node: p.ID, Source: text("_SYSTEMD_UNIT"), Message: msg})
	}
	sort.SliceStable(rows, func(i, j int) bool { return rows[i].At.Before(rows[j].At) })
	return rows, scanner.Err()
}
