//go:build linux

package main

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode"
)

type deviceNodeState struct {
	State string `json:"state"`
	Error string `json:"error,omitempty"`
	Slot  int    `json:"slot,omitempty"`
}
type managedDevice struct {
	ID        string                     `json:"id"`
	Name      string                     `json:"name"`
	Platform  string                     `json:"platform"`
	Protocol  string                     `json:"protocol"`
	PublicKey string                     `json:"public_key,omitempty"`
	Nodes     []string                   `json:"nodes"`
	Status    map[string]deviceNodeState `json:"status"`
	State     string                     `json:"state"`
	Revoked   bool                       `json:"revoked"`
	Created   time.Time                  `json:"created"`
	Updated   time.Time                  `json:"updated"`
}
type createDeviceRequest struct {
	Name      string   `json:"name"`
	Platform  string   `json:"platform"`
	Protocol  string   `json:"protocol"`
	PublicKey string   `json:"public_key"`
	Nodes     []string `json:"nodes"`
}

var devicesState = struct {
	sync.Mutex
	path string
	rows []managedDevice
}{}
var nodeApply = callNode

func loadDevices(dir string) error {
	devicesState.Lock()
	defer devicesState.Unlock()
	devicesState.path = filepath.Join(dir, "managed-devices.json")
	err := readStrictJSON(devicesState.path, &devicesState.rows, 4<<20)
	if errors.Is(err, os.ErrNotExist) {
		devicesState.rows = []managedDevice{}
		return nil
	}
	if err != nil {
		return err
	}
	if len(devicesState.rows) > 1024 {
		return errors.New("too many managed devices")
	}
	return nil
}
func saveDevicesLocked() error {
	b, err := json.MarshalIndent(devicesState.rows, "", "  ")
	if err != nil {
		return err
	}
	return atomicPrivateFile(devicesState.path, b)
}
func deviceIndex(id string) int {
	for i := range devicesState.rows {
		if devicesState.rows[i].ID == id {
			return i
		}
	}
	return -1
}
func validateDevice(r createDeviceRequest) error {
	if strings.TrimSpace(r.Name) == "" || len([]rune(r.Name)) > 64 || strings.IndexFunc(r.Name, unicode.IsControl) >= 0 {
		return errors.New("название: от 1 до 64 символов без управляющих знаков")
	}
	if r.Platform != "windows" && r.Platform != "android" && r.Platform != "linux" {
		return errors.New("неизвестная платформа")
	}
	if r.Protocol != "citp" && r.Protocol != "ks" {
		return errors.New("неизвестный транспорт")
	}
	if r.Protocol == "citp" && !validPublicKey(r.PublicKey) {
		return errors.New("укажите публичный X25519-ключ устройства из клиента")
	}
	if len(r.Nodes) < 1 || len(r.Nodes) > 8 {
		return errors.New("выберите ноды")
	}
	seen := map[string]bool{}
	for _, id := range r.Nodes {
		n, ok := findNode(id)
		if !ok || seen[id] {
			return errors.New("неверный или повторный идентификатор ноды")
		}
		seen[id] = true
		if r.Protocol == "ks" && !n.SupportsKS {
			return errors.New("KS-хаб недоступен на выбранной ноде")
		}
	}
	return nil
}

func applyDeviceLocked(ctx context.Context, index int, actor string) error {
	d := &devicesState.rows[index]
	d.State = "partial"
	d.Updated = time.Now().UTC()
	if d.Status == nil {
		d.Status = map[string]deviceNodeState{}
	}
	if err := audit(actor, "", "device.apply", d.ID, "begin"); err != nil {
		return fmt.Errorf("не удалось записать аудит: %w", err)
	}
	if err := saveDevicesLocked(); err != nil {
		return err
	}
	for _, id := range d.Nodes {
		n, ok := findNode(id)
		if !ok {
			d.Status[id] = deviceNodeState{State: "pending", Error: "нода отсутствует в конфигурации"}
			continue
		}
		action := "grant"
		if d.Revoked {
			action = "revoke"
		}
		if d.Protocol == "ks" {
			action = "ks-add"
			if d.Revoked {
				action = "ks-revoke"
			}
		}
		response, err := nodeApply(ctx, n, nodeRequest{Action: action, Device: d.ID, PublicKey: d.PublicKey})
		status := deviceNodeState{State: "active", Slot: response.Slot}
		outcome := "ok"
		if d.Revoked {
			status.State = "revoked"
		}
		if err != nil {
			status.State = "pending"
			status.Error = redactLog(err.Error())
			outcome = "failed: " + status.Error
		}
		d.Status[id] = status
		if err := audit(actor, id, action, d.ID, outcome); err != nil {
			_ = saveDevicesLocked()
			return fmt.Errorf("операция выполнена; аудит недоступен, проверьте статусы: %w", err)
		}
		if err := saveDevicesLocked(); err != nil {
			return err
		}
	}
	d.State = "active"
	if d.Revoked {
		d.State = "revoked"
	}
	for _, status := range d.Status {
		if status.State == "pending" {
			d.State = "partial"
		}
	}
	d.Updated = time.Now().UTC()
	return saveDevicesLocked()
}

func handleDevices(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		devicesState.Lock()
		defer devicesState.Unlock()
		rows := append([]managedDevice{}, devicesState.rows...)
		sort.Slice(rows, func(i, j int) bool { return rows[i].Created.After(rows[j].Created) })
		writeJSON(w, map[string]any{"devices": rows})
		return
	}
	if !requireMutation(w, r) {
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 8192)
	var input createDeviceRequest
	if err := decodeStrictJSON(r.Body, &input); err != nil {
		http.Error(w, "Некорректный JSON", 400)
		return
	}
	input.Name = strings.TrimSpace(input.Name)
	input.PublicKey = normalizePublicKey(input.PublicKey)
	if err := validateDevice(input); err != nil {
		http.Error(w, err.Error(), 400)
		return
	}
	devicesState.Lock()
	defer devicesState.Unlock()
	if len(devicesState.rows) >= 1024 {
		http.Error(w, "Достигнут предел реестра устройств", 409)
		return
	}
	for _, d := range devicesState.rows {
		if !d.Revoked && (strings.EqualFold(d.Name, input.Name) || input.Protocol == "citp" && d.PublicKey == input.PublicKey) {
			http.Error(w, "Устройство с таким именем или ключом уже существует. Проверьте список перед повторной выдачей.", 409)
			return
		}
	}
	id, err := randBytes(12)
	if err != nil {
		http.Error(w, "Генератор случайных чисел недоступен", 500)
		return
	}
	d := managedDevice{ID: hex.EncodeToString(id), Name: input.Name, Platform: input.Platform, Protocol: input.Protocol, PublicKey: input.PublicKey, Nodes: input.Nodes, Status: map[string]deviceNodeState{}, State: "partial", Created: time.Now().UTC(), Updated: time.Now().UTC()}
	if d.Protocol == "ks" {
		d.PublicKey = ""
	}
	devicesState.rows = append(devicesState.rows, d)
	index := len(devicesState.rows) - 1
	if err := applyDeviceLocked(r.Context(), index, requestActor(r)); err != nil {
		http.Error(w, redactLog(err.Error())+". Запись сохранена, проверьте список устройств.", 500)
		return
	}
	w.WriteHeader(http.StatusCreated)
	writeJSON(w, devicesState.rows[index])
}

func handleDeviceAction(w http.ResponseWriter, r *http.Request) {
	if !requireMutation(w, r) {
		return
	}
	parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/api/devices/"), "/")
	if len(parts) != 2 || parts[1] != "action" || !validID(parts[0]) {
		http.NotFound(w, r)
		return
	}
	var input struct {
		Action string `json:"action"`
	}
	r.Body = http.MaxBytesReader(w, r.Body, 1024)
	if decodeStrictJSON(r.Body, &input) != nil {
		http.Error(w, "Некорректный запрос", 400)
		return
	}
	if input.Action == "revoke" {
		if err := markActivationManualRevoke(parts[0]); err != nil {
			http.Error(w, "Activation registry unavailable", 503)
			return
		}
	}
	devicesState.Lock()
	defer devicesState.Unlock()
	index := deviceIndex(parts[0])
	if index < 0 {
		http.NotFound(w, r)
		return
	}
	d := &devicesState.rows[index]
	if input.Action == "profile" {
		if d.Revoked || d.State != "active" {
			http.Error(w, "Профиль доступен после подтверждения всех нод", 409)
			return
		}
		profile, err := buildDeviceProfile(r.Context(), *d)
		if err != nil {
			http.Error(w, redactLog(err.Error()), 502)
			return
		}
		if err := audit(requestActor(r), "", "profile.download", d.ID, "ok"); err != nil {
			http.Error(w, "Аудит недоступен", 503)
			return
		}
		w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="chameleon-%s.json"`, d.ID))
		writeJSON(w, profile)
		return
	}
	if input.Action != "revoke" && input.Action != "retry" {
		http.Error(w, "Неизвестное действие", 400)
		return
	}
	if input.Action == "revoke" {
		d.Revoked = true
	}
	if err := applyDeviceLocked(r.Context(), index, requestActor(r)); err != nil {
		http.Error(w, redactLog(err.Error()), 500)
		return
	}
	writeJSON(w, devicesState.rows[index])
}

type connectionProfile struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	Mode      string `json:"mode"`
	Addr      string `json:"addr"`
	PubKey    string `json:"pubkey,omitempty"`
	Subtitle  string `json:"subtitle,omitempty"`
	KSKey     string `json:"ks_key,omitempty"`
	Inner     string `json:"inner,omitempty"`
	PeerInner string `json:"peer_inner,omitempty"`
}

func buildDeviceProfile(ctx context.Context, d managedDevice) (any, error) {
	profiles := make([]connectionProfile, 0, len(d.Nodes))
	for _, id := range d.Nodes {
		n, ok := findNode(id)
		if !ok {
			return nil, errors.New("нода не найдена")
		}
		p := connectionProfile{ID: d.ID + "-" + id, Name: n.Name, Mode: d.Protocol, Addr: n.Address, PubKey: n.PublicKey, Subtitle: n.Role}
		if d.Protocol == "ks" {
			response, err := nodeApply(ctx, n, nodeRequest{Action: "ks-profile", Device: d.ID})
			if err != nil {
				return nil, err
			}
			p.Addr = n.KSAddress
			p.PubKey = ""
			p.KSKey = response.MasterKey
			p.Inner = fmt.Sprintf("10.99.9.%d", response.Slot)
			p.PeerInner = "10.99.9.2"
		}
		profiles = append(profiles, p)
	}
	return map[string]any{"kind": "chameleon-device-profile", "version": 2, "device_id": d.ID, "device_name": d.Name, "client_public_key": d.PublicKey, "resolution_auth_version": 2, "servers": profiles}, nil
}
