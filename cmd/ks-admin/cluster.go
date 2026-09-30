//go:build linux

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

var fCluster = flag.String("cluster", "/etc/chameleon/console-nodes.json", "конфигурация управляемых нод")
var fReleases = flag.String("releases", "/var/lib/ks-admin/releases", "проверенные клиентские пакеты")
var fNodeOp = flag.Bool("node-op", false, "ограниченный агент: один JSON-запрос на stdin")
var fNodeConfig = flag.String("node-config", "/etc/chameleon/node-agent.json", "политика ограниченного агента")

type nodeConfig struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Role        string `json:"role"`
	Address     string `json:"address"`
	PublicKey   string `json:"public_key"`
	KSAddress   string `json:"ks_address,omitempty"`
	SupportsKS  bool   `json:"supports_ks"`
	LocalConfig string `json:"local_config,omitempty"`
	SSHHost     string `json:"ssh_host,omitempty"`
	SSHKey      string `json:"ssh_key,omitempty"`
	KnownHosts  string `json:"known_hosts,omitempty"`
}

type nodeView struct {
	ID           string         `json:"id"`
	Resources    *hostResources `json:"resources,omitempty"`
	Name         string         `json:"name"`
	Role         string         `json:"role"`
	Address      string         `json:"address"`
	SupportsKS   bool           `json:"supports_ks"`
	Active       bool           `json:"active"`
	AllowedCount int            `json:"allowed_count"`
	Updated      time.Time      `json:"updated"`
	Error        string         `json:"error,omitempty"`
	Version      string         `json:"version,omitempty"`
}

var clusterState = struct {
	sync.RWMutex
	nodes []nodeConfig
	views []nodeView
}{}

func loadCluster(path string) error {
	var nodes []nodeConfig
	if err := readStrictJSON(path, &nodes, 1<<20); err != nil {
		return err
	}
	if len(nodes) == 0 || len(nodes) > 8 {
		return errors.New("ожидается от 1 до 8 нод")
	}
	seen := map[string]bool{}
	for _, n := range nodes {
		if !validID(n.ID) || seen[n.ID] || n.Name == "" || n.Address == "" || !validPublicKey(n.PublicKey) {
			return errors.New("некорректная конфигурация нод")
		}
		seen[n.ID] = true
		if n.LocalConfig == "" && (n.SSHHost == "" || n.SSHKey == "" || n.KnownHosts == "") {
			return errors.New("для удалённой ноды требуется закреплённый SSH-доступ")
		}
	}
	clusterState.Lock()
	clusterState.nodes = nodes
	clusterState.Unlock()
	return nil
}

func findNode(id string) (nodeConfig, bool) {
	clusterState.RLock()
	defer clusterState.RUnlock()
	for _, n := range clusterState.nodes {
		if n.ID == id {
			return n, true
		}
	}
	return nodeConfig{}, false
}
func clusterSnapshot() []nodeView {
	clusterState.RLock()
	defer clusterState.RUnlock()
	return append([]nodeView{}, clusterState.views...)
}
func pollCluster() {
	clusterState.RLock()
	nodes := append([]nodeConfig{}, clusterState.nodes...)
	clusterState.RUnlock()
	views := make([]nodeView, len(nodes))
	var wg sync.WaitGroup
	for i, n := range nodes {
		wg.Add(1)
		go func(i int, n nodeConfig) {
			defer wg.Done()
			v := nodeView{ID: n.ID, Name: n.Name, Role: n.Role, Address: n.Address, SupportsKS: n.SupportsKS, Updated: time.Now().UTC()}
			response, err := callNode(context.Background(), n, nodeRequest{Action: "status"})
			if err != nil {
				v.Error = redactLog(err.Error())
			} else {
				v.Active = response.Active
				v.AllowedCount = response.AllowedCount
				v.Version = response.Version
				v.Resources = response.Resources
				sampleCPU(n.ID, v.Resources)
			}
			views[i] = v
		}(i, n)
	}
	wg.Wait()
	clusterState.Lock()
	clusterState.views = views
	clusterState.Unlock()
}

type boundedOutput struct {
	bytes.Buffer
	limit int
}

func (b *boundedOutput) Write(p []byte) (int, error) {
	if len(p) > b.limit-b.Len() {
		return 0, errors.New("command output limit exceeded")
	}
	return b.Buffer.Write(p)
}
func commandOutput(ctx context.Context, input []byte, name string, args ...string) ([]byte, error) {
	c := exec.CommandContext(ctx, name, args...)
	out := &boundedOutput{limit: 2 << 20}
	errOut := &boundedOutput{limit: 8192}
	c.Stdin = bytes.NewReader(input)
	c.Stdout = out
	c.Stderr = errOut
	err := c.Run()
	if err != nil {
		return out.Bytes(), fmt.Errorf("%s: %w %s", name, err, redactLog(errOut.String()))
	}
	return out.Bytes(), nil
}

func callNode(parent context.Context, n nodeConfig, request nodeRequest) (nodeResponse, error) {
	ctx, cancel := context.WithTimeout(parent, 12*time.Second)
	defer cancel()
	if n.LocalConfig != "" {
		var policy nodePolicy
		if err := readStrictJSON(n.LocalConfig, &policy, 65536); err != nil {
			return nodeResponse{}, err
		}
		return executeNode(ctx, policy, request)
	}
	payload, _ := json.Marshal(request)
	out, err := commandOutput(ctx, payload, "ssh", "-T", "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=yes", "-o", "IdentitiesOnly=yes", "-o", "ConnectTimeout=5", "-o", "ServerAliveInterval=3", "-o", "ServerAliveCountMax=2", "-o", "UserKnownHostsFile="+n.KnownHosts, "-i", n.SSHKey, n.SSHHost, "/usr/local/bin/vpn-node-agent")
	if err != nil {
		return nodeResponse{}, err
	}
	var response nodeResponse
	if err := json.Unmarshal(out, &response); err != nil {
		return response, errors.New("некорректный ответ агента ноды")
	}
	if response.Error != "" {
		return response, errors.New(response.Error)
	}
	return response, nil
}

func readStrictJSON(path string, v any, limit int64) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	return decodeStrictJSON(io.LimitReader(f, limit+1), v)
}
func decodeStrictJSON(reader io.Reader, v any) error {
	d := json.NewDecoder(reader)
	d.DisallowUnknownFields()
	if err := d.Decode(v); err != nil {
		return err
	}
	var trailing any
	if err := d.Decode(&trailing); err != io.EOF {
		return errors.New("лишние данные JSON")
	}
	return nil
}
func boundedInt(s string, def, low, high int) int {
	n, err := strconv.Atoi(s)
	if err != nil {
		return def
	}
	return max(low, min(high, n))
}
func atomicPrivateFile(path string, body []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(path), ".console-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer os.Remove(tmp)
	if err = f.Chmod(0600); err == nil {
		_, err = f.Write(body)
	}
	if err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	if err = os.Rename(tmp, path); err != nil {
		return err
	}
	dir, err := os.Open(filepath.Dir(path))
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}
func validID(s string) bool {
	if s == "" || len(s) > 48 {
		return false
	}
	for _, c := range s {
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
			return false
		}
	}
	return true
}
func safeSingleLine(s string) bool { return !strings.ContainsAny(s, "\x00\r\n") }
