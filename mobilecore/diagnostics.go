package mobilecore

import (
	"encoding/json"
	"os"
	"regexp"
)

var mobileSecretPattern = regexp.MustCompile(`\b[A-Za-z0-9_+/-]{43,}={0,2}`)

func redactMobileLog(value string) string {
	return mobileSecretPattern.ReplaceAllString(value, "[REDACTED]")
}

func ClearLogs() {
	logMu.Lock()
	defer logMu.Unlock()
	lastLog = nil
	if logPath != "" {
		_ = os.WriteFile(logPath, nil, 0600)
		_ = os.Remove(logPath + ".1")
	}
}

func DiagnosticsJSON() string {
	mu.Lock()
	active, m := running, mx
	mu.Unlock()
	data := map[string]any{"release": "4.0.0", "mode": Mode(), "running": active, "up_bytes": UpBytes(), "down_bytes": DownBytes()}
	if Mode() == "ks" {
		data["last_valid_rx_age_sec"] = LastRxSec()
	}
	if m != nil {
		sent, received := m.PayloadStats()
		data["session_alive"] = m.Alive()
		data["payload_sent"] = sent
		data["payload_received"] = received
		data["rtt_ms"] = m.RTT().Milliseconds()
		data["udp_objects"] = m.Conn().DatagramStats()
		data["dns_auth_version"] = 2
	}
	b, err := json.Marshal(data)
	if err != nil {
		return "{}"
	}
	return string(b)
}
