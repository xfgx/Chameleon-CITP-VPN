//go:build linux

package hostmetrics

import (
	"bufio"
	"fmt"
	"os"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"
)

type Network struct {
	Name      string `json:"name"`
	RX        uint64 `json:"rx_bytes"`
	TX        uint64 `json:"tx_bytes"`
	RXDropped uint64 `json:"rx_dropped"`
	TXDropped uint64 `json:"tx_dropped"`
}
type Snapshot struct {
	At              time.Time `json:"at"`
	CPUCount        int       `json:"cpu_count"`
	CPUTotal        uint64    `json:"cpu_total"`
	CPUIdle         uint64    `json:"cpu_idle"`
	CPUPercent      *float64  `json:"cpu_percent,omitempty"`
	Load1           float64   `json:"load_1"`
	Load5           float64   `json:"load_5"`
	MemoryTotal     uint64    `json:"memory_total"`
	MemoryAvailable uint64    `json:"memory_available"`
	SwapTotal       uint64    `json:"swap_total"`
	SwapFree        uint64    `json:"swap_free"`
	DiskTotal       uint64    `json:"disk_total"`
	DiskFree        uint64    `json:"disk_free"`
	UptimeSec       float64   `json:"uptime_seconds"`
	Network         []Network `json:"network"`
	Warnings        []string  `json:"warnings"`
}

func Read() (*Snapshot, error) {
	r := &Snapshot{At: time.Now().UTC(), CPUCount: runtime.NumCPU(), Network: []Network{}, Warnings: []string{}}
	b, e := os.ReadFile("/proc/stat")
	if e != nil {
		return nil, e
	}
	line := strings.Fields(strings.SplitN(string(b), "\n", 2)[0])
	if len(line) < 5 || line[0] != "cpu" {
		return nil, fmt.Errorf("CPU metrics unavailable")
	}
	for i, s := range line[1:] {
		v, _ := strconv.ParseUint(s, 10, 64)
		if i < 8 {
			r.CPUTotal += v
		}
		if i == 3 || i == 4 {
			r.CPUIdle += v
		}
	}
	b, e = os.ReadFile("/proc/meminfo")
	if e != nil {
		return nil, e
	}
	scanner := bufio.NewScanner(strings.NewReader(string(b)))
	for scanner.Scan() {
		v := strings.Fields(scanner.Text())
		if len(v) < 2 {
			continue
		}
		n, _ := strconv.ParseUint(v[1], 10, 64)
		n *= 1024
		switch v[0] {
		case "MemTotal:":
			r.MemoryTotal = n
		case "MemAvailable:":
			r.MemoryAvailable = n
		case "SwapTotal:":
			r.SwapTotal = n
		case "SwapFree:":
			r.SwapFree = n
		}
	}
	if b, e = os.ReadFile("/proc/loadavg"); e == nil {
		v := strings.Fields(string(b))
		if len(v) >= 2 {
			r.Load1, _ = strconv.ParseFloat(v[0], 64)
			r.Load5, _ = strconv.ParseFloat(v[1], 64)
		}
	}
	if b, e = os.ReadFile("/proc/uptime"); e == nil {
		v := strings.Fields(string(b))
		if len(v) > 0 {
			r.UptimeSec, _ = strconv.ParseFloat(v[0], 64)
		}
	}
	var st syscall.Statfs_t
	if e = syscall.Statfs("/", &st); e == nil {
		r.DiskTotal = st.Blocks * uint64(st.Bsize)
		r.DiskFree = st.Bavail * uint64(st.Bsize)
	}
	entries, _ := os.ReadDir("/sys/class/net")
	for _, v := range entries {
		if v.Name() == "lo" {
			continue
		}
		read := func(name string) uint64 {
			b, e := os.ReadFile("/sys/class/net/" + v.Name() + "/statistics/" + name)
			if e != nil {
				return 0
			}
			n, _ := strconv.ParseUint(strings.TrimSpace(string(b)), 10, 64)
			return n
		}
		r.Network = append(r.Network, Network{Name: v.Name(), RX: read("rx_bytes"), TX: read("tx_bytes"), RXDropped: read("rx_dropped"), TXDropped: read("tx_dropped")})
		if len(r.Network) >= 32 {
			break
		}
	}
	if r.DiskTotal > 0 && float64(r.DiskFree)/float64(r.DiskTotal) < 0.1 {
		r.Warnings = append(r.Warnings, "disk free below 10%; this is not DPI evidence")
	}
	if r.MemoryTotal > 0 && float64(r.MemoryAvailable)/float64(r.MemoryTotal) < 0.1 {
		r.Warnings = append(r.Warnings, "available memory below 10%")
	}
	if r.Load1 > float64(r.CPUCount)*2 {
		r.Warnings = append(r.Warnings, "load exceeds twice logical CPU count")
	}
	return r, nil
}
