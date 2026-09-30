//go:build linux

package main

import (
	"chameleon/internal/hostmetrics"
	"sync"
)

type hostResources = hostmetrics.Snapshot

func readHostResources() (*hostResources, error) { return hostmetrics.Read() }

var resourceSamples = struct {
	sync.Mutex
	previous map[string]hostResources
}{previous: map[string]hostResources{}}

func sampleCPU(id string, r *hostResources) {
	if r == nil {
		return
	}
	resourceSamples.Lock()
	defer resourceSamples.Unlock()
	previous, ok := resourceSamples.previous[id]
	if ok && r.CPUTotal > previous.CPUTotal && r.CPUIdle >= previous.CPUIdle {
		total, idle := r.CPUTotal-previous.CPUTotal, r.CPUIdle-previous.CPUIdle
		if idle <= total {
			p := 100 * (1 - float64(idle)/float64(total))
			r.CPUPercent = &p
		}
	}
	resourceSamples.previous[id] = *r
}
