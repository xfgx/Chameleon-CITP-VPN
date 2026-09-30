package chameleon

import (
	"bytes"
	"errors"
	"fmt"
	"time"
)

const (
	smCapabilities    = 0x10
	smCapabilitiesOK  = 0x11
	smCapabilitiesErr = 0x12
)

var protocolCapabilities = []byte{1, ResolutionAuthVersion, 1}
var ErrProtocolUpgrade = errors.New("protocol upgrade required: DNS auth v2 and semantic UDP v1 must match on client and every node")

// Capabilities are exchanged only inside the authenticated encrypted session.
// A timeout or unknown version never enables the legacy unbound DNS path.
func (m *Mux) RequireCapabilities() error {
	if m.protocolReady.Load() {
		return nil
	}
	m.protocolMu.Lock()
	defer m.protocolMu.Unlock()
	if m.protocolReady.Load() {
		return nil
	}
	if !m.Alive() {
		return m.Err()
	}
	m.mu.Lock()
	sid := m.nextID
	m.nextID++
	m.mu.Unlock()
	s := &Stream{m: m, id: sid, inCh: make(chan []byte, streamQueueDepth), openDone: make(chan error, 1), capabilitiesProbe:true}
	if err := m.putStream(s); err != nil {
		return err
	}
	defer m.remove(sid)
	if err := m.send(sid, smCapabilities, protocolCapabilities); err != nil {
		return err
	}
	timer := time.NewTimer(3 * time.Second)
	defer timer.Stop()
	select {
	case err := <-s.openDone:
		if err != nil {
			return fmt.Errorf("%w: %v", ErrProtocolUpgrade, err)
		}
	case <-timer.C:
		return ErrProtocolUpgrade
	}
	select {
	case reply, ok := <-s.inCh:
		if !ok || !bytes.Equal(reply, protocolCapabilities) {
			return ErrProtocolUpgrade
		}
	case <-timer.C:
		return ErrProtocolUpgrade
	}
	m.protocolReady.Store(true)
	return nil
}
