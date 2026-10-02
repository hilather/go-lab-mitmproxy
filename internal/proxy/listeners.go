package proxy

import (
	"fmt"
	"net"

	"github.com/hilather/go-lab-mitmproxy/internal/model"
)

// PrepareListeners reserves changed Reset-only binds without accepting sessions.
// The caller serializes Reset and calls Commit only after publishing the snapshot.
func (s *Server) PrepareListeners(spec model.Spec, address string) (commit func(), rollback func(), err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.started || s.stopped {
		return nil, nil, fmt.Errorf("proxy: listener reconciliation requires a running server")
	}
	if address == "" {
		address = spec.Listeners.Proxy.Address
	}
	oldRaw, oldOrig := s.rawLn, s.origLn
	var raw, orig net.Listener
	changeRaw := address != s.addr
	if changeRaw {
		raw, err = net.Listen("tcp", address)
		if err != nil {
			return nil, nil, fmt.Errorf("proxy: listen: %w", err)
		}
	}
	odAddress := spec.Listeners.OriginalDestination.Address
	if s.origDestBind != "" {
		odAddress = s.origDestBind
	}
	if odAddress == "" {
		odAddress = "127.0.0.1:8890"
	}
	changeOrig := spec.Listeners.OriginalDestination.Enabled != (oldOrig != nil)
	if oldOrig != nil && spec.Listeners.OriginalDestination.Enabled {
		changeOrig = odAddress != s.origListenAddress
	}
	if changeOrig && spec.Listeners.OriginalDestination.Enabled {
		if !origDestSupported {
			_ = closeQuiet(raw)
			return nil, nil, fmt.Errorf("proxy: originalDestination requires linux (REDIRECT + SO_ORIGINAL_DST)")
		}
		orig, err = net.Listen("tcp", odAddress)
		if err != nil {
			_ = closeQuiet(raw)
			return nil, nil, fmt.Errorf("proxy: originalDestination listen: %w", err)
		}
	}
	committed := false
	rollback = func() {
		if !committed {
			_ = closeQuiet(raw)
			_ = closeQuiet(orig)
		}
	}
	commit = func() {
		s.mu.Lock()
		if changeRaw {
			s.rawLn = raw
			s.addr = address
			s.acceptWG.Add(1)
		}
		if changeOrig {
			s.origLn = orig
			s.origListenAddress = odAddress
			if orig != nil {
				s.acceptWG.Add(1)
			}
		}
		committed = true
		s.mu.Unlock()
		if changeRaw {
			_ = oldRaw.Close()
			go s.acceptLoop(raw, kindProxy)
		}
		if changeOrig {
			_ = closeQuiet(oldOrig)
			if orig != nil {
				go s.acceptLoop(orig, kindOrigDest)
			}
		}
	}
	return commit, rollback, nil
}
