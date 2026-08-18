package proxy

import "sync"

// Metrics is a process-local reject/session counter until OBS-001.
type Metrics struct {
	mu       sync.Mutex
	rejected map[string]int64
	sessions map[string]int64
	tls      map[string]int64
}

func newMetrics() *Metrics {
	return &Metrics{
		rejected: make(map[string]int64),
		sessions: make(map[string]int64),
		tls:      make(map[string]int64),
	}
}

func (m *Metrics) reject(reason string) {
	if m == nil {
		return
	}
	m.mu.Lock()
	m.rejected[reason]++
	m.mu.Unlock()
}

func (m *Metrics) session(result string) {
	if m == nil {
		return
	}
	m.mu.Lock()
	m.sessions[result]++
	m.mu.Unlock()
}

func (m *Metrics) tlsIntercept(result string) {
	if m == nil {
		return
	}
	m.mu.Lock()
	m.tls[result]++
	m.mu.Unlock()
}

// Rejected returns the count for reason (admission, http2, socks,
// target_denied, absolute_https).
func (m *Metrics) Rejected(reason string) int64 {
	if m == nil {
		return 0
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.rejected[reason]
}

// TLSIntercepts returns labmitm_tls_intercepts_total{result}.
func (m *Metrics) TLSIntercepts(result string) int64 {
	if m == nil {
		return 0
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.tls[result]
}
