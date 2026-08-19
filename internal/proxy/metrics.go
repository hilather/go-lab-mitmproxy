package proxy

import (
	"sync"

	"github.com/hilather/go-lab-mitmproxy/internal/model"
	"github.com/hilather/go-lab-mitmproxy/internal/observability"
)

// Metrics is a process-local reject/session counter that dual-writes
// to the OpenMetrics registry when attached.
type Metrics struct {
	mu        sync.Mutex
	rejected  map[string]int64
	sessions  map[string]int64
	tls       map[string]int64
	rules     map[string]int64
	storeFull int64
	reg       *observability.Registry
	log       *observability.Logger
}

func (m *Metrics) attach(reg *observability.Registry, log *observability.Logger) {
	if m == nil {
		return
	}
	m.mu.Lock()
	m.reg = reg
	m.log = log
	m.mu.Unlock()
}

func newMetrics() *Metrics {
	return &Metrics{
		rejected: make(map[string]int64),
		sessions: make(map[string]int64),
		tls:      make(map[string]int64),
		rules:    make(map[string]int64),
	}
}

func (m *Metrics) reject(reason string) {
	if m == nil {
		return
	}
	reason = observability.ProxyRejectReason(reason)
	m.mu.Lock()
	m.rejected[reason]++
	reg, log := m.reg, m.log
	m.mu.Unlock()
	if reg != nil {
		reg.Inc(observability.MetricProxyRejectedTotal, map[string]string{"reason": reason}, 1)
	}
	if log != nil {
		log.Log(observability.Record{Event: observability.EventProxyRejected, Component: "proxy", Result: reason})
	}
}

func (m *Metrics) accept() {
	if m == nil {
		return
	}
	m.mu.Lock()
	log := m.log
	m.mu.Unlock()
	if log != nil {
		log.Log(observability.Record{Event: observability.EventProxyAccepted, Component: "proxy", Result: "ok"})
	}
}

func (m *Metrics) session(result string) {
	if m == nil {
		return
	}
	result = observability.ProxySessionResult(result)
	m.mu.Lock()
	m.sessions[result]++
	reg, log := m.reg, m.log
	m.mu.Unlock()
	if reg != nil {
		reg.Inc(observability.MetricProxySessionsTotal, map[string]string{"result": result}, 1)
	}
	if log != nil {
		log.Log(observability.Record{Event: observability.EventProxySessionEnd, Component: "proxy", Result: result})
	}
}

func (m *Metrics) tlsIntercept(result string) {
	if m == nil {
		return
	}
	result = observability.TLSInterceptResult(result)
	m.mu.Lock()
	m.tls[result]++
	reg, log := m.reg, m.log
	m.mu.Unlock()
	if reg != nil {
		reg.Inc(observability.MetricTLSInterceptsTotal, map[string]string{"result": result}, 1)
	}
	if log != nil {
		log.Log(observability.Record{Event: observability.EventTLSIntercept, Component: "tlsmitm", Result: result})
	}
}

func (m *Metrics) storeFullInc() {
	if m == nil {
		return
	}
	m.mu.Lock()
	m.storeFull++
	m.mu.Unlock()
	// Registry increment lives in store.Insert on ErrFull so the series is
	// counted once even when the proxy still forwards.
}

func (m *Metrics) ruleHit(action string) {
	if m == nil || action == "" {
		return
	}
	m.mu.Lock()
	m.rules[action]++
	reg, log := m.reg, m.log
	m.mu.Unlock()
	if reg != nil {
		reg.Inc(observability.MetricRuleHitsTotal, map[string]string{"action": action}, 1)
	}
	if log != nil {
		log.Log(observability.Record{Event: observability.EventRuleHit, Component: "rules", Result: action})
	}
}

func (m *Metrics) flow(f *model.Flow) {
	if m == nil || f == nil {
		return
	}
	m.mu.Lock()
	reg := m.reg
	m.mu.Unlock()
	if reg == nil {
		return
	}
	result := "ok"
	if f.Error != "" {
		result = "error"
	}
	reg.Inc(observability.MetricFlowsTotal, map[string]string{
		"scheme":      observability.FlowScheme(f.Scheme),
		"intercepted": observability.InterceptedLabel(f.Intercepted),
		"result":      observability.FlowResult(result),
	}, 1)
}

// RuleHits is labmitm_rule_hits_total{action}.
func (m *Metrics) RuleHits(action string) int64 {
	if m == nil {
		return 0
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.rules[action]
}

// StoreFull is labmitm_store_full_total (capture rejected; proxy still forwarded).
func (m *Metrics) StoreFull() int64 {
	if m == nil {
		return 0
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.storeFull
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
