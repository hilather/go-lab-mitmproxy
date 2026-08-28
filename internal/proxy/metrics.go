package proxy

import (
	"sync"

	"github.com/hilather/go-lab-mitmproxy/internal/model"
	"github.com/hilather/go-lab-mitmproxy/internal/observability"
)

// Metrics is a process-local reject/session counter that dual-writes
// to the OpenMetrics registry when attached.
type Metrics struct {
	mu                sync.Mutex
	rejected          map[string]int64
	sessions          map[string]int64
	tls               map[string]int64
	rules             map[string]int64
	socksN            map[string]int64
	wsN               map[string]int64
	grpcN             map[string]int64
	storeFull         int64
	h2TrailersDropped int64
	accepted          int64
	h2Push            map[string]int64
	reg               *observability.Registry
	log               *observability.Logger
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
		socksN:   make(map[string]int64),
		wsN:      make(map[string]int64),
		grpcN:    make(map[string]int64),
		h2Push:   make(map[string]int64),
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
	m.accepted++
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

func (m *Metrics) socks(result string) {
	if m == nil {
		return
	}
	result = observability.SocksSessionResult(result)
	m.mu.Lock()
	m.socksN[result]++
	reg := m.reg
	m.mu.Unlock()
	if reg != nil {
		reg.Inc(observability.MetricSocksSessionsTotal, map[string]string{"result": result}, 1)
	}
}

func (m *Metrics) wsFrame(opcode string) {
	if m == nil {
		return
	}
	opcode = observability.WSOpcodeLabel(opcode)
	m.mu.Lock()
	if m.wsN == nil {
		m.wsN = make(map[string]int64)
	}
	m.wsN[opcode]++
	reg := m.reg
	m.mu.Unlock()
	if reg != nil {
		reg.Inc(observability.MetricWSFramesTotal, map[string]string{"opcode": opcode}, 1)
	}
}

func (m *Metrics) grpcDecode(result string) {
	if m == nil {
		return
	}
	result = observability.GRPCDecodeResult(result)
	m.mu.Lock()
	if m.grpcN == nil {
		m.grpcN = make(map[string]int64)
	}
	m.grpcN[result]++
	reg := m.reg
	m.mu.Unlock()
	if reg != nil {
		reg.Inc(observability.MetricGRPCDecodeTotal, map[string]string{"result": result}, 1)
	}
}

func (m *Metrics) h2PushCaptured(result string) {
	if m == nil {
		return
	}
	result = observability.H2PushCapturedResult(result)
	m.mu.Lock()
	if m.h2Push == nil {
		m.h2Push = make(map[string]int64)
	}
	m.h2Push[result]++
	reg := m.reg
	m.mu.Unlock()
	if reg != nil {
		reg.Inc(observability.MetricH2PushCapturedTotal, map[string]string{"result": result}, 1)
	}
}

func (m *Metrics) h2TrailerDropped() {
	if m == nil {
		return
	}
	m.mu.Lock()
	m.h2TrailersDropped++
	reg := m.reg
	m.mu.Unlock()
	if reg != nil {
		reg.Inc(observability.MetricH2TrailerDroppedTotal, nil, 1)
	}
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

// Accepted is the number of times accept() ran (admission passed).
func (m *Metrics) Accepted() int64 {
	if m == nil {
		return 0
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.accepted
}

// Rejected returns the count for reason (admission, http2, socks,
// socks_auth, socks_command, target_denied, absolute_https, websocket,
// connect, absolute_form).
func (m *Metrics) Rejected(reason string) int64 {
	if m == nil {
		return 0
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.rejected[reason]
}

// Socks returns labmitm_socks_sessions_total{result}.
func (m *Metrics) Socks(result string) int64 {
	if m == nil {
		return 0
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.socksN[result]
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

// WSFrames is labmitm_ws_frames_total{opcode}.
func (m *Metrics) WSFrames(opcode string) int64 {
	if m == nil {
		return 0
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.wsN[observability.WSOpcodeLabel(opcode)]
}

// GRPCDecode is labmitm_grpc_decode_total{result}.
func (m *Metrics) GRPCDecode(result string) int64 {
	if m == nil {
		return 0
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.grpcN[observability.GRPCDecodeResult(result)]
}

// H2PushCaptured is labmitm_h2_push_captured_total{result}.
func (m *Metrics) H2PushCaptured(result string) int64 {
	if m == nil {
		return 0
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.h2Push[observability.H2PushCapturedResult(result)]
}

// H2TrailerDropped is labmitm_h2_trailer_dropped_total.
func (m *Metrics) H2TrailerDropped() int64 {
	if m == nil {
		return 0
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.h2TrailersDropped
}
