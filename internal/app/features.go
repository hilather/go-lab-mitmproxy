package app

import (
	"context"

	"github.com/hilather/go-lab-mitmproxy/internal/model"
	"github.com/hilather/go-lab-mitmproxy/internal/snapshot"
)

const (
	FeatureApplyLive  = "live"
	FeatureApplyReset = "reset"

	FeatureVerbSetFeature = "setFeature"
	FeatureVerbReplaceTLS = "replaceTLS"
	FeatureVerbReset      = "reset"

	FeatureIDHTTP2          = "protocols.http2"
	FeatureIDWebSocket      = "protocols.websocket"
	FeatureIDConnect        = "protocols.connect"
	FeatureIDAbsoluteForm   = "protocols.absoluteForm"
	FeatureIDAcceptSOCKS5   = "listeners.proxy.acceptSOCKS5"
	FeatureIDAcceptSOCKS4   = "listeners.proxy.acceptSOCKS4"
	FeatureIDOriginalDest   = "listeners.originalDestination"
	FeatureIDCompatFlowREST = "compat.flowREST"
	FeatureIDTLSIntercept   = "tls.intercept"
	FeatureIDRulesEnabled   = "rules.enabled"
	FeatureIDUIEnabled      = "ui.enabled"
)

// Feature is one derived hop/protocol gate. IDs and Verb tokens are frozen.
type Feature struct {
	ID          string
	YAMLPath    string
	Title       string
	Description string
	Enabled     bool
	ApplyMode   string
	Verb        string
}

// FeatureList is the catalog plus the snapshot revision it was derived from.
type FeatureList struct {
	RuntimeRevision model.Revision
	Generation      model.Generation
	Drifted         bool
	Items           []Feature
}

// CatalogFromSpec projects hop/protocol gates from an already-decoded spec.
// It does not default bools; callers that need omitted-field defaults must Load first.
func CatalogFromSpec(spec model.Spec) []Feature {
	return []Feature{
		{
			ID:          FeatureIDHTTP2,
			YAMLPath:    "spec.protocols.http2.enabled",
			Title:       "Inner HTTP/2",
			Description: "Inner+origin ALPN h2 on intercepted CONNECT. Off keeps HTTP/1.1; client-facing PRI stays a hard close.",
			Enabled:     spec.Protocols.HTTP2.Enabled,
			ApplyMode:   FeatureApplyLive,
			Verb:        FeatureVerbSetFeature,
		},
		{
			ID:          FeatureIDWebSocket,
			YAMLPath:    "spec.protocols.websocket.enabled",
			Title:       "WebSocket upgrade",
			Description: "HTTP/1.1 Upgrade: websocket on cleartext and intercepted inner HTTP/1.1. Off refuses the upgrade. setFeature is validation_failed until hop 403 lands.",
			Enabled:     spec.Protocols.WebSocket.Enabled,
			ApplyMode:   FeatureApplyLive,
			Verb:        FeatureVerbSetFeature,
		},
		{
			ID:          FeatureIDConnect,
			YAMLPath:    "spec.protocols.connect.enabled",
			Title:       "HTTP CONNECT",
			Description: "Forward-proxy HTTP CONNECT. SOCKS CONNECT is a different ID. Orig-dest tagged CONNECT stays 400. setFeature is validation_failed until hop 403 lands.",
			Enabled:     spec.Protocols.Connect.Enabled,
			ApplyMode:   FeatureApplyLive,
			Verb:        FeatureVerbSetFeature,
		},
		{
			ID:          FeatureIDAbsoluteForm,
			YAMLPath:    "spec.protocols.absoluteForm.enabled",
			Title:       "Absolute-form HTTP",
			Description: "Absolute-form http:// requests on the proxy listener. Orig-dest origin-form is not this flag. Absolute https:// stays 400. setFeature is validation_failed until hop 403 lands.",
			Enabled:     spec.Protocols.AbsoluteForm.Enabled,
			ApplyMode:   FeatureApplyLive,
			Verb:        FeatureVerbSetFeature,
		},
		{
			ID:          FeatureIDAcceptSOCKS5,
			YAMLPath:    "spec.listeners.proxy.acceptSOCKS5",
			Title:       "SOCKS5 accept",
			Description: "SOCKS5 CONNECT on the proxy listener (NO AUTH). Decided on the next peeked connection.",
			Enabled:     spec.Listeners.Proxy.AcceptSOCKS5,
			ApplyMode:   FeatureApplyLive,
			Verb:        FeatureVerbSetFeature,
		},
		{
			ID:          FeatureIDAcceptSOCKS4,
			YAMLPath:    "spec.listeners.proxy.acceptSOCKS4",
			Title:       "SOCKS4 accept",
			Description: "SOCKS4 CONNECT on the proxy listener. Decided on the next peeked connection.",
			Enabled:     spec.Listeners.Proxy.AcceptSOCKS4,
			ApplyMode:   FeatureApplyLive,
			Verb:        FeatureVerbSetFeature,
		},
		{
			ID:          FeatureIDOriginalDest,
			YAMLPath:    "spec.listeners.originalDestination.enabled",
			Title:       "Original-destination REDIRECT",
			Description: "Linux SO_ORIGINAL_DST listener. Changing this requires Reset (bind).",
			Enabled:     spec.Listeners.OriginalDestination.Enabled,
			ApplyMode:   FeatureApplyReset,
			Verb:        FeatureVerbReset,
		},
		{
			ID:          FeatureIDCompatFlowREST,
			YAMLPath:    "spec.compat.flowREST.enabled",
			Title:       "Compat flow REST",
			Description: "Optional first-party /compat flow REST adapter. Enabled is live-read. Path prefix is not this boolean.",
			Enabled:     spec.Compat.FlowREST.Enabled,
			ApplyMode:   FeatureApplyLive,
			Verb:        FeatureVerbSetFeature,
		},
		{
			ID:          FeatureIDTLSIntercept,
			YAMLPath:    "spec.tls.intercept",
			Title:       "TLS intercept",
			Description: "MITM intercept for matched hosts/ports. Change via replaceTLS; generate-mode CA rotates when the TLS spec changes.",
			Enabled:     spec.TLS.Intercept,
			ApplyMode:   FeatureApplyLive,
			Verb:        FeatureVerbReplaceTLS,
		},
		{
			ID:          FeatureIDRulesEnabled,
			YAMLPath:    "spec.rules.enabled",
			Title:       "Rules engine",
			Description: "Master switch for spec.rules. Items are unchanged. Next request/CONNECT pins the engine pointer.",
			Enabled:     spec.Rules.Enabled,
			ApplyMode:   FeatureApplyLive,
			Verb:        FeatureVerbSetFeature,
		},
		{
			ID:          FeatureIDUIEnabled,
			YAMLPath:    "spec.ui.enabled",
			Title:       "Embedded inspector UI",
			Description: "Serves the flow-inspector SPA. REST and MCP stay up when disabled.",
			Enabled:     spec.UI.Enabled,
			ApplyMode:   FeatureApplyLive,
			Verb:        FeatureVerbSetFeature,
		},
	}
}

// CompactStatusFlags projects compact status.features booleans from a catalog.
func CompactStatusFlags(items []Feature) StatusFeatures {
	var out StatusFeatures
	for _, f := range items {
		switch f.ID {
		case FeatureIDHTTP2:
			out.HTTP2 = f.Enabled
		case FeatureIDAcceptSOCKS5:
			out.SOCKS5 = f.Enabled
		case FeatureIDAcceptSOCKS4:
			out.SOCKS4 = f.Enabled
		case FeatureIDOriginalDest:
			out.OriginalDestination = f.Enabled
		case FeatureIDCompatFlowREST:
			out.CompatFlowREST = f.Enabled
		}
	}
	return out
}

// Features returns the derived catalog for the active snapshot.
func (s *App) Features(ctx context.Context, actor Actor) (*FeatureList, error) {
	if err := s.requireCtx(ctx); err != nil {
		return nil, err
	}
	_ = actor
	snap, err := s.active()
	if err != nil {
		return nil, err
	}
	list := featureListFromSnap(snap)
	return &list, nil
}

func featureListFromSnap(snap *snapshot.Snapshot) FeatureList {
	if snap == nil {
		return FeatureList{Items: CatalogFromSpec(model.Spec{})}
	}
	return FeatureList{
		RuntimeRevision: snap.Revision,
		Generation:      snap.Generation,
		Drifted:         snap.Drifted(),
		Items:           CatalogFromSpec(snap.Spec()),
	}
}
