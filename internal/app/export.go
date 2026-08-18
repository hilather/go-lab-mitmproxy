package app

import (
	"context"

	"github.com/hilather/go-lab-mitmproxy/internal/config"
	"github.com/hilather/go-lab-mitmproxy/internal/domainerr"
	"github.com/hilather/go-lab-mitmproxy/internal/model"
)

// Export returns canonical YAML or JSON of the active snapshot.
func (s *App) Export(ctx context.Context, actor Actor, format ExportFormat) (*Export, error) {
	if err := s.requireCtx(ctx); err != nil {
		return nil, err
	}
	_ = actor
	snap, err := s.active()
	if err != nil {
		return nil, err
	}
	if format == "" {
		format = ExportYAML
	}
	if format != ExportYAML && format != ExportJSON {
		return nil, domainerr.ValidationFailed("unknown export format",
			domainerr.FieldViolation{Path: "format", Code: "invalid_value", Message: "format must be yaml or json"})
	}
	var body []byte
	switch format {
	case ExportJSON:
		body, err = config.CanonicalJSON(snap.Canonical)
	default:
		body, err = config.CanonicalYAML(snap.Canonical)
	}
	if err != nil {
		return nil, asDomain(err)
	}
	bootCanon := snap.Canonical
	if b := s.snaps.Bootstrap(); b != nil {
		bootCanon = b.Canonical
	}
	_, human, err := diffStates(bootCanon, snap.Canonical)
	if err != nil {
		return nil, err
	}
	return &Export{
		Format:            format,
		Body:              append([]byte(nil), body...),
		Revision:          snap.Revision,
		BootstrapRevision: snap.BootstrapRevision,
		Drifted:           snap.Drifted(),
		HumanDiff:         human,
	}, nil
}

// GetState returns a copy of the live spec plus revision metadata.
func (s *App) GetState(ctx context.Context, actor Actor) (*StateView, error) {
	if err := s.requireCtx(ctx); err != nil {
		return nil, err
	}
	_ = actor
	snap, err := s.active()
	if err != nil {
		return nil, err
	}
	copied, err := cloneState(snap.Canonical)
	if err != nil {
		return nil, err
	}
	view := &StateView{
		BootstrapRevision: snap.BootstrapRevision,
		RuntimeRevision:   snap.Revision,
		Generation:        snap.Generation,
		Drifted:           snap.Drifted(),
		LoadedAt:          snap.CompiledAt,
		Canonical:         copied,
	}
	if s.inbox != nil {
		st := s.inbox.Stats()
		view.StoreGeneration = st.Generation
		view.FlowCount = st.FlowCount
		view.StoreBytes = st.Bytes
	}
	return view, nil
}

// Status is revisions plus inbox occupancy and CA metadata (never the key).
func (s *App) Status(ctx context.Context, actor Actor) (*Status, error) {
	if err := s.requireCtx(ctx); err != nil {
		return nil, err
	}
	_ = actor
	snap, err := s.active()
	if err != nil {
		return nil, err
	}
	st := Status{
		Ready: ready(s.HealthFacts()),
		Revisions: model.RevisionStatus{
			BootstrapRevision: snap.BootstrapRevision,
			RuntimeRevision:   snap.Revision,
			Generation:        snap.Generation,
			Drifted:           snap.Drifted(),
			LoadedAt:          snap.CompiledAt.UTC().Format("2006-01-02T15:04:05Z"),
		},
		Intercept: snap.Spec().TLS.Intercept,
	}
	if snap.CA != nil {
		st.CA = snap.CA.Status()
	}
	if s.inbox != nil {
		stats := s.inbox.Stats()
		st.Revisions.StoreGeneration = stats.Generation
		st.Revisions.FlowCount = stats.FlowCount
		st.Revisions.StoreBytes = stats.Bytes
		st.Epoch = stats.Epoch
	}
	return &st, nil
}

// GetCA returns the lab CA certificate PEM only. Never the private key.
func (s *App) GetCA(ctx context.Context, actor Actor) ([]byte, error) {
	if err := s.requireCtx(ctx); err != nil {
		return nil, err
	}
	_ = actor
	snap, err := s.active()
	if err != nil {
		return nil, err
	}
	if snap.CA == nil {
		return nil, domainerr.NotFound("lab CA is not compiled")
	}
	return snap.CA.CertPEM(), nil
}
