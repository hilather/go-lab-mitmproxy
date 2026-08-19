package compat

import (
	"context"

	"github.com/hilather/go-lab-mitmproxy/internal/app"
	"github.com/hilather/go-lab-mitmproxy/internal/model"
)

// List returns at most ListLimit newest mapped flows. truncated is true when
// the inbox has more (D52).
func List(ctx context.Context, svc app.Service, actor app.Actor) ([]Flow, bool, error) {
	res, err := svc.ListFlows(ctx, actor, model.ListQuery{Limit: ListLimit})
	if err != nil {
		return nil, false, err
	}
	return MapList(res.Items), res.NextCursor != "", nil
}

// Get maps one flow.
func Get(ctx context.Context, svc app.Service, actor app.Actor, id string) (Flow, error) {
	f, err := svc.GetFlow(ctx, actor, id)
	if err != nil {
		return Flow{}, err
	}
	return MapFlow(f), nil
}

// Delete removes one flow.
func Delete(ctx context.Context, svc app.Service, actor app.Actor, id string) error {
	return svc.DeleteFlow(ctx, actor, id, app.DeleteIn{})
}

// Clear empties the inbox.
func Clear(ctx context.Context, svc app.Service, actor app.Actor) error {
	_, err := svc.ClearFlows(ctx, actor, app.DeleteIn{})
	return err
}

// Replay maps the newly captured flow.
func Replay(ctx context.Context, svc app.Service, actor app.Actor, id string) (Flow, error) {
	f, err := svc.Replay(ctx, actor, id)
	if err != nil {
		return Flow{}, err
	}
	return MapFlow(f), nil
}
