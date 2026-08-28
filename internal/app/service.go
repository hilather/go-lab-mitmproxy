package app

import (
	"context"

	"github.com/hilather/go-lab-mitmproxy/internal/model"
	"github.com/hilather/go-lab-mitmproxy/internal/store"
)

// Service is the HTTP-less capability surface. REST and MCP must call these
// methods rather than implementing mutation or query logic. Proxy insert is
// not on this interface.
type Service interface {
	GetState(ctx context.Context, actor Actor) (*StateView, error)
	Validate(ctx context.Context, actor Actor, in ValidateIn) (*Plan, error)
	Plan(ctx context.Context, actor Actor, in ChangeIn) (*Plan, error)
	Apply(ctx context.Context, actor Actor, in ChangeIn) (*ApplyResult, error)
	Export(ctx context.Context, actor Actor, format ExportFormat) (*Export, error)
	Reset(ctx context.Context, actor Actor, in ResetIn) (*ApplyResult, error)
	Status(ctx context.Context, actor Actor) (*Status, error)
	Features(ctx context.Context, actor Actor) (*FeatureList, error)
	GetCA(ctx context.Context, actor Actor) ([]byte, error)

	ListFlows(ctx context.Context, actor Actor, q model.ListQuery) (model.ListResult, error)
	GetFlow(ctx context.Context, actor Actor, id string) (*model.Flow, error)
	DeleteFlow(ctx context.Context, actor Actor, id string, in DeleteIn) error
	ClearFlows(ctx context.Context, actor Actor, in DeleteIn) (int, error)
	Wait(ctx context.Context, actor Actor, in WaitIn) (*model.Flow, error)
	Resume(ctx context.Context, actor Actor, id string, patch *store.ResumePatch) error
	Drop(ctx context.Context, actor Actor, id string) error
	Replay(ctx context.Context, actor Actor, id string) (*model.Flow, error)
	Subscribe(ctx context.Context, actor Actor, buffer int) (<-chan FlowEvent, func())
	OnReset(fn func())
	OnApply(fn func())

	QueryAudit(ctx context.Context, actor Actor, in AuditQuery) (*AuditList, error)
	GetAudit(ctx context.Context, actor Actor, id string) (*AuditEvent, error)
}
