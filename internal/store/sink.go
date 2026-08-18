package store

import (
	"context"

	"github.com/hilather/go-lab-mitmproxy/internal/model"
)

// Sink accepts captured flows from the proxy data plane.
type Sink interface {
	// Insert records f if epoch still matches the value captured at request start.
	Insert(ctx context.Context, epoch uint64, f *model.Flow) (model.InsertResult, error)
	Epoch() uint64
}
