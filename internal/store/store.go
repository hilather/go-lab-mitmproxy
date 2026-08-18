package store

import (
	"context"
	"time"

	"github.com/hilather/go-lab-mitmproxy/internal/model"
)

// DefaultListLimit / MaxListLimit match the native REST list contract.
const (
	DefaultListLimit = 50
	MaxListLimit     = 200
)

// ResumePatch is an optional replacement applied by Resume.
// Nil Headers/Body keep the stored side; non-nil replaces (including empty).
type ResumePatch struct {
	Headers []model.Header
	Body    []byte
}

// Store is the queryable flow inbox. The proxy uses Sink (epoch-aware Insert).
// Wipe and ResetTo are the only epoch bumps.
type Store interface {
	Insert(ctx context.Context, epoch uint64, f *model.Flow) (model.InsertResult, error)
	Get(id string) (*model.Flow, error)
	List(model.ListQuery) (model.ListResult, error)
	Delete(id string) error
	DeleteAll() (deleted int, err error)
	Wait(ctx context.Context, filter model.FlowFilter) (*model.Flow, error)
	Pause(id string) error
	Resume(id string, patch *ResumePatch) error
	Drop(id string) error
	WaitPaused(ctx context.Context, id string) (ResumePatch, error)
	Subscribe(cap int) (<-chan Event, func())
	Generation() uint64
	Epoch() uint64
	Stats() model.StoreStats
	Wipe()
	ReplaceCaps(opts Options, force bool) error
	ResetTo(opts Options) error
}

// Options construct a Memory inbox.
type Options struct {
	MaxFlows       int
	MaxBytes       int64
	MaxBodyBytes   int64
	FullPolicy     string
	MaxWait        time.Duration
	SpillDirectory string
	SpillThreshold int64
}

// OptionsFromSpec copies compiled store caps.
func OptionsFromSpec(spec model.StoreSpec) Options {
	return Options{
		MaxFlows:       spec.MaxFlows,
		MaxBytes:       spec.MaxBytes,
		MaxBodyBytes:   spec.MaxBodyBytes,
		FullPolicy:     spec.FullPolicy,
		MaxWait:        spec.MaxWait,
		SpillDirectory: spec.SpillDirectory,
		SpillThreshold: spec.SpillThreshold,
	}
}
