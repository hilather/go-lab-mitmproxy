package snapshot

import "sync/atomic"

// Store holds the active, previous, and bootstrap snapshots behind atomic
// pointers. The proxy loads once per request / CONNECT. Zero value is ready.
type Store struct {
	active    atomic.Pointer[Snapshot]
	previous  atomic.Pointer[Snapshot]
	bootstrap atomic.Pointer[Snapshot]
}

// NewStore returns an empty Store. Load, Previous, and Bootstrap are nil.
func NewStore() *Store {
	return &Store{}
}

// Load returns the active snapshot, or nil if none has been installed.
func (s *Store) Load() *Snapshot {
	if s == nil {
		return nil
	}
	return s.active.Load()
}

// Swap installs next as the active snapshot and returns the previous active
// pointer. A non-nil displaced snapshot becomes Previous. Swap does not
// change Bootstrap.
func (s *Store) Swap(next *Snapshot) *Snapshot {
	if s == nil {
		return nil
	}
	prev := s.active.Swap(next)
	if prev != nil {
		s.previous.Store(prev)
	}
	return prev
}

// Bootstrap returns the compiled bootstrap snapshot, or nil.
func (s *Store) Bootstrap() *Snapshot {
	if s == nil {
		return nil
	}
	return s.bootstrap.Load()
}

// Previous returns the last non-nil snapshot displaced by Swap, or nil.
func (s *Store) Previous() *Snapshot {
	if s == nil {
		return nil
	}
	return s.previous.Load()
}

// SetBootstrap records the compiled bootstrap snapshot without changing
// active or previous.
func (s *Store) SetBootstrap(next *Snapshot) {
	if s == nil {
		return
	}
	s.bootstrap.Store(next)
}

// InstallBootstrap records next as bootstrap and installs it as active.
// A nil receiver or nil next is a no-op so a failed compile cannot clear a
// live store.
func (s *Store) InstallBootstrap(next *Snapshot) *Snapshot {
	if s == nil || next == nil {
		return nil
	}
	s.SetBootstrap(next)
	return s.Swap(next)
}
