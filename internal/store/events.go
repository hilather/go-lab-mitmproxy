package store

import "sync"

// Inbox event kinds for REST SSE / MCP notify.
const (
	EventInserted = "inserted"
	EventPaused   = "paused"
	EventResumed  = "resumed"
	EventDropped  = "dropped"
	EventDeleted  = "deleted"
	EventWiped    = "wiped"
)

// Event is one inbox membership or breakpoint-state change.
type Event struct {
	Kind string
	ID   string
	Host string
	Gen  uint64
}

type subscriber struct {
	ch chan Event
}

// Subscribe receives membership events. The buffer is a ring: a slow
// consumer drops the oldest event so wipe/resume/drop stay visible.
// cancel must be called.
func (m *Memory) Subscribe(cap int) (<-chan Event, func()) {
	if m == nil {
		ch := make(chan Event)
		close(ch)
		return ch, func() {}
	}
	if cap <= 0 {
		cap = 16
	}
	sub := &subscriber{ch: make(chan Event, cap)}
	m.mu.Lock()
	m.subs = append(m.subs, sub)
	m.mu.Unlock()
	var once sync.Once
	cancel := func() {
		once.Do(func() {
			m.mu.Lock()
			for i, s := range m.subs {
				if s == sub {
					m.subs = append(m.subs[:i], m.subs[i+1:]...)
					break
				}
			}
			m.mu.Unlock()
			close(sub.ch)
		})
	}
	return sub.ch, cancel
}

func (m *Memory) emitLocked(ev Event) {
	for _, s := range m.subs {
		pushEvent(s.ch, ev)
	}
}

func pushEvent(ch chan Event, ev Event) {
	for {
		select {
		case ch <- ev:
			return
		default:
			select {
			case <-ch:
			default:
				return
			}
		}
	}
}
