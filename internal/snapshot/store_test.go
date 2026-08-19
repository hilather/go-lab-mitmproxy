package snapshot

import "testing"

func TestStoreZeroLoadPreviousBootstrapNil(t *testing.T) {
	s := NewStore()
	if s.Load() != nil || s.Previous() != nil || s.Bootstrap() != nil {
		t.Fatalf("empty store has pointers: load=%p prev=%p boot=%p", s.Load(), s.Previous(), s.Bootstrap())
	}
}

func TestStoreSwapPreviousAndBootstrap(t *testing.T) {
	s := NewStore()
	boot := &Snapshot{Generation: 0, Revision: "sha256:boot"}
	a := &Snapshot{Generation: 1, Revision: "sha256:a"}
	b := &Snapshot{Generation: 2, Revision: "sha256:b"}
	c := &Snapshot{Generation: 3, Revision: "sha256:c"}

	s.SetBootstrap(boot)
	if s.Bootstrap() != boot {
		t.Fatal("SetBootstrap did not stick")
	}
	if s.Load() != nil {
		t.Fatal("SetBootstrap must not change active")
	}

	if prev := s.Swap(a); prev != nil {
		t.Fatalf("first Swap previous = %p, want nil", prev)
	}
	if s.Load() != a {
		t.Fatal("Load after first Swap")
	}
	if s.Previous() != nil {
		t.Fatal("Previous after first Swap should be nil")
	}
	if s.Bootstrap() != boot {
		t.Fatal("Swap must not change Bootstrap")
	}

	if prev := s.Swap(b); prev != a {
		t.Fatalf("second Swap returned %p, want a", prev)
	}
	if s.Load() != b || s.Previous() != a {
		t.Fatal("after second Swap")
	}

	if prev := s.Swap(c); prev != b {
		t.Fatalf("third Swap returned %p, want b", prev)
	}
	if s.Load() != c || s.Previous() != b {
		t.Fatal("after third Swap")
	}
	if s.Bootstrap() != boot {
		t.Fatal("bootstrap lost")
	}
}

func TestInstallBootstrap(t *testing.T) {
	s := NewStore()
	if s.InstallBootstrap(nil) != nil {
		t.Fatal("nil next")
	}
	boot := &Snapshot{Generation: 0, Revision: "sha256:boot"}
	if prev := s.InstallBootstrap(boot); prev != nil {
		t.Fatal("first install previous")
	}
	if s.Load() != boot || s.Bootstrap() != boot {
		t.Fatal("install")
	}
	next := &Snapshot{Generation: 1, Revision: "sha256:next"}
	if prev := s.InstallBootstrap(next); prev != boot {
		t.Fatal("reinstall previous")
	}
	if s.Load() != next || s.Bootstrap() != next {
		t.Fatal("reinstall")
	}
}

func TestSnapshotDrifted(t *testing.T) {
	var nilSnap *Snapshot
	if nilSnap.Drifted() {
		t.Fatal("nil")
	}
	same := &Snapshot{Revision: "sha256:a", BootstrapRevision: "sha256:a"}
	if same.Drifted() {
		t.Fatal("same")
	}
	diff := &Snapshot{Revision: "sha256:b", BootstrapRevision: "sha256:a"}
	if !diff.Drifted() {
		t.Fatal("want drift")
	}
}
