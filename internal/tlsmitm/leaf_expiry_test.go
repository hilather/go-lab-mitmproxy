package tlsmitm

import (
	"bytes"
	"testing"
	"time"
)

func TestLeafCacheRenewsAtExpiryWithSameCA(t *testing.T) {
	a, err := New(Options{})
	if err != nil {
		t.Fatal(err)
	}
	ca := a.CertPEM()
	start := time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC)
	first, err := a.leafForAt("App.Lab", start)
	if err != nil {
		t.Fatal(err)
	}
	cached, err := a.leafForAt("app.lab", first.Leaf.NotAfter.Add(-time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if cached != first {
		t.Fatal("valid leaf was not reused")
	}
	renewed, err := a.leafForAt("app.lab", first.Leaf.NotAfter)
	if err != nil {
		t.Fatal(err)
	}
	if renewed == first || bytes.Equal(renewed.Certificate[0], first.Certificate[0]) {
		t.Fatal("expired leaf was reused")
	}
	if !renewed.Leaf.NotAfter.After(first.Leaf.NotAfter) {
		t.Fatal("renewed leaf did not extend validity")
	}
	if err := renewed.Leaf.CheckSignatureFrom(a.CACertificate()); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(ca, a.CertPEM()) {
		t.Fatal("leaf renewal rotated CA")
	}
	if len(a.cache.items) != 1 || len(a.cache.order) != 1 {
		t.Fatal("renewal grew cache")
	}
}
func TestLeafCacheRenewsNotYetValidEntry(t *testing.T) {
	a, err := New(Options{})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC)
	future, err := a.leafForAt("app.lab", now.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := a.leafForAt("app.lab", now)
	if err != nil {
		t.Fatal(err)
	}
	if leaf == future || leaf.Leaf.NotBefore.After(now) {
		t.Fatal("not-yet-valid cache entry was reused")
	}
}
