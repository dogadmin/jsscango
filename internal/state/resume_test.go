package state

import (
	"os"
	"path/filepath"
	"testing"
)

func TestResume_FreshThenLoad(t *testing.T) {
	dir := t.TempDir()
	target := "https://example.com/"

	r1, loaded, err := LoadOrInit(dir, target)
	if err != nil {
		t.Fatalf("init: %v", err)
	}
	if loaded {
		t.Fatal("expected fresh init, got loaded")
	}
	if err := r1.Done(StageHomepage); err != nil {
		t.Fatalf("Done: %v", err)
	}
	r1.SetSeenURLs([]string{"https://example.com/a", "https://example.com/b"})
	if err := r1.Save(); err != nil {
		t.Fatalf("Save: %v", err)
	}

	r2, loaded, err := LoadOrInit(dir, target)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	if !loaded {
		t.Fatal("expected loaded state from disk")
	}
	if !r2.IsDone(StageHomepage) {
		t.Error("homepage should be marked done")
	}
	if r2.IsDone(StageProbe) {
		t.Error("probe should not be marked done")
	}
	urls := r2.SeenURLs()
	if len(urls) != 2 {
		t.Errorf("seen urls len = %d, want 2", len(urls))
	}
}

func TestResume_HydrateSeen(t *testing.T) {
	dir := t.TempDir()
	r, _, _ := LoadOrInit(dir, "https://x.com/")
	r.SetSeenURLs([]string{"u1", "u2", "u3"})
	s := NewSeen()
	r.HydrateSeen(s)
	for _, u := range []string{"u1", "u2", "u3"} {
		if !s.HasURL(u) {
			t.Errorf("Seen missing %q after Hydrate", u)
		}
	}
	// AddURL on a hydrated URL should return false (not new).
	if s.AddURL("u1") {
		t.Error("AddURL on hydrated URL should return false")
	}
}

func TestResume_TargetMismatchRejected(t *testing.T) {
	dir := t.TempDir()
	r, _, _ := LoadOrInit(dir, "https://a.com/")
	r.Save()
	_, _, err := LoadOrInit(dir, "https://b.com/")
	if err == nil {
		t.Fatal("expected target mismatch error")
	}
}

func TestResume_AtomicWrite(t *testing.T) {
	dir := t.TempDir()
	r, _, _ := LoadOrInit(dir, "https://x.com/")
	if err := r.Save(); err != nil {
		t.Fatal(err)
	}
	// state.json should exist; state.json.tmp should not.
	if _, err := os.Stat(filepath.Join(dir, "state.json")); err != nil {
		t.Errorf("state.json missing: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "state.json.tmp")); err == nil {
		t.Error("state.json.tmp leaked - tmp file not renamed")
	}
}
