package state

import (
	"sync"
	"sync/atomic"
	"testing"
)

func TestSeenAddURL_ConcurrentSingleWinner(t *testing.T) {
	s := NewSeen()
	const url = "https://example.com/foo.js"
	const goroutines = 200

	var winners atomic.Int32
	var wg sync.WaitGroup
	wg.Add(goroutines)
	start := make(chan struct{})
	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			<-start
			if s.AddURL(url) {
				winners.Add(1)
			}
		}()
	}
	close(start)
	wg.Wait()
	if got := winners.Load(); got != 1 {
		t.Fatalf("expected exactly one AddURL winner, got %d", got)
	}
	if !s.HasURL(url) {
		t.Fatal("url should be present after AddURL")
	}
}

func TestSeenAddURL_EmptyRejected(t *testing.T) {
	s := NewSeen()
	if s.AddURL("") {
		t.Fatal("empty URL should not be accepted")
	}
}

func TestSeenAddBody_FirstWins(t *testing.T) {
	s := NewSeen()
	body := []byte("hello, world")
	first, isNew := s.AddBody(body, "https://a.com/x")
	if !isNew || first != "https://a.com/x" {
		t.Fatalf("first AddBody: got (%q,%v), want (%q,true)", first, isNew, "https://a.com/x")
	}
	prev, isNew := s.AddBody(body, "https://b.com/y")
	if isNew || prev != "https://a.com/x" {
		t.Fatalf("second AddBody: got (%q,%v), want (%q,false)", prev, isNew, "https://a.com/x")
	}
}

func TestSeenSnapshot(t *testing.T) {
	s := NewSeen()
	for _, u := range []string{"a", "b", "c"} {
		s.AddURL(u)
	}
	snap := s.Snapshot()
	if len(snap) != 3 {
		t.Fatalf("snapshot size = %d, want 3", len(snap))
	}
}
