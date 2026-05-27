package preflight

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// TestCheck_ClassifiesResponseCodes confirms that a server returning a
// non-2xx (here: 401) is still classified as "alive" — the whole point
// of pre-flight is to keep gated APIs in scope.
func TestCheck_ClassifiesResponseCodes(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()

	res := Check(context.Background(), []string{srv.URL}, 2*time.Second, 4, nil)
	if len(res.Alive) != 1 {
		t.Fatalf("expected 1 alive (401 still counts), got %d alive, %d dead (%+v)", len(res.Alive), len(res.Dead), res.Dead)
	}
	if len(res.Dead) != 0 {
		t.Errorf("expected 0 dead, got %d: %+v", len(res.Dead), res.Dead)
	}
}

// TestCheck_ClassifiesDeadHost points at 127.0.0.1:1 (a port nothing
// listens on in any reasonable test environment) and asserts we mark
// it dead with reason="refused". If a CI runner ever does run a
// service on :1 we'll see this start failing — that's louder than a
// silent mis-classification.
func TestCheck_ClassifiesDeadHost(t *testing.T) {
	res := Check(context.Background(), []string{"http://127.0.0.1:1"}, 2*time.Second, 4, nil)
	if len(res.Alive) != 0 {
		t.Fatalf("expected 0 alive against 127.0.0.1:1, got %d (%v)", len(res.Alive), res.Alive)
	}
	if len(res.Dead) != 1 {
		t.Fatalf("expected 1 dead, got %d", len(res.Dead))
	}
	r := res.Dead[0].Reason
	// Either "refused" (connection refused) or "timeout" (some kernels
	// drop SYNs to :1 silently) is acceptable here. What we DO want to
	// reject is an empty reason or an unclassified raw error.
	if r != "refused" && r != "timeout" {
		t.Errorf(`dead reason for 127.0.0.1:1 = %q, want "refused" or "timeout"`, r)
	}
}

// TestCheck_RespectsTimeout spins up a server that sleeps longer than
// the per-URL timeout and confirms we classify it as a timeout (not
// hang forever, not silently succeed).
func TestCheck_RespectsTimeout(t *testing.T) {
	// Server blocks well past the 300 ms timeout below. We don't need
	// the handler to ever return — the client should close the conn.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-r.Context().Done():
		case <-time.After(5 * time.Second):
		}
	}))
	defer srv.Close()

	start := time.Now()
	res := Check(context.Background(), []string{srv.URL}, 300*time.Millisecond, 2, nil)
	elapsed := time.Since(start)

	if len(res.Alive) != 0 {
		t.Fatalf("expected 0 alive (server hung), got %d", len(res.Alive))
	}
	if len(res.Dead) != 1 {
		t.Fatalf("expected 1 dead, got %d", len(res.Dead))
	}
	if res.Dead[0].Reason != "timeout" {
		t.Errorf(`dead reason = %q, want "timeout"`, res.Dead[0].Reason)
	}
	// Sanity: we shouldn't have waited anywhere near the server's 5s.
	if elapsed > 2*time.Second {
		t.Errorf("Check blocked for %v, expected ~300ms timeout-driven return", elapsed)
	}
}

// TestCheck_ReportsProgress verifies the onProgress callback fires
// once per completed probe and that (alive+dead) reaches len(urls)
// by the end.
func TestCheck_ReportsProgress(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	urls := []string{srv.URL, srv.URL, srv.URL}

	var calls int
	var lastTotal int
	res := Check(context.Background(), urls, 2*time.Second, 2, func(alive, dead, total int) {
		calls++
		lastTotal = total
		// The (alive+dead) running sum must never exceed the announced total.
		if alive+dead > total {
			t.Errorf("progress: alive=%d dead=%d total=%d (sum > total)", alive, dead, total)
		}
	})
	if calls != len(urls) {
		t.Errorf("onProgress called %d times, want %d", calls, len(urls))
	}
	if lastTotal != len(urls) {
		t.Errorf("final total reported = %d, want %d", lastTotal, len(urls))
	}
	if len(res.Alive)+len(res.Dead) != len(urls) {
		t.Errorf("alive+dead = %d, want %d", len(res.Alive)+len(res.Dead), len(urls))
	}
}
