// Package preflight runs cheap liveness probes against a target list
// BEFORE the full scan pipeline kicks in. The goal is straightforward:
// when an operator points the tool at tens of thousands of IPs/URLs,
// most of them are dead, and we don't want the scan pipeline to spend
// a full per-target-timeout (default 15 minutes) on every dead host
// before moving on.
//
// A target is "alive" iff the dial+TLS handshake completes and the
// server returns ANY HTTP response code — yes, even 4xx/5xx. The host
// being up is what matters; protected APIs return 401 and are still
// worth scanning. Body content is irrelevant and is not read.
package preflight

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/sync/errgroup"
	"golang.org/x/sync/semaphore"
)

// DeadTarget records a URL we dropped during pre-flight liveness along
// with a short, grep-friendly reason. Reasons are intentionally small
// strings ("timeout", "dns", "refused", or a truncated error message)
// so operators can pipe the dead-list through wc / sort | uniq -c.
type DeadTarget struct {
	URL    string
	Reason string
}

// LivenessResult buckets a target as alive or dead. The Reason is a
// short human-readable string for the dead bucket so operators can grep
// the log to understand why a target was dropped.
type LivenessResult struct {
	Alive []string
	Dead  []DeadTarget
}

// Check probes each URL concurrently with a short timeout. A target is
// "alive" iff the dial+TLS handshake completes and the server returns
// ANY HTTP response code (yes, even 4xx/5xx — the host being up is what
// matters; protected APIs return 401 and are still worth scanning).
//
// "dead" is: connection refused, DNS failure, dial timeout, TLS error,
// or any net.Error with Timeout/Temporary. Body content is irrelevant
// and not read.
//
// Concurrency = workers (bounded by a semaphore). timeout is per-URL.
// onProgress, if non-nil, is called once per completed probe with the
// running (alive, dead, total) counts — let the CLI plumb this to the
// existing progress tracker.
func Check(ctx context.Context, urls []string, timeout time.Duration, workers int, onProgress func(alive, dead, total int)) LivenessResult {
	if len(urls) == 0 {
		return LivenessResult{}
	}
	if workers <= 0 {
		workers = 1
	}
	if timeout <= 0 {
		timeout = 3 * time.Second
	}

	client := newProbeClient(timeout, workers)
	defer client.CloseIdleConnections()

	total := len(urls)
	alive := make([]string, 0, total/2)
	dead := make([]DeadTarget, 0, total/2)
	var mu sync.Mutex
	var aliveN, deadN atomic.Int64

	sem := semaphore.NewWeighted(int64(workers))
	g, gctx := errgroup.WithContext(ctx)

	for _, raw := range urls {
		u := raw
		if err := sem.Acquire(gctx, 1); err != nil {
			// Parent ctx cancelled — abandon the remaining probes and
			// fall through to the wait/return below. Anything not yet
			// classified is silently dropped from both buckets, which
			// the caller is responsible for handling (we surface the
			// remaining count via onProgress's "total" arg below).
			break
		}
		g.Go(func() error {
			defer sem.Release(1)
			ok, reason := probeOne(gctx, client, u)
			mu.Lock()
			if ok {
				alive = append(alive, u)
				aliveN.Add(1)
			} else {
				dead = append(dead, DeadTarget{URL: u, Reason: reason})
				deadN.Add(1)
			}
			mu.Unlock()
			if onProgress != nil {
				onProgress(int(aliveN.Load()), int(deadN.Load()), total)
			}
			return nil
		})
	}
	_ = g.Wait()

	return LivenessResult{Alive: alive, Dead: dead}
}

// newProbeClient builds an *http.Client tuned for thin, short-lived
// liveness probes. The transport caps idle conns at workers, allows
// only 1 idle conn per host (we never re-hit the same host inside a
// single pre-flight pass), and skips TLS verification — the goal is
// "did the server respond at all", not "is this cert trustworthy".
func newProbeClient(timeout time.Duration, workers int) *http.Client {
	dialer := &net.Dialer{Timeout: timeout / 2}
	tr := &http.Transport{
		DialContext:           dialer.DialContext,
		TLSHandshakeTimeout:   timeout / 2,
		ResponseHeaderTimeout: timeout,
		MaxIdleConns:          workers,
		MaxIdleConnsPerHost:   1,
		IdleConnTimeout:       30 * time.Second,
		TLSClientConfig:       &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // matches scan-time fetcher behaviour
		DisableCompression:    true,
	}
	return &http.Client{
		Timeout:   timeout,
		Transport: tr,
		// Don't follow redirects — a 3xx still means the host is up.
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

// probeOne issues a single HEAD (falling back to GET on 405) against
// url and returns (alive, reasonOnDead). The body is drained and closed
// cheaply — we never read more than a few bytes — and the request ctx
// piggybacks on the caller's ctx so cancellation propagates.
func probeOne(ctx context.Context, client *http.Client, url string) (alive bool, reason string) {
	req, err := http.NewRequestWithContext(ctx, http.MethodHead, url, nil)
	if err != nil {
		return false, truncReason(err.Error())
	}
	resp, err := client.Do(req)
	if err != nil {
		return false, classifyErr(err)
	}
	// 405 Method Not Allowed → some servers refuse HEAD. Retry with GET.
	if resp.StatusCode == http.StatusMethodNotAllowed {
		drainAndClose(resp.Body)
		req2, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			return false, truncReason(err.Error())
		}
		resp2, err := client.Do(req2)
		if err != nil {
			return false, classifyErr(err)
		}
		drainAndClose(resp2.Body)
		return true, ""
	}
	drainAndClose(resp.Body)
	return true, ""
}

// drainAndClose throws away whatever's left on the body so the
// connection can return to the idle pool. We cap the drain at 1 KiB —
// far more than any realistic 4xx/5xx body for liveness purposes.
func drainAndClose(body io.ReadCloser) {
	if body == nil {
		return
	}
	_, _ = io.CopyN(io.Discard, body, 1024)
	_ = body.Close()
}

// classifyErr turns a Go HTTP/dial error into a short reason token.
// Order matters: we check the more specific cases (context deadline,
// DNS, refused) before falling back to a truncated error string.
func classifyErr(err error) string {
	if err == nil {
		return ""
	}
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
		return "timeout"
	}
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) {
		return "dns"
	}
	msg := err.Error()
	low := strings.ToLower(msg)
	switch {
	// Linux/macOS use "connection refused"; Windows wsa-style says
	// "no connection could be made because the target machine actively
	// refused it" (10061 / WSAECONNREFUSED) — match either.
	case strings.Contains(low, "connection refused"),
		strings.Contains(low, "actively refused"),
		strings.Contains(low, "connectex"):
		return "refused"
	case strings.Contains(low, "no such host"):
		return "dns"
	case strings.Contains(low, "timeout"), strings.Contains(low, "deadline exceeded"):
		return "timeout"
	case strings.Contains(low, "tls"):
		return "tls"
	}
	// Last-ditch: a net.Error timeout/temporary
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return "timeout"
	}
	return truncReason(msg)
}

// truncReason caps an error string at ~80 chars and strips line
// breaks so it stays readable in a single log/csv line.
func truncReason(s string) string {
	s = strings.ReplaceAll(s, "\n", " ")
	s = strings.ReplaceAll(s, "\r", " ")
	if len(s) > 80 {
		s = s[:80]
	}
	return s
}
