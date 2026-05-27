package fetcher

import (
	"context"
	"sync"

	"golang.org/x/time/rate"
)

// hostLimiter holds a per-host token bucket so we never overwhelm a single
// backend regardless of total worker count. Maps directly to the
// "300 threads against one site" failure mode of the Python version.
type hostLimiter struct {
	qps   float64
	mu    sync.RWMutex
	store map[string]*rate.Limiter
}

func newHostLimiter(qps float64) *hostLimiter {
	return &hostLimiter{qps: qps, store: make(map[string]*rate.Limiter)}
}

func (h *hostLimiter) Wait(ctx context.Context, host string) error {
	return h.get(host).Wait(ctx)
}

func (h *hostLimiter) get(host string) *rate.Limiter {
	h.mu.RLock()
	if l, ok := h.store[host]; ok {
		h.mu.RUnlock()
		return l
	}
	h.mu.RUnlock()
	h.mu.Lock()
	defer h.mu.Unlock()
	if l, ok := h.store[host]; ok {
		return l
	}
	// burst = max(qps, 1); allow a small head-start while keeping steady-state qps.
	burst := int(h.qps)
	if burst < 1 {
		burst = 1
	}
	l := rate.NewLimiter(rate.Limit(h.qps), burst)
	h.store[host] = l
	return l
}
