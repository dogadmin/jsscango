package fetcher

import (
	"errors"
	"math/rand/v2"
	"net"
	"time"
)

// retryPolicy controls exponential-backoff retries with jitter. Defaults: 3
// attempts, 250ms base, 4s cap, ±25% jitter.
type retryPolicy struct {
	MaxAttempts int
	Base        time.Duration
	Cap         time.Duration
	Jitter      float64
}

func defaultRetryPolicy() retryPolicy {
	return retryPolicy{MaxAttempts: 3, Base: 250 * time.Millisecond, Cap: 4 * time.Second, Jitter: 0.25}
}

// shouldRetry returns true for net.Error/network failures and for 5xx/429
// responses. ctx errors, DNS NXDOMAIN, and 4xx (except 429) do not retry.
func shouldRetry(status int, err error) bool {
	if err != nil {
		// NXDOMAIN: the host doesn't exist. Retrying never helps.
		var dnsErr *net.DNSError
		if errors.As(err, &dnsErr) && dnsErr.IsNotFound {
			return false
		}
		var ne net.Error
		if errors.As(err, &ne) {
			return true
		}
		return false
	}
	return status >= 500 || status == 429
}

func (p retryPolicy) backoff(attempt int) time.Duration {
	d := p.Base << attempt
	if d > p.Cap || d < 0 {
		d = p.Cap
	}
	// ±jitter
	delta := float64(d) * p.Jitter * (rand.Float64()*2 - 1)
	out := time.Duration(float64(d) + delta)
	if out < 0 {
		out = p.Base
	}
	return out
}
