package fetcher

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/dogadmin/jsscango/internal/config"
	"github.com/dogadmin/jsscango/internal/util"
)

// HTTPFetcher is the production Fetcher implementation: single *http.Client,
// per-host rate limiter, retry+backoff, body-size cap. Safe for concurrent use.
type HTTPFetcher struct {
	client    *http.Client
	limiter   *hostLimiter
	maxBody   int64
	defaultUA string
	cookies   string
	retry     retryPolicy
}

// New returns an HTTPFetcher configured from cfg.
func New(cfg config.Config) (*HTTPFetcher, error) {
	tr, err := newTransport(!cfg.SecureTLS, cfg.Proxy)
	if err != nil {
		return nil, err
	}
	c := &http.Client{
		Transport: tr,
		Timeout:   cfg.Timeout,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	return &HTTPFetcher{
		client:    c,
		limiter:   newHostLimiter(cfg.PerHostQPS),
		maxBody:   cfg.MaxBodyBytes(),
		defaultUA: cfg.UA,
		cookies:   cfg.Cookies,
		retry:     defaultRetryPolicy(),
	}, nil
}

// Fetch issues the request, honouring per-host rate limit, retry on transient
// failures, and body size cap. Body is fully read into memory.
func (f *HTTPFetcher) Fetch(ctx context.Context, r Request) (*Response, error) {
	host := util.HostKey(r.URL)
	if err := f.limiter.Wait(ctx, host); err != nil {
		return nil, err
	}

	var lastErr error
	for attempt := 0; attempt < f.retry.MaxAttempts; attempt++ {
		req, err := f.build(ctx, r)
		if err != nil {
			return nil, err
		}
		resp, err := f.client.Do(req)
		if err == nil && !shouldRetry(resp.StatusCode, nil) {
			return f.consume(r.URL, resp)
		}
		if err == nil && attempt == f.retry.MaxAttempts-1 {
			// last attempt and the status is retryable but we're out of
			// retries - still return the response so the caller can decide.
			return f.consume(r.URL, resp)
		}
		if err != nil {
			lastErr = err
			if !shouldRetry(0, err) {
				return nil, err
			}
		} else {
			// drain & close before retry
			io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
			lastErr = fmt.Errorf("status %d", resp.StatusCode)
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(f.retry.backoff(attempt)):
		}
	}
	if lastErr == nil {
		lastErr = errors.New("fetch failed")
	}
	return nil, lastErr
}

func (f *HTTPFetcher) build(ctx context.Context, r Request) (*http.Request, error) {
	method := http.MethodGet
	var body io.Reader
	switch r.Method {
	case MethodPOSTForm, MethodPOSTJSON:
		method = http.MethodPost
		if r.Body != nil {
			body = bytes.NewReader(r.Body)
		} else {
			body = bytes.NewReader(nil)
		}
	case "", MethodGET:
		method = http.MethodGet
	default:
		return nil, fmt.Errorf("unknown method %q", r.Method)
	}
	req, err := http.NewRequestWithContext(ctx, method, r.URL, body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", f.defaultUA)
	if f.cookies != "" {
		req.Header.Set("Cookie", f.cookies)
	}
	switch r.Method {
	case MethodPOSTForm:
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	case MethodPOSTJSON:
		req.Header.Set("Content-Type", "application/json")
	}
	for k, v := range r.Headers {
		req.Header.Set(k, v)
	}
	return req, nil
}

func (f *HTTPFetcher) consume(reqURL string, resp *http.Response) (*Response, error) {
	defer resp.Body.Close()
	// Drop attachment downloads - mirrors Content-Disposition skip in
	// jsAndStaticUrlFind.py:138.
	if cd := resp.Header.Get("Content-Disposition"); strings.Contains(cd, "attachment") {
		io.Copy(io.Discard, resp.Body)
		return &Response{
			URL:         reqURL,
			StatusCode:  resp.StatusCode,
			ContentType: resp.Header.Get("Content-Type"),
			Header:      flatHeaders(resp.Header),
			Skipped:     true,
		}, nil
	}
	body, truncated, err := readAll(resp.Body, f.maxBody)
	if err != nil {
		return nil, err
	}
	return &Response{
		URL:         reqURL,
		StatusCode:  resp.StatusCode,
		ContentType: resp.Header.Get("Content-Type"),
		Header:      flatHeaders(resp.Header),
		Body:        body,
		Truncated:   truncated,
	}, nil
}

func flatHeaders(h http.Header) map[string]string {
	out := make(map[string]string, len(h))
	for k, v := range h {
		if len(v) > 0 {
			out[k] = v[0]
		}
	}
	return out
}
