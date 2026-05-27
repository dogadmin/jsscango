package fetcher

import (
	"context"
	"io"
)

// Method enumerates the HTTP methods used by the probe stage.
type Method string

const (
	MethodGET      Method = "GET"
	MethodPOSTForm Method = "POST_FORM"
	MethodPOSTJSON Method = "POST_JSON"
)

// Request bundles the inputs to a single HTTP call.
type Request struct {
	URL     string
	Method  Method
	Body    []byte            // POST body
	Headers map[string]string // additional headers, override defaults
	// NoFollow defaults to true; redirects are not followed because both the
	// Python crawler and probe use allow_redirects=False.
	FollowRedirects bool
}

// Response is the in-memory result of a fetch with the body fully read
// (bounded by --max-body-mb).
type Response struct {
	URL         string
	StatusCode  int
	ContentType string
	Header      map[string]string
	Body        []byte
	Truncated   bool // body exceeded MaxBodyBytes; Body holds the prefix
	Skipped     bool // body intentionally not read (e.g. Content-Disposition: attachment)
}

// Fetcher is the HTTP abstraction shared by crawler and probe.
type Fetcher interface {
	Fetch(ctx context.Context, req Request) (*Response, error)
}

// readAll reads up to limit bytes from r, returning the buffer and a
// Truncated flag.
func readAll(r io.Reader, limit int64) ([]byte, bool, error) {
	if limit <= 0 {
		limit = 16 << 20
	}
	lr := io.LimitReader(r, limit+1)
	b, err := io.ReadAll(lr)
	if err != nil {
		return b, false, err
	}
	if int64(len(b)) > limit {
		return b[:limit], true, nil
	}
	return b, false, nil
}
