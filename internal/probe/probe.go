// Package probe implements stage 4 of the pipeline: send GET / POST_FORM /
// POST_JSON to each candidate API URL, keep only the responses that look
// genuinely interesting (200 + json/xml + not BLACK_TEXT), and save bodies.
package probe

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"golang.org/x/sync/errgroup"
	"golang.org/x/sync/semaphore"

	"github.com/dogadmin/jsscango/internal/fetcher"
	"github.com/dogadmin/jsscango/internal/rules"
	"github.com/dogadmin/jsscango/internal/state"
	"github.com/dogadmin/jsscango/internal/types"
	"github.com/dogadmin/jsscango/internal/util"
)

// Prober probes a slice of API URLs with three methods each. Concurrency is
// bounded by a semaphore (replacing the Python's 300 raw threads + sleep(0.2)
// stagger at apiUrlReqNoParameter.py:99-118 and apiUrlReqWithParameter.py:118).
type Prober struct {
	F          fetcher.Fetcher
	Rules      *rules.Set
	Seen       *state.Seen
	Workers    int
	OutDir     string         // results/<target_folder>
	TargetURL  string         // for ProbeResult.Target / Referer fallback
	Logger     *slog.Logger
	Emit       func(types.ProbeResult)
	Parameters []string       // mined params for POST/GET-with-param probes
}

// Job is one (url, method, body) tuple to probe.
type Job struct {
	URL     string
	Method  fetcher.Method
	Body    []byte
	Referer string
}

// methodFolderPrefix mirrors the file-naming used by the Python tool at
// apiUrlReqNoParameter.py:23, 47, 71 — response/GET_*, response/POST_DATA_*,
// response/POST_JSON_*.
func methodFolderPrefix(m fetcher.Method) string {
	switch m {
	case fetcher.MethodPOSTForm:
		return "POST_DATA"
	case fetcher.MethodPOSTJSON:
		return "POST_JSON"
	default:
		return "GET"
	}
}

// Run probes every (url × {GET, POST_FORM, POST_JSON}) combination. Each is
// scheduled as an individual Job so a slow URL on one method doesn't block
// the others. Dangerous paths are noted but not probed.
func (p *Prober) Run(ctx context.Context, apiURLs []string) error {
	if p.Workers <= 0 {
		p.Workers = 32
	}
	if err := os.MkdirAll(filepath.Join(p.OutDir, "response"), 0o755); err != nil {
		return fmt.Errorf("mkdir response: %w", err)
	}

	sem := semaphore.NewWeighted(int64(p.Workers))
	g, gctx := errgroup.WithContext(ctx)

	for _, u := range apiURLs {
		u := u
		if IsDangerous(u) {
			// Surface skip via emit so users see the decision in JSONL/xlsx.
			if p.Emit != nil {
				p.Emit(types.ProbeResult{
					Target:  p.TargetURL,
					URL:     u,
					Method:  "SKIPPED_DANGEROUS",
					Referer: p.TargetURL,
				})
			}
			continue
		}
		for _, m := range []fetcher.Method{fetcher.MethodGET, fetcher.MethodPOSTForm, fetcher.MethodPOSTJSON} {
			m := m
			if err := sem.Acquire(gctx, 1); err != nil {
				return err
			}
			g.Go(func() error {
				defer sem.Release(1)
				p.runOne(gctx, Job{URL: u, Method: m, Body: bodyFor(m, p.Parameters), Referer: p.TargetURL})
				return nil
			})
		}
	}
	return g.Wait()
}

func (p *Prober) runOne(ctx context.Context, j Job) {
	if ctx.Err() != nil {
		return
	}
	resp, err := p.F.Fetch(ctx, fetcher.Request{URL: j.URL, Method: j.Method, Body: j.Body})
	if err != nil {
		if p.Logger != nil {
			p.Logger.Debug("probe fetch failed", "url", j.URL, "method", j.Method, "err", err)
		}
		return
	}

	pr := types.ProbeResult{
		Target:      p.TargetURL,
		URL:         j.URL,
		Method:      string(j.Method),
		StatusCode:  resp.StatusCode,
		ContentType: resp.ContentType,
		Size:        int64(len(resp.Body)),
		Referer:     j.Referer,
	}
	if len(j.Body) > 0 {
		pr.Parameter = "<params>"
	}

	pr.Kept = isKept(resp.StatusCode, resp.ContentType, resp.Body, p.Rules)
	if pr.Kept && len(resp.Body) > 0 {
		// Deduplicate by body hash so the same payload from N URLs only
		// hits disk once. Mirrors what disposeResults.py does later, moved
		// up-front.
		first, isNew := p.Seen.AddBody(resp.Body, j.URL)
		pr.BodySHA256 = sha(resp.Body)
		if !isNew {
			pr.Duplicate = true
			pr.BodyPath = "" // skip write; first occurrence already saved
			_ = first
		} else {
			path, err := p.save(resp.Body, j)
			if err != nil {
				if p.Logger != nil {
					p.Logger.Warn("save response", "err", err)
				}
			} else {
				pr.BodyPath = path
			}
		}
	}
	if p.Emit != nil {
		p.Emit(pr)
	}
}

// isKept replicates the Python "200 && (json|xml) && !BLACK_TEXT" filter
// applied uniformly in apiUrlReqNoParameter.py:18 etc.
func isKept(status int, ct string, body []byte, rs *rules.Set) bool {
	if status != 200 {
		return false
	}
	ct = strings.ToLower(ct)
	if !strings.Contains(ct, "xml") && !strings.Contains(ct, "json") {
		return false
	}
	if rs != nil && rs.IsBlackText(body) {
		return false
	}
	return true
}

// save writes body to results/<target>/response/<METHOD>_<sanitized>.txt and
// returns the path. Replaces nodeCommon.save_response_to_file at
// nodeCommon.py:216 (now with explicit error return rather than try/except).
func (p *Prober) save(body []byte, j Job) (string, error) {
	name := fmt.Sprintf("%s_%s.txt", methodFolderPrefix(j.Method), util.SanitizeName(j.URL))
	full := filepath.Join(p.OutDir, "response", name)
	return full, os.WriteFile(full, body, 0o644)
}

func sha(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

// bodyFor builds the POST body. With no mined parameters, POST_FORM gets an
// empty body (matching Python apiUrlReqNoParameter.py:35) and POST_JSON gets
// `{}`. With parameters, POST_FORM gets URL-encoded `k=&k=...` and POST_JSON
// gets a flat `{"k":"", ...}` object.
func bodyFor(m fetcher.Method, params []string) []byte {
	switch m {
	case fetcher.MethodPOSTForm:
		if len(params) == 0 {
			return nil
		}
		var b strings.Builder
		for i, k := range params {
			if i > 0 {
				b.WriteByte('&')
			}
			b.WriteString(k)
			b.WriteByte('=')
		}
		return []byte(b.String())
	case fetcher.MethodPOSTJSON:
		if len(params) == 0 {
			return []byte("{}")
		}
		var b strings.Builder
		b.WriteByte('{')
		for i, k := range params {
			if i > 0 {
				b.WriteByte(',')
			}
			fmt.Fprintf(&b, "%q:%q", k, "")
		}
		b.WriteByte('}')
		return []byte(b.String())
	}
	return nil
}

// Aggregate counts probes for the summary line.
type Stats struct {
	mu                                sync.Mutex
	Total, Kept, Dup, Skipped, Failed int
}

func (s *Stats) Observe(pr types.ProbeResult) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.Total++
	if pr.Method == "SKIPPED_DANGEROUS" {
		s.Skipped++
		return
	}
	if pr.StatusCode == 0 {
		s.Failed++
		return
	}
	if pr.Kept {
		s.Kept++
	}
	if pr.Duplicate {
		s.Dup++
	}
}
