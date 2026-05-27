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
	"regexp"
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

// Fan-out strategy names. See methodsFor for the per-strategy behavior.
const (
	FanoutAll          = "all"           // legacy: GET + POST_FORM + POST_JSON for every URL without a method hint
	FanoutActionAware  = "action-aware"  // GET always; add POST_JSON when the path suggests a state-changing action
	FanoutConservative = "conservative"  // GET only — POST attempts are skipped entirely
)

// actionWordPattern matches verbs that strongly imply a state-changing
// endpoint. When the URL's path contains one of these the prober adds a
// POST_JSON probe in addition to the GET; otherwise GET alone is sent under
// action-aware fan-out. Tuned for English + pinyin paths common in Chinese
// SaaS systems; lowercase comparison via case-insensitive flag.
var actionWordPattern = regexp.MustCompile(`(?i)\b(create|add|insert|new|register|update|edit|set|modify|put|patch|delete|remove|destroy|cancel|reset|save|submit|login|logout|signin|signout|signup|upload|import|export|send|publish|approve|reject|change|enable|disable|toggle|do|exec|run)\b`)

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
	// Fanout selects the method fan-out strategy when Target.Methods is empty.
	// Empty defaults to FanoutActionAware. See the constants above.
	Fanout string
}

// Target is one URL to probe with optional method hints. When Methods is
// non-empty, the Prober sends exactly those methods (mapped to fetcher.Method)
// instead of its default GET / POST_FORM / POST_JSON fan-out. The methods
// come from framework-aware extraction (axios url+method pairs, OpenAPI
// declarations, etc.) — surfacing them lets the prober skip wasted requests
// AND probe non-default verbs like DELETE / PATCH that the fan-out misses.
//
// Source/ParentURL annotate where the target came from. Source is propagated
// into ProbeResult so output sinks can group probes by origin
// ("ancestor_recurse" vs primary extraction). ParentURL is set on
// ancestor-recurse targets and identifies the 2xx hit that produced the
// ancestor — useful for trace/debug.
type Target struct {
	URL       string
	Methods   []string // upper-case HTTP verbs; empty -> fan-out fallback
	Source    string   // optional; "extractor" | "ancestor_recurse" | ...
	ParentURL string   // optional; when Source=="ancestor_recurse", the URL that produced this ancestor
}

// Job is one (url, method, body) tuple to probe.
type Job struct {
	URL     string
	Method  fetcher.Method
	Body    []byte
	Referer string
	Source  string // propagated into ProbeResult.Source
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
//
// This is the legacy entry point preserved for callers that don't yet have
// method hints. RunTargets is the method-aware path used by the pipeline.
func (p *Prober) Run(ctx context.Context, apiURLs []string) error {
	targets := make([]Target, 0, len(apiURLs))
	for _, u := range apiURLs {
		targets = append(targets, Target{URL: u})
	}
	return p.RunTargets(ctx, targets)
}

// RunTargets probes each Target, honoring its Methods hint when present.
// Targets without a Methods hint fall back to the legacy three-method
// fan-out (GET, POST_FORM, POST_JSON). When a Methods hint specifies a
// verb the prober doesn't have a body builder for (PUT/DELETE/PATCH/HEAD/
// OPTIONS), the request is sent with no body; the fetcher accepts any
// HTTP method string so this Just Works against the live target.
func (p *Prober) RunTargets(ctx context.Context, targets []Target) error {
	if p.Workers <= 0 {
		p.Workers = 32
	}
	if err := os.MkdirAll(filepath.Join(p.OutDir, "response"), 0o755); err != nil {
		return fmt.Errorf("mkdir response: %w", err)
	}

	sem := semaphore.NewWeighted(int64(p.Workers))
	g, gctx := errgroup.WithContext(ctx)

	for _, t := range targets {
		t := t
		if IsDangerous(t.URL) {
			// Surface skip via emit so users see the decision in JSONL/xlsx.
			if p.Emit != nil {
				p.Emit(types.ProbeResult{
					Target:  p.TargetURL,
					URL:     t.URL,
					Method:  "SKIPPED_DANGEROUS",
					Referer: p.TargetURL,
					Source:  t.Source,
				})
			}
			continue
		}
		methods := methodsFor(t, p.Fanout)
		for _, m := range methods {
			m := m
			if err := sem.Acquire(gctx, 1); err != nil {
				return err
			}
			src := t.Source
			g.Go(func() error {
				defer sem.Release(1)
				p.runOne(gctx, Job{URL: t.URL, Method: m, Body: bodyFor(m, p.Parameters), Referer: p.TargetURL, Source: src})
				return nil
			})
		}
	}
	return g.Wait()
}

// methodsFor decides which methods to fire for a Target. Precedence:
//  1. Target.Methods is non-empty → honor the declared hint (one method per
//     verb, deduplicated, unmappable verbs skipped). This wins regardless of
//     fan-out strategy.
//  2. Empty hint + fan-out strategy:
//       "all"          → GET + POST_FORM + POST_JSON (legacy)
//       "conservative" → GET only
//       "action-aware" → GET always; add POST_JSON when the URL path matches
//                        actionWordPattern (default; empty strategy == this)
//
// If the strategy string is unrecognized we fall back to action-aware rather
// than the noisier legacy three-tuple.
func methodsFor(t Target, fanout string) []fetcher.Method {
	if len(t.Methods) > 0 {
		out := make([]fetcher.Method, 0, len(t.Methods))
		seen := make(map[fetcher.Method]struct{}, len(t.Methods))
		for _, raw := range t.Methods {
			m := mapDeclaredMethod(raw)
			if m == "" {
				continue
			}
			if _, ok := seen[m]; ok {
				continue
			}
			seen[m] = struct{}{}
			out = append(out, m)
		}
		if len(out) > 0 {
			return out
		}
		// Hint was non-empty but contained only unrecognized verbs — fall
		// through to the strategy default rather than firing nothing.
	}
	switch fanout {
	case FanoutAll:
		return []fetcher.Method{fetcher.MethodGET, fetcher.MethodPOSTForm, fetcher.MethodPOSTJSON}
	case FanoutConservative:
		return []fetcher.Method{fetcher.MethodGET}
	default: // FanoutActionAware or empty/unknown
		if actionWordPattern.MatchString(t.URL) {
			return []fetcher.Method{fetcher.MethodGET, fetcher.MethodPOSTJSON}
		}
		return []fetcher.Method{fetcher.MethodGET}
	}
}

// mapDeclaredMethod converts an upper-case HTTP verb (as parsed from JS
// source or an OpenAPI doc) into the fetcher.Method we issue. GET / POST
// map to MethodGET / MethodPOSTJSON respectively (POST defaults to JSON
// since axios callers more often expect JSON than form bodies). The other
// standard verbs are passed through as raw method strings; fetcher.Method
// is a string type so this is a value cast, no plumbing change needed.
func mapDeclaredMethod(verb string) fetcher.Method {
	switch verb {
	case "GET":
		return fetcher.MethodGET
	case "POST":
		return fetcher.MethodPOSTJSON
	case "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS":
		return fetcher.Method(verb)
	}
	return ""
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
		Source:      j.Source,
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
