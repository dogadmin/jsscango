// Package postprocess implements stage 5: scan saved response bodies for
// rule hits (fingerprint / vuln / sensitive) and emit RuleHit events.
//
// Body-level deduplication is intentionally done up-front in the probe stage
// (probe.Prober uses state.Seen.AddBody before writing to disk), so this
// stage only walks files that survive that dedup gate. That's the equivalent
// of plugins/disposeResults.py:diff_response_api, hoisted forward by one
// stage in the Go port so we don't pay disk-write cost on duplicates.
package postprocess

import (
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"golang.org/x/sync/errgroup"
	"golang.org/x/sync/semaphore"

	"github.com/dogadmin/jsscango/internal/rules"
	"github.com/dogadmin/jsscango/internal/types"
)

// Processor scans response bodies and emits RuleHit events.
//
// EmitURL is an optional callback fed by the JSON-walk pass: when a saved
// response body parses as JSON, the processor walks the structure for
// URL-bearing fields and pushes each surfaced value through EmitURL. Leave
// nil to skip the JSON-walk emission entirely; the rule-based scan still
// runs.
type Processor struct {
	Rules   *rules.Set
	Workers int
	OutDir  string // results/<target_folder>
	Target  string
	Logger  *slog.Logger
	Emit    func(types.RuleHit)
	EmitURL func(d types.DiscoveredURL) // optional callback for JSON-walked URLs
}

// Run walks all *.txt files under <OutDir>/response and applies the rule set
// to each. Hits are emitted via Emit.
func (p *Processor) Run(ctx context.Context) error {
	if p.Workers <= 0 {
		p.Workers = 8
	}
	dir := filepath.Join(p.OutDir, "response")
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil // nothing was saved; benign.
		}
		return err
	}

	sem := semaphore.NewWeighted(int64(p.Workers))
	g, gctx := errgroup.WithContext(ctx)

	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if !strings.HasSuffix(name, ".txt") {
			continue
		}
		full := filepath.Join(dir, name)
		if err := sem.Acquire(gctx, 1); err != nil {
			return err
		}
		g.Go(func() error {
			defer sem.Release(1)
			p.processFile(full)
			return nil
		})
	}
	return g.Wait()
}

func (p *Processor) processFile(path string) {
	data, err := os.ReadFile(path)
	if err != nil {
		if p.Logger != nil {
			p.Logger.Debug("read response", "path", path, "err", err)
		}
		return
	}
	hits := p.Rules.Apply(data)
	for _, h := range hits {
		if p.Emit == nil {
			continue
		}
		p.Emit(types.RuleHit{
			Target:  p.Target,
			Kind:    string(h.Kind),
			RuleID:  h.RuleID,
			Group:   h.Group,
			Matches: h.Matches,
			File:    path,
		})
	}

	// Parallel pass: when the saved body parses as JSON, walk the structure
	// and emit any URL-bearing field values via EmitURL. The cheap leading-
	// byte gate ([] or {}) skips the parse for non-JSON bodies (HTML, JS,
	// CSS, etc.) which is the common case. The file path is passed through
	// as the Referer so downstream stages can trace the URL back to the
	// originating response.
	if p.EmitURL != nil && looksLikeJSON(data) {
		for _, u := range WalkJSONForURLs(data) {
			p.EmitURL(types.DiscoveredURL{
				URL:     u,
				Referer: path,
				Kind:    types.KindAPIPath,
				Source:  "json_walk",
			})
		}
	}
}

// looksLikeJSON returns true when the first non-whitespace byte of data is
// '{' or '['. It is a fast gate to avoid the json.Unmarshal cost on HTML
// or JS bodies, which dominate the saved-response set.
func looksLikeJSON(data []byte) bool {
	for _, b := range data {
		switch b {
		case ' ', '\t', '\n', '\r':
			continue
		case '{', '[':
			return true
		default:
			return false
		}
	}
	return false
}

// Stats counts hits per Kind for the summary line.
type Stats struct {
	mu     sync.Mutex
	Counts map[string]int
}

func NewStats() *Stats { return &Stats{Counts: make(map[string]int)} }

func (s *Stats) Observe(h types.RuleHit) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.Counts[h.Kind]++
}

func (s *Stats) Total() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for _, v := range s.Counts {
		n += v
	}
	return n
}
