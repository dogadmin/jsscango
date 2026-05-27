package pipeline

import (
	"context"
	"fmt"
	"log/slog"
	"net/url"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/dogadmin/jsscango/internal/config"
	"github.com/dogadmin/jsscango/internal/crawler"
	"github.com/dogadmin/jsscango/internal/fetcher"
	"github.com/dogadmin/jsscango/internal/output"
	"github.com/dogadmin/jsscango/internal/postprocess"
	"github.com/dogadmin/jsscango/internal/probe"
	"github.com/dogadmin/jsscango/internal/progress"
	"github.com/dogadmin/jsscango/internal/rules"
	"github.com/dogadmin/jsscango/internal/state"
	"github.com/dogadmin/jsscango/internal/types"
	"github.com/dogadmin/jsscango/internal/util"
)

// Pipeline owns the long-lived resources (HTTP client, sinks, rule set) that
// are reused across targets. RunTarget executes the 5-stage flow for a single
// URL.
type Pipeline struct {
	cfg      config.Config
	log      *slog.Logger
	fetch    fetcher.Fetcher
	rules    *rules.Set
	sinks    *output.Multi
	homepage fetcher.HomepageDiscoverer
	headless *fetcher.Headless // non-nil iff chromedp is in use; closed at Close
	tracker  *progress.Tracker // optional; nil is treated as a no-op
	closed   bool
	mu       sync.Mutex
}

// SetTracker attaches a progress.Tracker for live status reporting. Passing
// nil clears any previously attached tracker. Safe to call before RunTarget.
func (p *Pipeline) SetTracker(t *progress.Tracker) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.tracker = t
}

func New(cfg config.Config, logger *slog.Logger) (*Pipeline, error) {
	f, err := fetcher.New(cfg)
	if err != nil {
		return nil, err
	}
	rs, err := rules.Load(cfg.RulesFile)
	if err != nil {
		return nil, fmt.Errorf("rules: %w", err)
	}
	if errs := rs.CompileErrors(); len(errs) > 0 {
		for id, err := range errs {
			logger.Warn("rule failed to compile, skipped", "id", id, "err", err)
		}
	}
	counts := rs.Count()
	logger.Info("rules loaded",
		"fingerprint", counts[rules.KindFingerprint],
		"vuln", counts[rules.KindVuln],
		"sensitive", counts[rules.KindSensitive],
		"blacktext_markers", len(rs.BlackText),
	)

	var sinks []output.Sink
	for _, fm := range cfg.Formats {
		switch fm {
		case config.FormatJSONL:
			sinks = append(sinks, output.NewJSONL(cfg.OutDir))
		case config.FormatXLSX:
			sinks = append(sinks, output.NewXLSX(cfg.OutDir))
		}
	}

	// Pick the homepage discoverer: chromedp when requested (or auto + Chrome
	// is available), else the static HTML parser. Either way the pipeline
	// downstream depends only on fetcher.HomepageDiscoverer.
	homepage, headless, err := selectHomepage(cfg, f, logger)
	if err != nil {
		return nil, err
	}

	return &Pipeline{
		cfg:      cfg,
		log:      logger,
		fetch:    f,
		rules:    rs,
		sinks:    &output.Multi{Sinks: sinks},
		homepage: homepage,
		headless: headless,
	}, nil
}

// selectHomepage resolves --chrome={on,off,auto} into a concrete
// HomepageDiscoverer. Returns the discoverer and, if chromedp is used, a
// pointer to the Headless so Pipeline.Close can shut it down.
func selectHomepage(cfg config.Config, f fetcher.Fetcher, logger *slog.Logger) (fetcher.HomepageDiscoverer, *fetcher.Headless, error) {
	switch cfg.Chrome {
	case config.ChromeOff:
		logger.Info("homepage discovery", "mode", "static")
		return &crawler.StaticHomepage{F: f}, nil, nil
	case config.ChromeOn:
		if !fetcher.HeadlessAvailable() {
			return nil, nil, fmt.Errorf("--chrome=on requires a Chrome/Chromium binary on PATH; install Chrome or use --chrome=auto/off")
		}
		logger.Info("homepage discovery", "mode", "chromedp")
		h := fetcher.NewHeadless()
		h.Logger = logger
		return h, h, nil
	default: // ChromeAuto
		if fetcher.HeadlessAvailable() {
			logger.Info("homepage discovery", "mode", "chromedp", "reason", "auto detected Chrome")
			h := fetcher.NewHeadless()
			h.Logger = logger
			return h, h, nil
		}
		logger.Info("homepage discovery", "mode", "static", "reason", "Chrome not found on PATH")
		return &crawler.StaticHomepage{F: f}, nil, nil
	}
}

func (p *Pipeline) Close() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return nil
	}
	p.closed = true
	if p.headless != nil {
		p.headless.Close()
	}
	return p.sinks.Close()
}

// RunTarget executes the 5-stage pipeline for one URL.
func (p *Pipeline) RunTarget(ctx context.Context, raw string) error {
	target, err := buildTarget(raw, p.cfg)
	if err != nil {
		return err
	}
	folder := util.TargetFolder(target.URL)
	if err := p.sinks.Start(ctx, folder); err != nil {
		return err
	}
	defer p.sinks.Flush()

	outDir := filepath.Join(p.cfg.OutDir, folder)
	start := time.Now()

	emit := func(ev string, r types.Report) {
		r.Schema = types.SchemaVersion
		r.Time = time.Now()
		r.Target = target.URL
		r.Event = ev
		if err := p.sinks.Write(r); err != nil {
			p.log.Warn("sink write failed", "err", err)
		}
	}

	// setStage mirrors stage transitions into the live tracker; nil-safe.
	setStage := func(name string) {
		if p.tracker != nil {
			p.tracker.SetStage(name)
		}
	}
	// setCount pushes a counter value into the tracker; nil-safe.
	setCount := func(key string, value int) {
		if p.tracker != nil {
			p.tracker.SetCount(key, value)
		}
	}

	seen := state.NewSeen()

	// --- Resume state (--resume) ------------------------------------------
	// On --resume we load any existing state.json, hydrate Seen with prior
	// URLs (so the crawler won't re-fetch them), and skip stages already
	// marked done. Fresh runs always create a new state file.
	resume, resumed, err := state.LoadOrInit(outDir, target.URL)
	if err != nil {
		p.log.Warn("resume load", "err", err)
		resume, _, _ = state.LoadOrInit(outDir, target.URL)
	}
	if resumed && p.cfg.Resume {
		resume.HydrateSeen(seen)
		p.log.Info("resuming", "stages_done", stageList(resume))
	}
	doStage := func(name string) bool {
		if p.cfg.Resume && resume.IsDone(name) {
			p.log.Info("skipping stage (resume)", "stage", name)
			return false
		}
		return true
	}

	// Stats counters (shared, mutex-protected via their own types).
	stats := struct {
		urlsDiscovered, jsDiscovered, apiPaths int
		mu                                     sync.Mutex
	}{}

	emitDU := func(d types.DiscoveredURL) {
		d.Target = target.URL
		stats.mu.Lock()
		stats.urlsDiscovered++
		switch d.Kind {
		case types.KindJS:
			stats.jsDiscovered++
		case types.KindAPIPath:
			stats.apiPaths++
		}
		urls := stats.urlsDiscovered
		js := stats.jsDiscovered
		apis := stats.apiPaths
		stats.mu.Unlock()
		setCount("urls", urls)
		setCount("js", js)
		setCount("api_paths", apis)
		emit("discovered_url", types.Report{URL: &d})
	}

	// --- Stage 1: homepage -------------------------------------------------
	var seeds []types.DiscoveredURL
	if doStage(state.StageHomepage) {
		setStage(state.StageHomepage)
		p.log.Info("stage", "name", state.StageHomepage, "phase", "start")
		emit("stage", types.Report{Stage: state.StageHomepage})
		stageStart := time.Now()
		seeds, err = p.homepage.Discover(ctx, target.URL, p.cfg.Cookies)
		if err != nil {
			p.log.Warn("homepage discover", "url", target.URL, "err", err)
		}
		setCount("seeds", len(seeds))
		p.log.Info("stage", "name", state.StageHomepage, "phase", "done",
			"elapsed", time.Since(stageStart), "seeds", len(seeds))
		_ = resume.Done(state.StageHomepage)
	}

	// --- Stage 2 + 3: crawl + inline API path extraction ------------------
	apiPathSet := newConcurrentSet()
	apiEmitter := func(d types.DiscoveredURL) {
		emitDU(d)
		if d.Kind == types.KindAPIPath {
			apiPathSet.Add(d.URL)
			emit("api_path", types.Report{API: &types.APIPath{
				Target: target.URL, Referer: d.Referer, Path: d.URL, Pattern: d.Source,
			}})
		}
	}
	if doStage(state.StageCrawl) {
		setStage(state.StageCrawl)
		p.log.Info("stage", "name", state.StageCrawl, "phase", "start",
			"workers", p.cfg.WorkersCrawl, "max_depth", p.cfg.MaxDepth, "per_host_qps", p.cfg.PerHostQPS)
		emit("stage", types.Report{Stage: state.StageCrawl})
		stageStart := time.Now()
		cr := &crawler.Crawler{
			F:          p.fetch,
			Seen:       seen,
			Workers:    p.cfg.WorkersCrawl,
			MaxDepth:   p.cfg.MaxDepth,
			BaseDomain: target.BaseDomain,
			Logger:     p.log,
			Emit:       apiEmitter,
		}
		if err := cr.Run(ctx, seeds); err != nil {
			p.log.Warn("crawl", "err", err)
		}
		resume.SetSeenURLs(seen.Snapshot())
		stats.mu.Lock()
		urls := stats.urlsDiscovered
		js := stats.jsDiscovered
		apis := stats.apiPaths
		stats.mu.Unlock()
		p.log.Info("stage", "name", state.StageCrawl, "phase", "done",
			"elapsed", time.Since(stageStart), "urls", urls, "js", js, "api_paths", apis)
		_ = resume.Done(state.StageCrawl)
	}

	probeCount, hitCount := 0, 0

	// --- Stage 4: probe ---------------------------------------------------
	if !p.cfg.NoProbe && !p.cfg.CollectOnly && doStage(state.StageProbe) {
		// Construct probe URLs: combine each discovered base URL with each
		// API path. Faithful to filter_data() in getJsUrl.py:119 minus the
		// path-with-api-string heuristics, which Phase 2 keeps simple - the
		// crawler emits full URLs when JS contains absolute API paths, and
		// the relative ones get prefixed onto the target's scheme+host.
		urls := buildProbeURLs(target, seeds, apiPathSet.Items())
		setStage(state.StageProbe)
		p.log.Info("stage", "name", state.StageProbe, "phase", "start",
			"urls", len(urls), "workers", p.cfg.WorkersProbe, "per_host_qps", p.cfg.PerHostQPS)
		emit("stage", types.Report{Stage: state.StageProbe})
		stageStart := time.Now()
		var probeStats probe.Stats
		// Mirror probeStats.Total/Kept into the tracker. probe.Stats keeps
		// its mutex unexported, so we maintain a parallel atomic pair to
		// avoid racing the locked Observe writes when probe workers run
		// concurrently.
		var liveTotal, liveKept atomic.Int64
		pr := &probe.Prober{
			F:         p.fetch,
			Rules:     p.rules,
			Seen:      seen,
			Workers:   p.cfg.WorkersProbe,
			OutDir:    outDir,
			TargetURL: target.URL,
			Logger:    p.log,
			Emit: func(r types.ProbeResult) {
				probeStats.Observe(r)
				total := liveTotal.Add(1)
				kept := liveKept.Load()
				if r.Kept {
					kept = liveKept.Add(1)
				}
				setCount("probes", int(total))
				setCount("probes_kept", int(kept))
				emit("probe", types.Report{Probe: &r})
			},
		}
		if err := pr.Run(ctx, urls); err != nil {
			p.log.Warn("probe", "err", err)
		}
		probeCount = probeStats.Total
		p.log.Info("stage", "name", state.StageProbe, "phase", "done",
			"elapsed", time.Since(stageStart),
			"total", probeStats.Total, "kept", probeStats.Kept,
			"dup", probeStats.Dup, "skipped", probeStats.Skipped, "failed", probeStats.Failed)
		_ = resume.Done(state.StageProbe)
	}

	// --- Stage 5: postprocess (rule hits on saved bodies) -----------------
	if !p.cfg.NoProbe && !p.cfg.CollectOnly && doStage(state.StagePostprocess) {
		setStage(state.StagePostprocess)
		p.log.Info("stage", "name", state.StagePostprocess, "phase", "start")
		emit("stage", types.Report{Stage: state.StagePostprocess})
		stageStart := time.Now()
		ppStats := postprocess.NewStats()
		var liveHits atomic.Int64
		pp := &postprocess.Processor{
			Rules:   p.rules,
			Workers: p.cfg.Workers,
			OutDir:  outDir,
			Target:  target.URL,
			Logger:  p.log,
			Emit: func(h types.RuleHit) {
				ppStats.Observe(h)
				setCount("rule_hits", int(liveHits.Add(1)))
				emit("rule_hit", types.Report{Hit: &h})
			},
		}
		if err := pp.Run(ctx); err != nil {
			p.log.Warn("postprocess", "err", err)
		}
		hitCount = ppStats.Total()
		p.log.Info("stage", "name", state.StagePostprocess, "phase", "done",
			"elapsed", time.Since(stageStart), "rule_hits", hitCount)
		_ = resume.Done(state.StagePostprocess)
	}

	resume.SetStat("urls_discovered", stats.urlsDiscovered)
	resume.SetStat("js_discovered", stats.jsDiscovered)
	resume.SetStat("api_paths", stats.apiPaths)
	resume.SetStat("probes", probeCount)
	resume.SetStat("rule_hits", hitCount)
	_ = resume.Finish()

	setStage("done")

	emit("summary", types.Report{Summary: &types.Summary{
		DurationMS:     time.Since(start).Milliseconds(),
		URLsDiscovered: stats.urlsDiscovered,
		JSFetched:      stats.jsDiscovered,
		APIPaths:       stats.apiPaths,
		Probes:         probeCount,
		RuleHits:       hitCount,
	}})

	// Per-target xlsx writers need a Close to actually serialize. The
	// JSONL writer needs Close on shutdown only. Cheap-and-correct: close
	// the sinks here (each sink Close is idempotent and flushes too), then
	// re-open them next call to RunTarget via Start.
	if err := p.sinks.Close(); err != nil {
		p.log.Warn("close sinks (per target)", "err", err)
	}
	// Re-create sinks so subsequent targets start fresh files.
	p.sinks = buildSinks(p.cfg)
	return nil
}

func buildSinks(cfg config.Config) *output.Multi {
	var sinks []output.Sink
	for _, fm := range cfg.Formats {
		switch fm {
		case config.FormatJSONL:
			sinks = append(sinks, output.NewJSONL(cfg.OutDir))
		case config.FormatXLSX:
			sinks = append(sinks, output.NewXLSX(cfg.OutDir))
		}
	}
	return &output.Multi{Sinks: sinks}
}

// buildProbeURLs combines target base URL with each API path candidate to
// produce concrete URLs for the probe stage. Absolute paths starting with /
// are joined onto the target's scheme://host; full URLs are passed through.
func buildProbeURLs(target types.Target, seeds []types.DiscoveredURL, apiPaths []string) []string {
	base := target.Scheme + "://" + target.Host
	if target.Port != "" {
		base = target.Scheme + "://" + target.Host + ":" + target.Port
	}
	seen := make(map[string]struct{}, len(apiPaths))
	var out []string
	add := func(u string) {
		if u == "" {
			return
		}
		if _, ok := seen[u]; ok {
			return
		}
		seen[u] = struct{}{}
		out = append(out, u)
	}
	// 1. Each discovered API path joined onto the target's base.
	for _, p := range apiPaths {
		switch {
		case strings.HasPrefix(p, "http://"), strings.HasPrefix(p, "https://"):
			add(p)
		case strings.HasPrefix(p, "/"):
			add(base + p)
		default:
			add(base + "/" + p)
		}
	}
	// 2. Also probe the seed "no_js" URLs from homepage discovery (e.g.
	// chromedp captured /api/X requests directly).
	for _, s := range seeds {
		if s.Kind == types.KindNoJS {
			add(s.URL)
		}
	}
	return out
}

func buildTarget(raw string, cfg config.Config) (types.Target, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return types.Target{}, fmt.Errorf("invalid URL: %q", raw)
	}
	t := types.Target{
		URL:        raw,
		Scheme:     u.Scheme,
		Host:       u.Hostname(),
		Port:       u.Port(),
		BaseDomain: util.BaseDomain(raw),
		Cookies:    cfg.Cookies,
		Folder:     util.TargetFolder(raw),
		StartedAt:  time.Now(),
	}
	return t, nil
}

// stageList returns the names of stages already marked done in r, sorted
// for log readability.
func stageList(r *state.Resume) []string {
	all := []string{state.StageHomepage, state.StageCrawl, state.StageProbe, state.StagePostprocess}
	var out []string
	for _, s := range all {
		if r.IsDone(s) {
			out = append(out, s)
		}
	}
	return out
}

// concurrentSet is a tiny string set with a mutex; the crawler emits API
// paths from many goroutines and we need them deduplicated before probe.
type concurrentSet struct {
	mu sync.Mutex
	m  map[string]struct{}
}

func newConcurrentSet() *concurrentSet { return &concurrentSet{m: make(map[string]struct{})} }

func (s *concurrentSet) Add(v string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.m[v] = struct{}{}
}

func (s *concurrentSet) Items() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]string, 0, len(s.m))
	for k := range s.m {
		out = append(out, k)
	}
	return out
}
