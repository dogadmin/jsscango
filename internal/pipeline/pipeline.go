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
		"source", rs.Source,
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
			x := output.NewXLSX(cfg.OutDir)
			x.Split = cfg.XLSXSplit
			sinks = append(sinks, x)
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
		h.NoStealth = cfg.NoStealth
		return h, h, nil
	default: // ChromeAuto
		if fetcher.HeadlessAvailable() {
			logger.Info("homepage discovery", "mode", "chromedp", "reason", "auto detected Chrome")
			h := fetcher.NewHeadless()
			h.Logger = logger
			h.NoStealth = cfg.NoStealth
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

	// --- Stage 0: well-known endpoints (free discovery before homepage) ----
	// Robots.txt, sitemap.xml, OpenAPI/Swagger docs, and Spring actuator
	// often expose route surface area at fixed URLs. Anything we learn here
	// is funnelled into the same seeds + probe-URL paths used downstream,
	// so the rest of the pipeline doesn't need to know this stage exists.
	var wellKnownSeeds []types.DiscoveredURL
	var wellKnownAPIs []crawler.APIEndpoint
	if !p.cfg.SkipWellKnown && doStage(state.StageWellKnown) {
		p.log.Info("stage", "name", state.StageWellKnown, "phase", "start")
		setStage(state.StageWellKnown)
		emit("stage", types.Report{Stage: state.StageWellKnown})
		stageStart := time.Now()
		wk := &crawler.WellKnown{F: p.fetch, Logger: p.log}
		r, err := wk.Probe(ctx, target.URL)
		if err != nil {
			p.log.Warn("wellknown probe", "err", err)
		}
		wellKnownSeeds = r.Discovered
		wellKnownAPIs = r.APIPaths
		p.log.Info("stage", "name", state.StageWellKnown, "phase", "done",
			"elapsed", time.Since(stageStart),
			"urls", len(wellKnownSeeds), "openapi_endpoints", len(wellKnownAPIs))
		_ = resume.Done(state.StageWellKnown)
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
	// Prepend well-known seeds so the crawler walks them first. Doing this
	// outside the homepage block keeps the wellknown stage useful even when
	// homepage is skipped via --resume.
	if len(wellKnownSeeds) > 0 {
		seeds = append(wellKnownSeeds, seeds...)
		setCount("seeds", len(seeds))
	}

	// --- Stage 2 + 3: crawl + inline API path extraction ------------------
	apiPathSet := newConcurrentSet()
	// apiMethodHints captures the HTTP verb that framework-aware extraction
	// attached to each discovered API path (axios-style url+method pairs).
	// The probe stage prefers these over the default GET/POST_FORM/POST_JSON
	// fan-out, saving probe traffic AND covering DELETE/PATCH-only endpoints
	// the fan-out would have missed entirely.
	apiMethodHints := newConcurrentMap()
	apiEmitter := func(d types.DiscoveredURL) {
		emitDU(d)
		if d.Kind == types.KindAPIPath {
			apiPathSet.Add(d.URL)
			if d.Method != "" {
				apiMethodHints.Set(d.URL, d.Method)
			}
			emit("api_path", types.Report{API: &types.APIPath{
				Target: target.URL, Referer: d.Referer, Path: d.URL, Pattern: d.Source,
				Method: d.Method,
			}})
		}
		// Vue Router / SPA-router routes get their own event so they show up
		// in the dedicated XLSX sheet. They are intentionally NOT added to
		// apiPathSet — the probe stage's GET + POST_FORM + POST_JSON fan-out
		// would generate 3x noise per route against a 404 page (frontend
		// routes resolve only via SPA navigation, not via a server-side GET
		// on the path).
		if d.Kind == types.KindFrontendRoute {
			route := d
			route.Target = target.URL
			emit("frontend_route", types.Report{URL: &route})
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
	// hits2xx and probedURLs are populated by the probe Emit callback below
	// and consumed by the ancestor-recurse sub-stage that follows.
	var (
		hits2xxMu   sync.Mutex
		hits2xx     []string
		probedURLs  = make(map[string]struct{})
	)
	if !p.cfg.NoProbe && !p.cfg.CollectOnly && doStage(state.StageProbe) {
		// Construct probe targets: combine each discovered base URL with each
		// API path AND attach the declared HTTP method when extraction
		// surfaced one. Faithful to filter_data() in getJsUrl.py:119 minus
		// the path-with-api-string heuristics, which Phase 2 keeps simple -
		// the crawler emits full URLs when JS contains absolute API paths,
		// and the relative ones get prefixed onto the target's scheme+host.
		targets := buildProbeTargets(target, seeds, apiPathSet.Items(), apiMethodHints.Snapshot(), wellKnownAPIs)
		// Seed the already-probed set with the primary targets so the
		// ancestor-recurse stage skips URLs we already covered.
		for _, t := range targets {
			probedURLs[t.URL] = struct{}{}
		}
		setStage(state.StageProbe)
		p.log.Info("stage", "name", state.StageProbe, "phase", "start",
			"urls", len(targets), "workers", p.cfg.WorkersProbe, "per_host_qps", p.cfg.PerHostQPS)
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
			Fanout:    p.cfg.ProbeFanout,
			Emit: func(r types.ProbeResult) {
				probeStats.Observe(r)
				total := liveTotal.Add(1)
				kept := liveKept.Load()
				if r.Kept {
					kept = liveKept.Add(1)
				}
				setCount("probes", int(total))
				setCount("probes_kept", int(kept))
				// Record 2xx hits from the PRIMARY stage only (Source=="")
				// so the ancestor-recurse stage doesn't re-recurse on its
				// own results — depth is capped at 2 from the original hit.
				if r.Source == "" && r.StatusCode >= 200 && r.StatusCode < 300 {
					hits2xxMu.Lock()
					hits2xx = append(hits2xx, r.URL)
					hits2xxMu.Unlock()
				}
				emit("probe", types.Report{Probe: &r})
			},
		}
		if err := pr.RunTargets(ctx, targets); err != nil {
			p.log.Warn("probe", "err", err)
		}
		probeCount = probeStats.Total
		p.log.Info("stage", "name", state.StageProbe, "phase", "done",
			"elapsed", time.Since(stageStart),
			"total", probeStats.Total, "kept", probeStats.Kept,
			"dup", probeStats.Dup, "skipped", probeStats.Skipped, "failed", probeStats.Failed)
		_ = resume.Done(state.StageProbe)

		// --- Stage 4b: ancestor recurse ---------------------------------
		// For each 2xx hit, ascend up to AncestorRecurseDepth parent paths
		// and probe them as potential index endpoints. Crucially this stage
		// does NOT recurse on its own results — hard stop at depth 2 from
		// the ORIGINAL hit, because DeriveAncestors already returns parents
		// up to depth in one shot.
		if p.cfg.AncestorRecurseDepth > 0 && doStage(state.StageAncestorRecurse) {
			var ancestors []probe.Target
			seenAncestor := make(map[string]struct{})
			for _, hit := range hits2xx {
				parents, err := probe.DeriveAncestors(hit, p.cfg.AncestorRecurseDepth)
				if err != nil {
					p.log.Debug("derive ancestors", "url", hit, "err", err)
					continue
				}
				for _, pURL := range parents {
					if _, ok := seenAncestor[pURL]; ok {
						continue
					}
					if _, ok := probedURLs[pURL]; ok {
						continue
					}
					seenAncestor[pURL] = struct{}{}
					ancestors = append(ancestors, probe.Target{
						URL:       pURL,
						Methods:   []string{"GET"}, // index lookups only
						Source:    "ancestor_recurse",
						ParentURL: hit,
					})
				}
			}
			if len(ancestors) > 0 {
				setStage(state.StageAncestorRecurse)
				p.log.Info("stage", "name", state.StageAncestorRecurse, "phase", "start",
					"ancestors", len(ancestors), "from_2xx", len(hits2xx))
				emit("stage", types.Report{Stage: state.StageAncestorRecurse})
				ancStart := time.Now()
				var ancKept atomic.Int64
				ancPr := &probe.Prober{
					F:         p.fetch,
					Rules:     p.rules,
					Seen:      seen,
					Workers:   p.cfg.WorkersProbe,
					OutDir:    outDir,
					TargetURL: target.URL,
					Logger:    p.log,
					Fanout:    probe.FanoutConservative,
					Emit: func(r types.ProbeResult) {
						probeStats.Observe(r)
						total := liveTotal.Add(1)
						kept := liveKept.Load()
						if r.Kept {
							kept = liveKept.Add(1)
							ancKept.Add(1)
						}
						setCount("probes", int(total))
						setCount("probes_kept", int(kept))
						emit("probe", types.Report{Probe: &r})
					},
				}
				if err := ancPr.RunTargets(ctx, ancestors); err != nil {
					p.log.Warn("ancestor recurse", "err", err)
				}
				probeCount = probeStats.Total
				p.log.Info("stage", "name", state.StageAncestorRecurse, "phase", "done",
					"elapsed", time.Since(ancStart),
					"ancestors", len(ancestors), "kept", int(ancKept.Load()))
				_ = resume.Done(state.StageAncestorRecurse)
			}
		}
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
			// JSON-walk pass: surface URL-bearing fields (href / url / link
			// / endpoint / action / path) found inside saved JSON responses
			// as discovered_url events. Marked source="json_walk" so output
			// consumers can tell these apart from regex-scanned hits.
			EmitURL: func(d types.DiscoveredURL) {
				d.Target = target.URL
				emit("discovered_url", types.Report{URL: &d})
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
			x := output.NewXLSX(cfg.OutDir)
			x.Split = cfg.XLSXSplit
			sinks = append(sinks, x)
		}
	}
	return &output.Multi{Sinks: sinks}
}

// buildProbeTargets combines the target base URL with each API path
// candidate to produce concrete probe.Target entries. Absolute paths
// starting with / are joined onto the target's scheme://host; full URLs
// are passed through. apiMethodHints carries the verb that framework-aware
// extraction attached to a discovered path (axios-style url+method pair);
// when present, the probe stage uses ONLY that method, skipping the
// three-method fan-out. wellKnownAPIs are OpenAPI/Swagger/actuator-derived
// (path, methods) pairs; their methods are now honored.
func buildProbeTargets(
	target types.Target,
	seeds []types.DiscoveredURL,
	apiPaths []string,
	apiMethodHints map[string]string,
	wellKnownAPIs []crawler.APIEndpoint,
) []probe.Target {
	base := target.Scheme + "://" + target.Host
	if target.Port != "" {
		base = target.Scheme + "://" + target.Host + ":" + target.Port
	}
	type slot struct {
		idx     int      // index into out
		methods []string // upper-cased verbs accumulated so far
	}
	seen := make(map[string]*slot, len(apiPaths))
	var out []probe.Target
	add := func(u string, methods []string) {
		if u == "" {
			return
		}
		if s, ok := seen[u]; ok {
			// Merge any new methods into the existing slot. Empty methods
			// (the fan-out fallback) trump any prior hint — once we have
			// seen the URL without a method hint we want the fan-out so
			// rules cover GET / POST as well as the declared verb.
			if len(methods) == 0 {
				out[s.idx].Methods = nil
				s.methods = nil
				return
			}
			if out[s.idx].Methods == nil {
				return
			}
			for _, m := range methods {
				exists := false
				for _, em := range s.methods {
					if em == m {
						exists = true
						break
					}
				}
				if !exists {
					s.methods = append(s.methods, m)
				}
			}
			out[s.idx].Methods = s.methods
			return
		}
		out = append(out, probe.Target{URL: u, Methods: append([]string(nil), methods...)})
		seen[u] = &slot{idx: len(out) - 1, methods: append([]string(nil), methods...)}
	}
	// 1. Each discovered API path joined onto the target's base. Method
	// hints are keyed by the raw apiPath (the same value the extractor
	// emitted and we stored in apiMethodHints).
	for _, p := range apiPaths {
		var methods []string
		if hint, ok := apiMethodHints[p]; ok && hint != "" {
			methods = []string{hint}
		}
		switch {
		case strings.HasPrefix(p, "http://"), strings.HasPrefix(p, "https://"):
			add(p, methods)
		case strings.HasPrefix(p, "/"):
			add(base+p, methods)
		default:
			add(base+"/"+p, methods)
		}
	}
	// 2. Also probe the seed "no_js" URLs from homepage discovery (e.g.
	// chromedp captured /api/X requests directly).
	for _, s := range seeds {
		if s.Kind == types.KindNoJS {
			add(s.URL, nil)
		}
	}
	// 3. Well-known endpoints (OpenAPI/Swagger/actuator). Their declared
	// methods are now honored: when the doc said `DELETE /foo`, we probe
	// only DELETE instead of the three-method fan-out.
	for _, e := range wellKnownAPIs {
		p := e.Path
		if p == "" {
			continue
		}
		methods := append([]string(nil), e.Methods...)
		switch {
		case strings.HasPrefix(p, "http://"), strings.HasPrefix(p, "https://"):
			add(p, methods)
		case strings.HasPrefix(p, "/"):
			add(base+p, methods)
		default:
			add(base+"/"+p, methods)
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
	all := []string{state.StageWellKnown, state.StageHomepage, state.StageCrawl, state.StageProbe, state.StageAncestorRecurse, state.StagePostprocess}
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

// concurrentMap is a tiny string->string map with a mutex. Used by the
// crawler's apiEmitter callback (which fires from many goroutines) to
// accumulate the (api_path -> declared HTTP method) hints surfaced by
// framework-aware extraction. Snapshot returns a plain map[string]string
// snapshot for the probe stage to consume.
type concurrentMap struct {
	mu sync.Mutex
	m  map[string]string
}

func newConcurrentMap() *concurrentMap { return &concurrentMap{m: make(map[string]string)} }

func (s *concurrentMap) Set(k, v string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.m[k] = v
}

func (s *concurrentMap) Snapshot() map[string]string {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make(map[string]string, len(s.m))
	for k, v := range s.m {
		out[k] = v
	}
	return out
}
