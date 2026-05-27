package cli

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"golang.org/x/sync/errgroup"

	"github.com/dogadmin/jsscango/internal/autotune"
	"github.com/dogadmin/jsscango/internal/config"
	"github.com/dogadmin/jsscango/internal/pipeline"
	"github.com/dogadmin/jsscango/internal/preflight"
	"github.com/dogadmin/jsscango/internal/progress"
	"github.com/dogadmin/jsscango/internal/util"
)

func newScanCmd() *cobra.Command {
	cfg := config.Default()
	defaults := config.Default() // baseline for "did the operator override this?" comparison
	var formatsCSV string
	var showTune bool

	cmd := &cobra.Command{
		Use:   "scan",
		Short: "Scan a URL or a file of URLs",
		RunE: func(cmd *cobra.Command, _ []string) error {
			if formatsCSV != "" {
				fs, err := config.ParseFormats(formatsCSV)
				if err != nil {
					return err
				}
				cfg.Formats = fs
			}

			// Apply autotune BEFORE Normalize so the tier's per-host-qps
			// and worker counts go through the same validation as
			// operator-supplied values. We compare each tunable field
			// against the defaults snapshot above; fields the operator
			// touched (i.e. don't match the default) are left alone.
			tier, applied, err := resolveTune(cfg.Tune)
			if err != nil {
				return err
			}
			if applied {
				applyTier(&cfg, defaults, tier)
				fmt.Fprintf(os.Stderr,
					"tune: %s  workers=%d workers-probe=%d per-host-qps=%g concurrent-targets=%d\n",
					tier.Name, cfg.Workers, cfg.WorkersProbe, cfg.PerHostQPS, cfg.ConcurrentTargets)
			}
			if showTune {
				printTune(os.Stderr, tier, applied, cfg)
				return nil
			}

			if err := cfg.Normalize(); err != nil {
				return err
			}

			// XLSX split-mode + parallel targets would race on the
			// per-target workbook write; reject loudly instead of
			// silently downgrading.
			if cfg.XLSXSplit && cfg.ConcurrentTargets > 1 {
				return fmt.Errorf("--xlsx-split is incompatible with concurrent-targets>1; drop --xlsx-split or run with concurrent-targets=1")
			}

			// The tracker is constructed unconditionally; when --no-progress
			// is set, or when stderr isn't a TTY, Start is a no-op and the
			// Writer() returned below behaves like a direct stderr pipe.
			trk := progress.New(os.Stderr)
			if !cfg.NoProgress {
				trk.Start()
			}
			defer trk.Stop()

			// Quiet-default logging: full INFO/DEBUG stream to a file under
			// the output dir, only WARN+ to stderr (so the progress tracker
			// owns the interactive window). --verbose lifts stderr to INFO.
			// --log-file= overrides the auto-derived file path; passing the
			// literal "stderr" routes everything to stderr at cfg.LogLevel.
			filePath := cfg.LogFile
			stderrLevel := "warn"
			if cfg.Verbose {
				stderrLevel = cfg.LogLevel
			}
			if filePath == "stderr" {
				filePath = ""
				stderrLevel = cfg.LogLevel
			} else if filePath == "" {
				if err := os.MkdirAll(cfg.OutDir, 0o755); err != nil {
					return fmt.Errorf("create out dir: %w", err)
				}
				filePath = filepath.Join(cfg.OutDir, "scan.log")
			}
			// Print the log path BEFORE trk.Start() so the spinner doesn't
			// immediately clear the line on its first render. Operators need
			// to see where the verbose log lives.
			if filePath != "" {
				fmt.Fprintf(os.Stderr, "log: %s\n", filePath)
			}
			logger, logCloser, err := util.NewSplitLogger(filePath, cfg.LogLevel, trk.Writer(), stderrLevel)
			if err != nil {
				return fmt.Errorf("logger: %w", err)
			}
			defer logCloser.Close()
			startPprof(cfg.PprofAddr, logger)
			targets, err := loadTargets(cfg)
			if err != nil {
				return err
			}
			if len(targets) == 0 {
				return fmt.Errorf("no targets to scan")
			}

			ctx, stop := signalCtx(cmd.Context())
			defer stop()

			// Liveness pre-probe (Feature 2). When "auto", we enable it
			// only above the threshold — running it for 5 targets is
			// more overhead than value.
			enableLiveness := false
			switch cfg.LivenessCheck {
			case "on":
				enableLiveness = true
			case "auto":
				enableLiveness = len(targets) > cfg.LivenessAutoThreshold
			}
			if enableLiveness {
				before := len(targets)
				logger.Info("liveness: starting pre-probe", "targets", before,
					"timeout", cfg.LivenessTimeout, "workers", cfg.LivenessWorkers)
				if trk != nil {
					trk.SetStage("liveness")
				}
				res := preflight.Check(ctx, targets, cfg.LivenessTimeout, cfg.LivenessWorkers,
					func(alive, dead, total int) {
						if trk != nil {
							trk.SetCount("liveness_alive", alive)
							trk.SetCount("liveness_dead", dead)
							trk.SetCount("liveness_total", total)
						}
					})
				targets = res.Alive
				fmt.Fprintf(os.Stderr, "liveness: %d/%d alive, %d dead\n",
					len(res.Alive), before, len(res.Dead))
				// Dead-target reasons go to the file logger ONLY (Info-level
				// is captured by the file handler; stderr handler is at WARN+
				// by default, so the progress window stays clean).
				for _, d := range res.Dead {
					logger.Info("liveness: dead", "url", d.URL, "reason", d.Reason)
				}
				if len(targets) == 0 {
					return fmt.Errorf("liveness pre-probe dropped every target; nothing to scan")
				}
			}

			runner, err := pipeline.New(cfg, logger)
			if err != nil {
				return err
			}
			runner.SetTracker(trk)
			// numTargets gates the /api fallback in the Python-parity
			// permutation: -u → 1 (fallback on), -f with N URLs → N
			// (fallback off so we don't spray /api across hosts).
			runner.SetNumTargets(len(targets))
			defer runner.Close()

			// Parallel target loop (Feature 3). When ConcurrentTargets ==
			// 1, the errgroup's limit makes this behaviourally identical
			// to the prior serial for-loop.
			g, gctx := errgroup.WithContext(ctx)
			g.SetLimit(cfg.ConcurrentTargets)
			for _, t := range targets {
				t := t
				g.Go(func() error {
					if gctx.Err() != nil {
						return gctx.Err()
					}
					targetCtx, cancel := context.WithTimeout(gctx, cfg.TargetTimeout)
					defer cancel()
					if err := runner.RunTarget(targetCtx, t); err != nil {
						logger.Error("target failed", "url", t, "err", err)
					}
					// Never propagate target failures — the errgroup must
					// run every target. The outer ctx cancellation (SIGINT)
					// is the only signal that should short-circuit.
					return nil
				})
			}
			if err := g.Wait(); err != nil {
				return err
			}
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return nil
		},
	}

	f := cmd.Flags()
	f.StringVarP(&cfg.URL, "url", "u", "", "target URL (single)")
	f.StringVarP(&cfg.File, "file", "f", "", "file with URLs (one per line)")
	f.StringVarP(&cfg.Cookies, "cookies", "c", "", "Cookie header value")
	f.StringVar((*string)(&cfg.Chrome), "chrome", string(config.ChromeAuto), "on|off|auto (chromedp headless mode)")
	f.BoolVar(&cfg.NoCollect, "no-collect", false, "skip stages 1-3 (consume cached responses)")
	f.BoolVar(&cfg.NoProbe, "no-probe", false, "skip API probing")
	f.BoolVar(&cfg.CollectOnly, "collect-only", false, "collect URLs/APIs only, no probing")
	f.BoolVar(&cfg.SkipWellKnown, "skip-wellknown", false, "skip the well-known endpoint pre-scan (robots.txt, sitemap.xml, openapi.json, actuator, etc.)")
	f.IntVar(&cfg.Workers, "workers", cfg.Workers, "default worker pool size")
	f.IntVar(&cfg.WorkersCrawl, "workers-crawl", 0, "override crawl pool size (0=workers)")
	f.IntVar(&cfg.WorkersProbe, "workers-probe", 0, "override probe pool size (0=workers)")
	f.Float64Var(&cfg.PerHostQPS, "per-host-qps", cfg.PerHostQPS, "per-host request rate cap")
	f.Uint8Var(&cfg.MaxDepth, "max-depth", cfg.MaxDepth, "BFS crawl depth cap")
	f.IntVar(&cfg.MaxBodyMB, "max-body-mb", cfg.MaxBodyMB, "max response body MiB")
	f.DurationVar(&cfg.Timeout, "timeout", cfg.Timeout, "per-request timeout")
	f.DurationVar(&cfg.TargetTimeout, "target-timeout", cfg.TargetTimeout, "per-target timeout")
	f.BoolVar(&cfg.SecureTLS, "secure-tls", false, "verify TLS certs (default: skip)")
	f.StringVar(&cfg.TLSFingerprint, "tls-fingerprint", cfg.TLSFingerprint, "TLS ClientHello fingerprint: chrome120|firefox120|safari17|go")
	f.StringVar(&cfg.RulesFile, "rules", "", "rules YAML override path")
	f.StringVar(&formatsCSV, "format", "jsonl,xlsx", "output formats: jsonl,xlsx")
	f.StringVar(&cfg.OutDir, "out", cfg.OutDir, "output directory")
	f.BoolVar(&cfg.XLSXSplit, "xlsx-split", false, "write one report.xlsx per target (legacy layout); default: single combined report.xlsx at the output root")
	f.BoolVar(&cfg.Resume, "resume", false, "resume from state.json if present")
	f.StringVar(&cfg.LogLevel, "log-level", cfg.LogLevel, "debug|info|warn|error")
	f.StringVar(&cfg.LogFile, "log-file", "", "log file path (default: <out>/scan.log; pass 'stderr' to route logs to terminal at --log-level)")
	f.StringVar(&cfg.Proxy, "proxy", "", "HTTP(S) proxy URL")
	f.StringVar(&cfg.UA, "user-agent", cfg.UA, "User-Agent header")
	f.StringVar(&cfg.PprofAddr, "pprof", "", "enable net/http/pprof on this addr (e.g. :6060); empty disables")
	f.BoolVar(&cfg.NoProgress, "no-progress", false, "disable the live status indicator (auto-disabled when stderr isn't a TTY)")
	f.BoolVar(&cfg.Verbose, "verbose", false, "also stream INFO/DEBUG logs to stderr (default: only WARN+ on stderr, full log in <out>/scan.log)")
	f.BoolVar(&cfg.NoStealth, "no-stealth", false, "disable chromedp stealth patches (debugging only)")
	f.IntVar(&cfg.AncestorRecurseDepth, "ancestor-recurse-depth", cfg.AncestorRecurseDepth, "ascend up to N parent paths from 2xx probe hits and probe them (0 disables; 2 is the recommended upper bound)")
	f.StringVar(&cfg.ProbeFanout, "probe-fanout", cfg.ProbeFanout, "method fan-out strategy when an api_path has no declared verb: action-aware (default; GET + POST_JSON for state-changing paths, GET only otherwise) | conservative (GET only) | all (legacy GET + POST_FORM + POST_JSON)")
	f.BoolVar(&cfg.PermutateProbe, "permutate-probe", cfg.PermutateProbe, "expand the probe set with Python-parity URL permutation (cartesian of derived bases x api-prefix-split paths); set --permutate-probe=false to disable")

	// Autotune + parallel-targets + liveness pre-probe flags (Phase: 30k-target scale-out).
	f.StringVar(&cfg.Tune, "tune", cfg.Tune, "autotune profile: auto (detect from CPU+RAM) | off (honour flags verbatim) | tiny|small|small-fat|medium|medium-fat|big|big-fat|huge|huge-fat")
	f.BoolVar(&showTune, "show-tune", false, "print the resolved tune profile and exit without scanning")
	f.IntVar(&cfg.ConcurrentTargets, "concurrent-targets", cfg.ConcurrentTargets, "number of targets to scan in parallel (1=serial; >1 forces JSONL to a single combined file and rejects --xlsx-split)")
	f.StringVar(&cfg.LivenessCheck, "liveness-check", cfg.LivenessCheck, "pre-probe liveness sweep: auto (on when targets > liveness-auto-threshold) | on | off")
	f.DurationVar(&cfg.LivenessTimeout, "liveness-timeout", cfg.LivenessTimeout, "per-URL timeout for the liveness sweep")
	f.IntVar(&cfg.LivenessWorkers, "liveness-workers", cfg.LivenessWorkers, "concurrency cap for the liveness sweep")
	f.IntVar(&cfg.LivenessAutoThreshold, "liveness-auto-threshold", cfg.LivenessAutoThreshold, "target count above which --liveness-check=auto enables the sweep")

	return cmd
}

// resolveTune turns the --tune flag value into a Tier and a "should I
// apply it" bool. "off" → no tier, no application. "auto" → Detect().
// Anything else is a named tier; an unknown name is a hard error so
// operators don't silently miss a typo.
func resolveTune(value string) (autotune.Tier, bool, error) {
	v := strings.ToLower(strings.TrimSpace(value))
	switch v {
	case "", "auto":
		return autotune.Detect(), true, nil
	case "off":
		return autotune.Tier{}, false, nil
	}
	t, ok := autotune.ByName(v)
	if !ok {
		names := make([]string, 0, len(autotune.Tiers))
		for _, t := range autotune.Tiers {
			names = append(names, t.Name)
		}
		return autotune.Tier{}, false, fmt.Errorf("unknown --tune %q (want auto|off|%s)", value, strings.Join(names, "|"))
	}
	return t, true, nil
}

// applyTier overlays the tier's tunables onto cfg, but only for fields
// the operator left at their default. The "is it default" check is a
// straight equality test against the baseline snapshot the CLI took
// before flag parsing — so any value the operator typed wins over the
// tier, even if the typed value happens to coincide with the default.
//
// Note on the equality test: cobra's StringVar/IntVar etc. don't tell
// us whether a flag was explicitly set, so we approximate with a value
// comparison. The operator who *intentionally* types --workers=64 on a
// machine where the autotuner would also pick 64 gets the same number
// either way, so the approximation is harmless.
func applyTier(cfg *config.Config, defaults config.Config, t autotune.Tier) {
	if cfg.Workers == defaults.Workers {
		cfg.Workers = t.Workers
	}
	if cfg.WorkersCrawl == defaults.WorkersCrawl {
		cfg.WorkersCrawl = t.WorkersCrawl
	}
	if cfg.WorkersProbe == defaults.WorkersProbe {
		cfg.WorkersProbe = t.WorkersProbe
	}
	if cfg.PerHostQPS == defaults.PerHostQPS {
		cfg.PerHostQPS = t.PerHostQPS
	}
	if cfg.ConcurrentTargets == defaults.ConcurrentTargets {
		cfg.ConcurrentTargets = t.ConcurrentTargets
	}
}

// printTune dumps the resolved tier values to w in a human-readable
// form. Used by --show-tune. We print the tier name when applied and
// "off" when the operator opted out, plus the resolved cfg values that
// would be sent to the pipeline (after Normalize-style defaulting on
// WorkersCrawl/WorkersProbe falling back to Workers).
func printTune(w *os.File, t autotune.Tier, applied bool, cfg config.Config) {
	if !applied {
		fmt.Fprintln(w, "tune: off")
	} else {
		fmt.Fprintf(w, "tune: %s\n", t.Name)
		fmt.Fprintf(w, "  min-cpu:           %d\n", t.MinCPU)
		fmt.Fprintf(w, "  min-ram:           %d MiB\n", t.MinRAMBytes>>20)
	}
	wc := cfg.WorkersCrawl
	if wc == 0 {
		wc = cfg.Workers
	}
	wp := cfg.WorkersProbe
	if wp == 0 {
		wp = cfg.Workers
	}
	fmt.Fprintf(w, "  workers:           %d\n", cfg.Workers)
	fmt.Fprintf(w, "  workers-crawl:     %d\n", wc)
	fmt.Fprintf(w, "  workers-probe:     %d\n", wp)
	fmt.Fprintf(w, "  per-host-qps:      %g\n", cfg.PerHostQPS)
	fmt.Fprintf(w, "  concurrent-targets:%d\n", cfg.ConcurrentTargets)
}

func loadTargets(cfg config.Config) ([]string, error) {
	var out []string
	if cfg.URL != "" {
		out = append(out, strings.TrimSpace(cfg.URL))
	}
	if cfg.File != "" {
		f, err := os.Open(cfg.File)
		if err != nil {
			return nil, fmt.Errorf("open target file: %w", err)
		}
		defer f.Close()
		sc := bufio.NewScanner(f)
		sc.Buffer(make([]byte, 64*1024), 1<<20)
		for sc.Scan() {
			line := strings.TrimSpace(sc.Text())
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			out = append(out, line)
		}
		if err := sc.Err(); err != nil {
			return nil, err
		}
	}
	return out, nil
}

// signalCtx wraps ctx with cancellation on SIGINT/SIGTERM. Returns cancel that
// is safe to call multiple times. The caller MUST defer the returned cancel
// so the inner signal goroutine, AfterFunc timer, and signal.Notify
// registration are all released on a graceful return — otherwise the timer
// can fire AFTER main returned and skip deferred Pipeline.Close /
// chromedp.Cancel / sink.Flush calls.
func signalCtx(parent context.Context) (context.Context, context.CancelFunc) {
	ctx, cancel := context.WithCancel(parent)
	ch1, stop1 := installSignalHandler()
	done := make(chan struct{})
	go func() {
		defer stop1()
		select {
		case <-ch1:
		case <-done:
			return
		}
		// First signal: arm a force-exit timer and cancel ctx so in-flight
		// work drains. Second signal jumps straight to os.Exit.
		t := time.AfterFunc(5*time.Second, func() { os.Exit(130) })
		defer t.Stop()
		cancel()
		ch2, stop2 := installSignalHandler()
		defer stop2()
		select {
		case <-ch2:
			os.Exit(130)
		case <-done:
			return
		}
	}()
	stopAll := func() {
		select {
		case <-done:
		default:
			close(done)
		}
		cancel()
	}
	return ctx, stopAll
}
