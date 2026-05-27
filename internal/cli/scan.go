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

	"github.com/dogadmin/jsscango/internal/config"
	"github.com/dogadmin/jsscango/internal/pipeline"
	"github.com/dogadmin/jsscango/internal/progress"
	"github.com/dogadmin/jsscango/internal/util"
)

func newScanCmd() *cobra.Command {
	cfg := config.Default()
	var formatsCSV string

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
			if err := cfg.Normalize(); err != nil {
				return err
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

			for _, t := range targets {
				targetCtx, cancel := context.WithTimeout(ctx, cfg.TargetTimeout)
				if err := runner.RunTarget(targetCtx, t); err != nil {
					logger.Error("target failed", "url", t, "err", err)
				}
				cancel()
				if ctx.Err() != nil {
					return ctx.Err()
				}
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

	return cmd
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
