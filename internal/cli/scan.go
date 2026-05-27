package cli

import (
	"bufio"
	"context"
	"fmt"
	"os"
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

			// Route slog output through the tracker so log lines clear the
			// spinner before printing. When cfg.LogFile is set, the wrapper
			// is ignored (file logs aren't TTY).
			logger, err := util.NewLoggerWithWriter(cfg.LogLevel, cfg.LogFile, trk.Writer())
			if err != nil {
				return fmt.Errorf("logger: %w", err)
			}
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
	f.StringVar(&cfg.LogFile, "log-file", "", "log file path (default stderr)")
	f.StringVar(&cfg.Proxy, "proxy", "", "HTTP(S) proxy URL")
	f.StringVar(&cfg.UA, "user-agent", cfg.UA, "User-Agent header")
	f.StringVar(&cfg.PprofAddr, "pprof", "", "enable net/http/pprof on this addr (e.g. :6060); empty disables")
	f.BoolVar(&cfg.NoProgress, "no-progress", false, "disable the live status indicator (auto-disabled when stderr isn't a TTY)")
	f.BoolVar(&cfg.NoStealth, "no-stealth", false, "disable chromedp stealth patches (debugging only)")
	f.IntVar(&cfg.AncestorRecurseDepth, "ancestor-recurse-depth", cfg.AncestorRecurseDepth, "ascend up to N parent paths from 2xx probe hits and probe them (0 disables; 2 is the recommended upper bound)")
	f.StringVar(&cfg.ProbeFanout, "probe-fanout", cfg.ProbeFanout, "method fan-out strategy when an api_path has no declared verb: action-aware (default; GET + POST_JSON for state-changing paths, GET only otherwise) | conservative (GET only) | all (legacy GET + POST_FORM + POST_JSON)")

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
// is safe to call multiple times.
func signalCtx(parent context.Context) (context.Context, context.CancelFunc) {
	ctx, cancel := context.WithCancel(parent)
	go func() {
		<-installSignalHandler()
		// Give in-flight work a few seconds; second signal forces exit.
		t := time.AfterFunc(5*time.Second, func() { os.Exit(130) })
		cancel()
		<-installSignalHandler()
		t.Stop()
		os.Exit(130)
	}()
	return ctx, cancel
}
