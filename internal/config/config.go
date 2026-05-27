package config

import (
	"fmt"
	"strings"
	"time"
)

const (
	DefaultUserAgent = "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/55.0.2883.75 Safari/537.36"
	DefaultTimeout   = 30 * time.Second
	DefaultTargetTTL = 15 * time.Minute
)

type ChromeMode string

const (
	ChromeOff  ChromeMode = "off"
	ChromeOn   ChromeMode = "on"
	ChromeAuto ChromeMode = "auto"
)

type Format string

const (
	FormatJSONL Format = "jsonl"
	FormatXLSX  Format = "xlsx"
)

// Config holds every tunable knob; fields map 1:1 to CLI flags. Bound by
// internal/cli at scan-command setup time.
type Config struct {
	URL     string
	File    string
	Cookies string

	Chrome ChromeMode

	NoCollect   bool
	NoProbe     bool
	CollectOnly bool

	// SkipWellKnown disables the pre-homepage well-known discovery stage
	// that probes robots.txt, sitemap.xml, OpenAPI/Swagger docs, and
	// /actuator endpoints. Default false (stage runs).
	SkipWellKnown bool

	Workers       int
	WorkersCrawl  int
	WorkersProbe  int
	PerHostQPS    float64
	MaxDepth      uint8
	MaxBodyMB     int
	Timeout       time.Duration
	TargetTimeout time.Duration
	SecureTLS     bool

	// TLSFingerprint controls JA3 mimicry. One of: chrome120 (default),
	// firefox120, safari17, go (stdlib crypto/tls — known JA3, easier
	// for WAFs to challenge).
	TLSFingerprint string

	RulesFile string
	Formats   []Format
	OutDir    string
	Resume    bool

	// XLSXSplit, when true, writes one report.xlsx per target into its own
	// subdirectory under OutDir (the legacy layout). Default false: a single
	// combined report.xlsx is written at OutDir/report.xlsx with a Target
	// column on every sheet.
	XLSXSplit bool

	LogLevel string
	LogFile  string
	Verbose  bool
	Proxy    string
	UA       string

	// PprofAddr enables a net/http/pprof listener at this address when
	// non-empty (e.g. ":6060"). Default empty = disabled.
	PprofAddr string

	// NoProgress, when true, suppresses the live status indicator even on a
	// TTY. Useful for operators piping the live stderr stream into less or
	// other consumers that don't render ANSI cursor controls.
	NoProgress bool

	// NoStealth, when true, disables the chromedp anti-detection stealth
	// patches injected via Page.addScriptToEvaluateOnNewDocument. Default
	// false (stealth ON); flip on for debugging the unpatched fingerprint.
	NoStealth bool

	// AncestorRecurseDepth controls the ancestor-path recurse stage that
	// fires after the primary probe stage: for each 2xx hit, ascend up to
	// N parent paths (with trailing slash) and probe them as potential
	// index endpoints. 0 disables the stage. 2 is the upper bound the
	// maintainer recommends — going further is mostly noise.
	AncestorRecurseDepth int

	// ProbeFanout chooses the method fan-out strategy for URLs without a
	// declared method hint. Values: "action-aware" (default; GET + POST_JSON
	// when the path contains a state-changing verb, GET-only otherwise),
	// "conservative" (GET only — POST attempts skipped entirely), "all"
	// (legacy three-method GET + POST_FORM + POST_JSON for every path).
	ProbeFanout string

	// PermutateProbe enables the Python-parity Cartesian URL permutation:
	// derive multiple bases from chromedp-captured XHR URLs and from
	// truncation inference, split api-prefix paths, and combine. Default
	// true. Set false to revert to the lean single-base behaviour from
	// earlier versions.
	PermutateProbe bool

	// Tune selects an autotune.Tier profile by name, "auto" to let the
	// host's CPU+RAM pick, or "off" to honour every CLI flag verbatim.
	// Default "auto". See internal/autotune for the tier table; --show-tune
	// dumps the resolved choice and exits without scanning.
	Tune string

	// ConcurrentTargets is how many targets the CLI loop will run in
	// parallel via errgroup. 1 = serial (legacy behaviour); higher means
	// the JSONL sink falls back to a single combined report.jsonl at
	// <OutDir>/report.jsonl and the XLSX sink refuses --xlsx-split.
	ConcurrentTargets int

	// LivenessCheck controls the pre-flight liveness sweep. "auto" turns
	// it on whenever target count > LivenessAutoThreshold; "on" forces
	// it; "off" disables it. Default "auto".
	LivenessCheck string

	// LivenessTimeout is the per-URL probe budget for the liveness sweep.
	// Default 3s — short enough to discard tens of thousands of dead
	// targets in minutes, generous enough to avoid false-negatives on
	// slow-but-alive servers.
	LivenessTimeout time.Duration

	// LivenessWorkers is the in-flight concurrency cap for the sweep.
	// Default 128.
	LivenessWorkers int

	// LivenessAutoThreshold is the target-count above which "auto" mode
	// enables the liveness sweep. Below this we skip the sweep (running
	// it for a handful of targets is more overhead than it saves).
	// Default 50.
	LivenessAutoThreshold int
}

func Default() Config {
	return Config{
		Chrome:               ChromeAuto,
		Workers:              64,
		PerHostQPS:           5.0,
		MaxDepth:             3,
		MaxBodyMB:            16,
		Timeout:              DefaultTimeout,
		TargetTimeout:        DefaultTargetTTL,
		Formats:              []Format{FormatJSONL, FormatXLSX},
		OutDir:               "results",
		LogLevel:             "info",
		UA:                   DefaultUserAgent,
		TLSFingerprint:       "chrome120",
		AncestorRecurseDepth: 2,
		ProbeFanout:          "action-aware",
		PermutateProbe:       true,
		Tune:                 "auto",
		ConcurrentTargets:    1,
		LivenessCheck:        "auto",
		LivenessTimeout:      3 * time.Second,
		LivenessWorkers:      128,
		LivenessAutoThreshold: 50,
	}
}

// Normalize fills derived fields and validates the config. Call before use.
func (c *Config) Normalize() error {
	if c.WorkersCrawl == 0 {
		c.WorkersCrawl = c.Workers
	}
	if c.WorkersProbe == 0 {
		c.WorkersProbe = c.Workers
	}
	if c.Workers <= 0 || c.WorkersCrawl <= 0 || c.WorkersProbe <= 0 {
		return fmt.Errorf("workers must be > 0")
	}
	if c.PerHostQPS <= 0 {
		return fmt.Errorf("per-host-qps must be > 0")
	}
	if c.MaxBodyMB <= 0 {
		return fmt.Errorf("max-body-mb must be > 0")
	}
	if c.UA == "" {
		c.UA = DefaultUserAgent
	}
	switch c.Chrome {
	case ChromeOff, ChromeOn, ChromeAuto, "":
		if c.Chrome == "" {
			c.Chrome = ChromeAuto
		}
	default:
		return fmt.Errorf("invalid --chrome value %q (want on|off|auto)", c.Chrome)
	}
	switch c.TLSFingerprint {
	case "":
		c.TLSFingerprint = "chrome120"
	case "chrome120", "firefox120", "safari17", "go":
	default:
		return fmt.Errorf("invalid --tls-fingerprint %q (want chrome120|firefox120|safari17|go)", c.TLSFingerprint)
	}
	if c.URL == "" && c.File == "" {
		return fmt.Errorf("either -u/--url or -f/--file is required")
	}
	if len(c.Formats) == 0 {
		c.Formats = []Format{FormatJSONL, FormatXLSX}
	}
	switch c.ProbeFanout {
	case "":
		c.ProbeFanout = "action-aware"
	case "action-aware", "conservative", "all":
	default:
		return fmt.Errorf("invalid --probe-fanout %q (want action-aware|conservative|all)", c.ProbeFanout)
	}
	if c.ConcurrentTargets <= 0 {
		c.ConcurrentTargets = 1
	}
	switch strings.ToLower(c.LivenessCheck) {
	case "":
		c.LivenessCheck = "auto"
	case "auto", "on", "off":
		c.LivenessCheck = strings.ToLower(c.LivenessCheck)
	default:
		return fmt.Errorf("invalid --liveness-check %q (want auto|on|off)", c.LivenessCheck)
	}
	if c.LivenessTimeout <= 0 {
		c.LivenessTimeout = 3 * time.Second
	}
	if c.LivenessWorkers <= 0 {
		c.LivenessWorkers = 128
	}
	if c.LivenessAutoThreshold <= 0 {
		c.LivenessAutoThreshold = 50
	}
	return nil
}

// ParseFormats turns "jsonl,xlsx" into []Format. Unknown tokens error.
func ParseFormats(s string) ([]Format, error) {
	if s == "" {
		return nil, nil
	}
	parts := strings.Split(s, ",")
	out := make([]Format, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		switch Format(p) {
		case FormatJSONL, FormatXLSX:
			out = append(out, Format(p))
		default:
			return nil, fmt.Errorf("unknown format %q (want jsonl|xlsx)", p)
		}
	}
	return out, nil
}

// MaxBodyBytes returns the configured cap in bytes.
func (c *Config) MaxBodyBytes() int64 { return int64(c.MaxBodyMB) << 20 }
