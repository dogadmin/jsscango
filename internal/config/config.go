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

	Workers       int
	WorkersCrawl  int
	WorkersProbe  int
	PerHostQPS    float64
	MaxDepth      uint8
	MaxBodyMB     int
	Timeout       time.Duration
	TargetTimeout time.Duration
	SecureTLS     bool

	RulesFile string
	Formats   []Format
	OutDir    string
	Resume    bool

	LogLevel string
	LogFile  string
	Proxy    string
	UA       string

	// PprofAddr enables a net/http/pprof listener at this address when
	// non-empty (e.g. ":6060"). Default empty = disabled.
	PprofAddr string
}

func Default() Config {
	return Config{
		Chrome:        ChromeAuto,
		Workers:       64,
		PerHostQPS:    5.0,
		MaxDepth:      3,
		MaxBodyMB:     16,
		Timeout:       DefaultTimeout,
		TargetTimeout: DefaultTargetTTL,
		Formats:       []Format{FormatJSONL, FormatXLSX},
		OutDir:        "results",
		LogLevel:      "info",
		UA:            DefaultUserAgent,
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
	if c.URL == "" && c.File == "" {
		return fmt.Errorf("either -u/--url or -f/--file is required")
	}
	if len(c.Formats) == 0 {
		c.Formats = []Format{FormatJSONL, FormatXLSX}
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
