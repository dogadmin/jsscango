// Package rules loads, compiles, and applies regex-based content rules.
// Default rules are embedded via go:embed and can be replaced by --rules.
package rules

import (
	"embed"
	"fmt"
	"os"
	"regexp"

	"gopkg.in/yaml.v3"

	"github.com/dogadmin/jsscango/internal/util/aho"
)

//go:embed embedded/rules.yaml embedded/blacktext.yaml
var defaultFS embed.FS

// Kind discriminates rule categories. Used in RuleHit.Kind and to drive
// xlsx sheet routing in the output layer.
type Kind string

const (
	KindFingerprint Kind = "fingerprint"
	KindVuln        Kind = "vuln"
	KindSensitive   Kind = "sensitive"
)

// Rule is the unified schema. Pattern compiles to *regexp.Regexp at load time.
type Rule struct {
	ID      string `yaml:"id"`
	Kind    Kind   `yaml:"kind"`
	Group   string `yaml:"group"`
	Pattern string `yaml:"pattern"`
	Enabled *bool  `yaml:"enabled"` // pointer so absence defaults to true
	Scope   string `yaml:"scope"`

	re *regexp.Regexp
}

// IsEnabled reports whether the rule should run; absence of `enabled`
// defaults to true.
func (r Rule) IsEnabled() bool { return r.Enabled == nil || *r.Enabled }

// Set is a loaded + compiled bundle of rules plus the BLACK_TEXT marker list.
type Set struct {
	Rules       []*Rule
	BlackText   []string // literal substrings (preserved for inspection)
	// Source describes where the rules YAML was loaded from. One of:
	//   "embedded"          - compiled-in default
	//   "flag:<path>"       - explicit --rules CLI flag
	//   "env:<path>"        - $JSSCANGO_RULES_PATH env override
	//   "user:<path>"       - lazily-materialized user config path
	Source      string
	blackTextAC *aho.Matcher
	compileErrs map[string]error
}

// CompileErrors returns the map of rule_id -> compile error for rules that
// failed to compile. They are silently skipped during Apply.
func (s *Set) CompileErrors() map[string]error { return s.compileErrs }

// Load builds a Set using the following precedence (highest first):
//
//  1. Explicit overridePath (the --rules CLI flag) - REPLACES the rule set.
//     A parse failure here is fatal — the user asked for this specific file.
//  2. $JSSCANGO_RULES_PATH env var - REPLACES the rule set. Same fatal
//     semantics as the flag.
//  3. The user-config rules.yaml at os.UserConfigDir()/jsscango/rules.yaml.
//     On first run this file is auto-created from the embedded defaults so
//     subsequent edits are picked up without re-running `rules dump`.
//     A parse failure here is NON-fatal — the auto-materialised file is
//     somewhere between the embedded baseline and a deliberate override,
//     and a broken edit shouldn't brick the tool. The Set returned in that
//     case has Source set to "embedded(user-fallback:<reason>)" so the
//     pipeline log surfaces what happened.
//  4. Embedded defaults compiled into the binary (final fallback).
//
// External overrides REPLACE the rule set; they do not merge.
func Load(overridePath string) (*Set, error) {
	// 1. Explicit --rules wins.
	if overridePath != "" {
		return loadFromFile(overridePath, "flag:"+overridePath)
	}
	// 2. Env override.
	if env := os.Getenv(EnvRulesPath); env != "" {
		return loadFromFile(env, "env:"+env)
	}
	// 3. User config path (best-effort auto-create on first run).
	if userPath, _, err := EnsureUserRulesFile(nil); err == nil && userPath != "" {
		if _, statErr := os.Stat(userPath); statErr == nil {
			set, err := loadFromFile(userPath, "user:"+userPath)
			if err == nil {
				return set, nil
			}
			// Parse failed — degrade to embedded so a broken hand-edit
			// doesn't brick the tool. The caller's logger will surface
			// the fallback via Set.Source.
			fb, fbErr := loadFromEmbedded()
			if fbErr != nil {
				return nil, fbErr
			}
			fb.Source = fmt.Sprintf("embedded(user-fallback: %v)", err)
			return fb, nil
		}
	}
	// 4. Embedded.
	return loadFromEmbedded()
}

// loadFromFile reads rules YAML from disk, combines it with the embedded
// blacktext.yaml, and returns a compiled Set tagged with the given source.
// Blacktext is intentionally NOT externalized; see Load doc.
func loadFromFile(path, source string) (*Set, error) {
	rulesYAML, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read rules %s: %w", path, err)
	}
	blackYAML, err := defaultFS.ReadFile("embedded/blacktext.yaml")
	if err != nil {
		return nil, err
	}
	return buildSet(rulesYAML, blackYAML, source)
}

// loadFromEmbedded uses the binary-embedded rules.yaml + blacktext.yaml.
func loadFromEmbedded() (*Set, error) {
	rulesYAML, err := defaultFS.ReadFile("embedded/rules.yaml")
	if err != nil {
		return nil, err
	}
	blackYAML, err := defaultFS.ReadFile("embedded/blacktext.yaml")
	if err != nil {
		return nil, err
	}
	return buildSet(rulesYAML, blackYAML, "embedded")
}

// buildSet parses and compiles the two YAML blobs into a ready-to-use Set.
// The source string is stored verbatim on the returned Set.
func buildSet(rulesYAML, blackYAML []byte, source string) (*Set, error) {
	var doc struct {
		Rules []*Rule `yaml:"rules"`
	}
	if err := yaml.Unmarshal(rulesYAML, &doc); err != nil {
		return nil, fmt.Errorf("parse rules.yaml: %w", err)
	}
	var bdoc struct {
		Markers []string `yaml:"markers"`
	}
	if err := yaml.Unmarshal(blackYAML, &bdoc); err != nil {
		return nil, fmt.Errorf("parse blacktext.yaml: %w", err)
	}

	set := &Set{
		BlackText:   bdoc.Markers,
		Source:      source,
		blackTextAC: aho.New(bdoc.Markers),
		compileErrs: make(map[string]error),
	}
	for _, r := range doc.Rules {
		if !r.IsEnabled() {
			continue
		}
		if r.Pattern == "" {
			set.compileErrs[r.ID] = fmt.Errorf("empty pattern")
			continue
		}
		re, err := regexp.Compile(r.Pattern)
		if err != nil {
			set.compileErrs[r.ID] = err
			continue
		}
		r.re = re
		set.Rules = append(set.Rules, r)
	}
	return set, nil
}

// Hit is one match emitted by Apply. The Matches slice carries each distinct
// captured value so callers can show concrete leaks (not just rule IDs).
type Hit struct {
	RuleID  string
	Kind    Kind
	Group   string
	Matches []string
}

// Apply runs every compiled rule against body. Returns a per-rule slice of
// matches; rules with no hits are omitted.
func (s *Set) Apply(body []byte) []Hit {
	if len(body) == 0 || s == nil {
		return nil
	}
	out := make([]Hit, 0, 4)
	for _, r := range s.Rules {
		matches := r.re.FindAll(body, -1)
		if len(matches) == 0 {
			continue
		}
		seen := make(map[string]struct{}, len(matches))
		dedup := make([]string, 0, len(matches))
		for _, m := range matches {
			s := string(m)
			if _, ok := seen[s]; ok {
				continue
			}
			seen[s] = struct{}{}
			dedup = append(dedup, s)
		}
		out = append(out, Hit{
			RuleID:  r.ID,
			Kind:    r.Kind,
			Group:   r.Group,
			Matches: dedup,
		})
	}
	return out
}

// IsBlackText reports whether body contains any literal marker from the
// BLACK_TEXT list. Backed by an Aho-Corasick matcher (one scan over body
// regardless of marker count).
func (s *Set) IsBlackText(body []byte) bool {
	if s == nil || len(body) == 0 {
		return false
	}
	return s.blackTextAC.Contains(body)
}

// Count returns the number of compiled rules per Kind, useful for startup log.
func (s *Set) Count() map[Kind]int {
	out := map[Kind]int{}
	for _, r := range s.Rules {
		out[r.Kind]++
	}
	return out
}

// EmbeddedRulesYAML returns the bytes of the default rules.yaml.
func EmbeddedRulesYAML() []byte {
	b, _ := defaultFS.ReadFile("embedded/rules.yaml")
	return b
}

// EmbeddedBlackTextYAML returns the bytes of the default blacktext.yaml.
func EmbeddedBlackTextYAML() []byte {
	b, _ := defaultFS.ReadFile("embedded/blacktext.yaml")
	return b
}

// EmbeddedFiles returns the embedded asset names with their content, keyed by
// the plain basename (no "embedded/" prefix). Callers that want to dump the
// defaults to disk can iterate this map.
func EmbeddedFiles() map[string][]byte {
	return map[string][]byte{
		"rules.yaml":     EmbeddedRulesYAML(),
		"blacktext.yaml": EmbeddedBlackTextYAML(),
	}
}
