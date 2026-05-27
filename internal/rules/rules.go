// Package rules loads, compiles, and applies regex-based content rules.
// Default rules are embedded via go:embed and can be replaced by --rules.
package rules

import (
	"embed"
	"fmt"
	"os"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
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
	BlackText   []string // literal substrings for fast Contains check
	compileErrs map[string]error
}

// CompileErrors returns the map of rule_id -> compile error for rules that
// failed to compile. They are silently skipped during Apply.
func (s *Set) CompileErrors() map[string]error { return s.compileErrs }

// Load builds a Set from embedded defaults, optionally replaced by an
// external YAML file at overridePath (empty = use defaults).
//
// External overrides REPLACE the rule set; they do not merge. This is the
// behaviour confirmed during planning ("--rules is replacement not merge").
func Load(overridePath string) (*Set, error) {
	var rulesYAML, blackYAML []byte
	var err error
	if overridePath != "" {
		rulesYAML, err = os.ReadFile(overridePath)
		if err != nil {
			return nil, fmt.Errorf("read --rules: %w", err)
		}
		// Black text always comes from embedded; users override regex rules
		// but they don't usually want to tweak BLACK_TEXT and there's no
		// schema collision risk this way.
		blackYAML, err = defaultFS.ReadFile("embedded/blacktext.yaml")
		if err != nil {
			return nil, err
		}
	} else {
		if rulesYAML, err = defaultFS.ReadFile("embedded/rules.yaml"); err != nil {
			return nil, err
		}
		if blackYAML, err = defaultFS.ReadFile("embedded/blacktext.yaml"); err != nil {
			return nil, err
		}
	}

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
// BLACK_TEXT list. Phase 4 will swap this linear scan for Aho-Corasick.
func (s *Set) IsBlackText(body []byte) bool {
	if len(body) == 0 || s == nil {
		return false
	}
	bs := string(body) // small bodies are typical; large ones are bounded by --max-body-mb
	for _, m := range s.BlackText {
		if strings.Contains(bs, m) {
			return true
		}
	}
	return false
}

// Count returns the number of compiled rules per Kind, useful for startup log.
func (s *Set) Count() map[Kind]int {
	out := map[Kind]int{}
	for _, r := range s.Rules {
		out[r.Kind]++
	}
	return out
}
