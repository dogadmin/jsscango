// _hae_converter.go: standalone tool used by scripts/fetch_hae_rules.sh.
//
// Reads:
//   ./hae_config.yml         - downloaded HaE upstream config
//   ./existing_rules.yaml    - current internal/rules/embedded/rules.yaml
// Writes:
//   ./rules_merged.yaml      - merged + sorted output (header included)
//
// The leading underscore in the filename keeps Go's package globbing from
// trying to compile this alongside the rest of the repo. The shell script
// runs it via `go run` after setting up a throwaway module.
package main

import (
	"fmt"
	"os"
	"regexp"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// HaE schema -----------------------------------------------------------------

type haeRule struct {
	Name      string `yaml:"name"`
	Loaded    bool   `yaml:"loaded"`
	FRegex    string `yaml:"f_regex"`
	SRegex    string `yaml:"s_regex"`
	Format    string `yaml:"format"`
	Color     string `yaml:"color"`
	Scope     string `yaml:"scope"`
	Engine    string `yaml:"engine"`
	Sensitive bool   `yaml:"sensitive"`
}

type haeGroup struct {
	Group string    `yaml:"group"`
	Rule  []haeRule `yaml:"rule"`
}

type haeDoc struct {
	Rules []haeGroup `yaml:"rules"`
}

// Our schema -----------------------------------------------------------------

type ourRule struct {
	ID      string `yaml:"id"`
	Kind    string `yaml:"kind"`
	Group   string `yaml:"group,omitempty"`
	Pattern string `yaml:"pattern"`
	Enabled *bool  `yaml:"enabled,omitempty"`
	Scope   string `yaml:"scope,omitempty"`
}

type ourDoc struct {
	Rules []ourRule `yaml:"rules"`
}

// slugify normalises a HaE rule name into our id format.
func slugify(s string) string {
	s = strings.ToLower(s)
	repl := strings.NewReplacer(
		" ", "-",
		".", "-",
		"/", "-",
		"\\", "-",
		"_", "-",
	)
	s = repl.Replace(s)
	var b strings.Builder
	for _, r := range s {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-' {
			b.WriteRune(r)
		}
	}
	out := b.String()
	for strings.Contains(out, "--") {
		out = strings.ReplaceAll(out, "--", "-")
	}
	out = strings.Trim(out, "-")
	return out
}

func groupAbbrev(group string) string {
	switch group {
	case "Fingerprint":
		return "fp"
	case "Maybe Vulnerability":
		return "vuln"
	case "Basic Information":
		return "info"
	case "Sensitive Information":
		return "sec"
	case "Other":
		return "other"
	default:
		return slugify(group)
	}
}

func inferKind(group string, sensitive bool) string {
	if sensitive {
		return "sensitive"
	}
	switch group {
	case "Maybe Vulnerability":
		return "vuln"
	case "Fingerprint":
		return "fingerprint"
	case "Basic Information", "Sensitive Information":
		return "sensitive"
	case "Other":
		return "fingerprint"
	default:
		return "fingerprint"
	}
}

func convertHaE(in haeDoc) ([]ourRule, []string, []string) {
	var out []ourRule
	var warns []string
	var bad []string
	seenSlugs := map[string]int{}
	for _, g := range in.Rules {
		for _, r := range g.Rule {
			if r.FRegex == "" {
				warns = append(warns, fmt.Sprintf("skip %q in %q: empty f_regex", r.Name, g.Group))
				continue
			}
			if r.SRegex != "" {
				warns = append(warns, fmt.Sprintf("note %q in %q: s_regex dropped (2-regex chain not supported)", r.Name, g.Group))
			}
			if _, err := regexp.Compile(r.FRegex); err != nil {
				bad = append(bad, fmt.Sprintf("%s/%s: %v", g.Group, r.Name, err))
				continue
			}
			slug := slugify(r.Name)
			if slug == "" {
				warns = append(warns, fmt.Sprintf("skip %q in %q: slug is empty", r.Name, g.Group))
				continue
			}
			abbrev := groupAbbrev(g.Group)
			full := abbrev + "-" + slug
			if seenSlugs[full] > 0 {
				full = fmt.Sprintf("%s-%d", full, seenSlugs[full]+1)
			}
			seenSlugs[full]++

			var enabled *bool
			if !r.Loaded {
				v := false
				enabled = &v
			}
			out = append(out, ourRule{
				ID:      full,
				Kind:    inferKind(g.Group, r.Sensitive),
				Group:   g.Group,
				Pattern: r.FRegex,
				Enabled: enabled,
			})
		}
	}
	return out, warns, bad
}

func stripPrefix(id string) string {
	id = strings.TrimPrefix(id, "fp-")
	id = strings.TrimPrefix(id, "vuln-")
	id = strings.TrimPrefix(id, "sec-")
	id = strings.TrimPrefix(id, "info-")
	id = strings.TrimPrefix(id, "other-")
	return id
}

func matchesOurRule(ours ourRule, hae []ourRule) bool {
	ourSlug := stripPrefix(ours.ID)
	for _, h := range hae {
		if stripPrefix(h.ID) == ourSlug {
			return true
		}
		if strings.TrimSpace(h.Pattern) == strings.TrimSpace(ours.Pattern) {
			return true
		}
	}
	idAliases := map[string]string{
		"shiro":                "shiro",
		"jwt_token":            "json-web-token",
		"swagger_ui":           "swagger-ui",
		"ueditor":              "ueditor",
		"druid":                "druid",
		"java_deserialization": "java-deserialization",
		"debug_logic_params":   "debug-logic-parameters",
		"url_as_value":         "url-as-a-value",
		"upload_form":          "upload-form",
		"chinese_idcard":       "chinese-idcard",
		"chinese_mobile":       "chinese-mobile-number",
		"internal_ip":          "internal-ip-address",
		"mac_address":          "mac-address",
		"jdbc_connection":      "jdbc-connection",
		"wecom_key":            "wecom-key",
		"username_field":       "username-field",
		"password_field":       "password-field",
		"sensitive_field":      "sensitive-field",
		"sourcemap_ref":        "source-map",
	}
	if alias, ok := idAliases[ours.ID]; ok {
		for _, h := range hae {
			if stripPrefix(h.ID) == alias {
				return true
			}
		}
	}
	return false
}

func main() {
	haeBytes, err := os.ReadFile("hae_config.yml")
	if err != nil {
		fmt.Fprintf(os.Stderr, "read hae_config.yml: %v\n", err)
		os.Exit(1)
	}
	var hae haeDoc
	if err := yaml.Unmarshal(haeBytes, &hae); err != nil {
		fmt.Fprintf(os.Stderr, "parse hae_config.yml: %v\n", err)
		os.Exit(1)
	}
	haeConverted, warns, bad := convertHaE(hae)
	fmt.Fprintf(os.Stderr, "HaE: parsed %d groups, produced %d rules\n", len(hae.Rules), len(haeConverted))
	for _, w := range warns {
		fmt.Fprintln(os.Stderr, "  warn:", w)
	}
	for _, b := range bad {
		fmt.Fprintln(os.Stderr, "  BAD :", b)
	}

	oursBytes, err := os.ReadFile("existing_rules.yaml")
	if err != nil {
		fmt.Fprintf(os.Stderr, "read existing_rules.yaml: %v\n", err)
		os.Exit(1)
	}
	var ours ourDoc
	if err := yaml.Unmarshal(oursBytes, &ours); err != nil {
		fmt.Fprintf(os.Stderr, "parse existing_rules.yaml: %v\n", err)
		os.Exit(1)
	}
	fmt.Fprintf(os.Stderr, "Ours: %d rules loaded\n", len(ours.Rules))

	var merged []ourRule
	merged = append(merged, haeConverted...)
	keptFromOurs := 0
	for _, our := range ours.Rules {
		if !matchesOurRule(our, haeConverted) {
			merged = append(merged, our)
			keptFromOurs++
		}
	}
	fmt.Fprintf(os.Stderr, "Kept %d of %d existing rules (the rest were superseded by HaE)\n", keptFromOurs, len(ours.Rules))

	dropped := 0
	cleaned := merged[:0]
	for _, r := range merged {
		if strings.TrimSpace(r.ID) == "" || strings.TrimSpace(r.Pattern) == "" {
			dropped++
			continue
		}
		cleaned = append(cleaned, r)
	}
	if dropped > 0 {
		fmt.Fprintf(os.Stderr, "Dropped %d malformed entries (empty id or pattern)\n", dropped)
	}

	sort.SliceStable(cleaned, func(i, j int) bool {
		if cleaned[i].Group != cleaned[j].Group {
			return cleaned[i].Group < cleaned[j].Group
		}
		return cleaned[i].ID < cleaned[j].ID
	})

	seen := map[string]int{}
	final := make([]ourRule, 0, len(cleaned))
	for _, r := range cleaned {
		if _, ok := seen[r.ID]; ok {
			fmt.Fprintf(os.Stderr, "dedupe: drop duplicate id %q\n", r.ID)
			continue
		}
		seen[r.ID] = 1
		final = append(final, r)
	}
	fmt.Fprintf(os.Stderr, "Final merged set: %d rules\n", len(final))

	out := ourDoc{Rules: final}
	var buf strings.Builder
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(2)
	if err := enc.Encode(out); err != nil {
		fmt.Fprintf(os.Stderr, "marshal: %v\n", err)
		os.Exit(1)
	}
	enc.Close()
	body := []byte(buf.String())

	header := `# jsscango unified rule set, v0.4.0+
#
# Schema:
#   - id:       short stable identifier (used in RuleHit.RuleID)
#     kind:     fingerprint | vuln | sensitive
#     group:    grouping label for reports (optional)
#     pattern:  RE2 regex (https://github.com/google/re2/wiki/Syntax)
#     enabled:  default true; set false to skip
#     scope:    body | header | any (advisory, currently always treated as "any")
#
# Sources:
#   - jsscango originals (framework discovery, Phase 4 extras)
#   - HaE Config.yml, upstream:
#     https://github.com/gh0stkey/HaE
#     src/HaENet/src/main/resources/rules/Rules.yml
#
# To regenerate: run scripts/fetch_hae_rules.sh.
# To override at runtime: --rules path/to/your.yaml

`
	if err := os.WriteFile("rules_merged.yaml", append([]byte(header), body...), 0o644); err != nil {
		fmt.Fprintf(os.Stderr, "write rules_merged.yaml: %v\n", err)
		os.Exit(1)
	}
	fmt.Fprintln(os.Stderr, "wrote rules_merged.yaml")
}
