package probe

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// MineParameters walks every saved GET_*.txt response in dir, decodes the
// body as JSON, and pulls out candidate parameter names. Mirrors
// plugins/getParameter.py with two key behaviour changes:
//
//   - Replaces the original `eval(f.read())` (getParameter.py:96) — a remote
//     code execution risk — with `json.Unmarshal` into interface{}. The text
//     blobs that aren't valid JSON are skipped instead of being eval'd.
//   - Returns a deduplicated slice, preserving discovery order.
func MineParameters(dir string) []string {
	root := filepath.Join(dir, "response")
	entries, err := os.ReadDir(root)
	if err != nil {
		return nil
	}
	seen := make(map[string]struct{}, 32)
	var out []string
	for _, e := range entries {
		if e.IsDir() || !strings.HasPrefix(e.Name(), "GET") {
			continue
		}
		full := filepath.Join(root, e.Name())
		data, err := os.ReadFile(full)
		if err != nil {
			continue
		}
		for _, p := range extractFromBlob(data) {
			if _, ok := seen[p]; ok {
				continue
			}
			seen[p] = struct{}{}
			out = append(out, p)
		}
	}
	return out
}

// extractFromBlob tries JSON first; falls back to regex-on-text for
// error-message patterns that name a required parameter.
func extractFromBlob(b []byte) []string {
	var v interface{}
	if err := json.Unmarshal(b, &v); err == nil {
		params := walkJSON(v, 1, 2)
		params = append(params, mineMessages(string(b))...)
		return uniq(params)
	}
	// Not valid JSON — only the regex path applies. This is the safe
	// replacement for getParameter.py:96 (`eval(f.read())`).
	return uniq(mineMessages(string(b)))
}

// walkJSON walks a decoded JSON value, collecting:
//   - Values of any field literally named "param" or "parameter"
//     (getParameter.py:53).
//   - Top-level object keys at depth >= targetDepth (getParameter.py:48).
//
// targetDepth=2 lets us include keys of nested objects (which are typically
// the request schema fields), but skip the top-level wrapper like
// {"code":..., "data":{...}} from leaking "code" and "data".
func walkJSON(v interface{}, depth, targetDepth int) []string {
	var out []string
	switch x := v.(type) {
	case map[string]interface{}:
		if depth >= targetDepth {
			for k := range x {
				out = append(out, k)
			}
		}
		for k, vv := range x {
			if (k == "param" || k == "parameter") {
				if s, ok := vv.(string); ok {
					out = append(out, s)
				}
			}
			out = append(out, walkJSON(vv, depth+1, targetDepth)...)
		}
	case []interface{}:
		for _, vv := range x {
			out = append(out, walkJSON(vv, depth+1, targetDepth)...)
		}
	case string:
		out = append(out, mineMessages(x)...)
	}
	return out
}

// englishParamPatterns mirrors getParameter.py:7-31. RE2-compatible.
var englishParamPatterns = []*regexp.Regexp{
	regexp.MustCompile(`'([a-zA-Z]+)' parameter`),
	regexp.MustCompile(`"([a-zA-Z]+)" parameter`),
	regexp.MustCompile(`([a-zA-Z]+) parameter`),
	regexp.MustCompile(`\(([a-zA-Z]+)=*\) parameter`),
	regexp.MustCompile(`parameter '([a-zA-Z]+)'`),
	regexp.MustCompile(`parameter "([a-zA-Z]+)"`),
	regexp.MustCompile(`parameter ([a-zA-Z]+)`),
	regexp.MustCompile(`parameter \(([a-zA-Z]+)=*\)`),
	regexp.MustCompile(`'([a-zA-Z]+)' param`),
	regexp.MustCompile(`"([a-zA-Z]+)" param`),
	regexp.MustCompile(`([a-zA-Z]+) param`),
	regexp.MustCompile(`\(([a-zA-Z]+)=*\) param`),
	regexp.MustCompile(`param '([a-zA-Z]+)'`),
	regexp.MustCompile(`param "([a-zA-Z]+)"`),
	regexp.MustCompile(`param ([a-zA-Z]+)`),
	regexp.MustCompile(`param \(([a-zA-Z]+)=*\)`),
	regexp.MustCompile(`param\[([a-zA-Z]+)\] required`),
	regexp.MustCompile(`parameter\[([a-zA-Z]+)\] required`),
}

// chineseMarker matches Chinese phrasing around a required-parameter name.
// Equivalent to getParameter.py:34-35.
var chineseMarkerPatterns = []*regexp.Regexp{
	regexp.MustCompile(`["']?([a-zA-Z]+)["']?\s*(?:不能为空|非法的|参数)`),
	regexp.MustCompile(`(?:不能为空|非法的|参数)\s*["']?([a-zA-Z]+)["']?`),
}

func mineMessages(s string) []string {
	var out []string
	for _, re := range englishParamPatterns {
		for _, m := range re.FindAllStringSubmatch(s, -1) {
			if len(m) >= 2 && m[1] != "" {
				out = append(out, m[1])
			}
		}
	}
	for _, re := range chineseMarkerPatterns {
		for _, m := range re.FindAllStringSubmatch(s, -1) {
			if len(m) >= 2 && m[1] != "" {
				out = append(out, m[1])
			}
		}
	}
	return out
}

func uniq(in []string) []string {
	seen := make(map[string]struct{}, len(in))
	out := in[:0]
	for _, s := range in {
		if s == "" {
			continue
		}
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	return out
}
