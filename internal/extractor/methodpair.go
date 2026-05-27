package extractor

import (
	"regexp"
	"strings"
)

// MethodPair is one (url, method) declaration extracted from an axios-style
// request config. The Method is upper-cased before return so probe-stage
// comparisons can rely on a fixed shape.
type MethodPair struct {
	Path   string
	Method string // upper-cased; one of GET, POST, PUT, DELETE, PATCH, HEAD, OPTIONS
}

// httpVerbs gates the Method value so noise like method:"GET HTTP" or
// method:"something" is dropped. RE2 captures the verb as letters-only, but
// callers can still feed garbage if a future regex changes the capture group.
var httpVerbs = map[string]struct{}{
	"GET":     {},
	"POST":    {},
	"PUT":     {},
	"DELETE":  {},
	"PATCH":   {},
	"HEAD":    {},
	"OPTIONS": {},
}

// methodPairForward catches `url:"X", ... , method:"Y"`. The
// (?:[^{}]|\{[^{}]*\}){0,200}? window bounds the distance between url
// and method to ~200 characters AND keeps us within a single object
// literal — except we allow ONE level of nested `{...}` so common axios
// shapes like
//
//   {url:"/foo",headers:{"X-Auth":"bar"},params:{a:1},method:"PATCH"}
//
// (where `headers` and `params` open inner objects) still pair correctly.
// Two levels of nesting is rare in real axios configs; if it appears,
// the pair is silently dropped, which is preferable to false positives
// pairing across separate configs in the same file.
//
// The 200-iteration ceiling is conservative for the longest configs
// we've seen in minified bundles; combined with the lazy quantifier
// this matches the NEAREST method on the right of the url, which is
// what we want when several inline configs sit next to each other.
var methodPairForward = regexp.MustCompile(
	`url\s*:\s*['"]([^'"]+)['"](?:[^{}]|\{[^{}]*\}){0,200}?method\s*:\s*['"]([A-Za-z]+)['"]`,
)

// methodPairReverse catches the inverse order `method:"Y", ... , url:"X"`.
// Some minifiers reorder members alphabetically and some hand-written
// configs declare method first. The same one-level-nested window applies
// so configs like `{method:"DELETE",headers:{"X-Auth":"a"},url:"/x"}`
// still pair correctly.
var methodPairReverse = regexp.MustCompile(
	`method\s*:\s*['"]([A-Za-z]+)['"](?:[^{}]|\{[^{}]*\}){0,200}?url\s*:\s*['"]([^'"]+)['"]`,
)

// DetectMethodPairs scans body for axios-style url+method declarations.
// Returns one entry per discovered (url, method) pair, deduplicated on
// (path, method). Methods are uppercased before return; pairs whose method
// isn't in the HTTP verb set are dropped.
//
// Implementation note: we scan the body with two regexes (forward and
// reverse member order) because RE2 doesn't support the kind of either-or
// distance-bounded match we'd need to do it in one pass.
func DetectMethodPairs(body []byte) []MethodPair {
	if len(body) == 0 {
		return nil
	}
	out := make([]MethodPair, 0, 16)
	seen := make(map[string]struct{}, 16)
	add := func(path, method string) {
		method = strings.ToUpper(method)
		if _, ok := httpVerbs[method]; !ok {
			return
		}
		if path == "" {
			return
		}
		k := path + "\x00" + method
		if _, ok := seen[k]; ok {
			return
		}
		seen[k] = struct{}{}
		out = append(out, MethodPair{Path: path, Method: method})
	}

	for _, m := range methodPairForward.FindAllSubmatch(body, -1) {
		if len(m) < 3 {
			continue
		}
		add(string(m[1]), string(m[2]))
	}
	for _, m := range methodPairReverse.FindAllSubmatch(body, -1) {
		if len(m) < 3 {
			continue
		}
		add(string(m[2]), string(m[1]))
	}
	return out
}
