package pipeline

import (
	"net/url"
	"strings"

	"github.com/dogadmin/jsscango/internal/probe"
	"github.com/dogadmin/jsscango/internal/types"
	"github.com/dogadmin/jsscango/internal/util"
)

// permutateMaxURLLen is the upper bound on a single permuted URL. RFC 7230
// does not mandate a limit but 2048 is the de facto cap for sane clients/
// servers; anything over that is almost certainly a cartesian artefact and
// would 414/400 anyway.
const permutateMaxURLLen = 2048

// PermutateTargets reproduces the Python filter_data() Cartesian URL
// derivation in getJsUrl.py:119.
//
// Step summary:
//
//  1. From `discovered` (KindNoJS only, same-baseDomain only) derive three
//     sets — tree_urls (scheme://host), base_urls (truncation inference
//     where a seed's path contains an extracted apiPath as a substring),
//     and path_with_api_urls (when a seed's path contains "api/").
//
//  2. From `apiPaths` split each path into path_with_api_paths (the
//     "/{before}api" prefix half when the path contains "api/") and
//     path_with_no_api_paths (the "/{after}" half OR the full path when
//     no "api/" is present).
//
//  3. If path_with_api_paths is empty AND isSingleTarget is true, append
//     "/api" as a fallback. We deliberately tighten the Python behaviour
//     here: -f batches multiply across N targets, so the unconditional
//     fallback in Python would blow up traffic for no real gain.
//
//  4. Cartesian product: (base_urls ∪ tree_urls) × path_with_api_paths,
//     then × path_with_no_api_paths. Same-baseDomain filter, length cap,
//     dedupe against the input apiPaths set and against probe.Target URLs
//     produced earlier.
//
// Note: the Python self_api_path constant (a list of short tokens like
// "add", "ls", "0", "1", "to") was intentionally skipped here. Half of
// the list duplicates the well-known endpoints already covered by the
// crawler stage; the other half (single-letter / single-digit tokens)
// generates huge cartesian noise for negligible coverage.
func PermutateTargets(
	target types.Target,
	discovered []types.DiscoveredURL,
	apiPaths []string,
	apiMethodHints map[string]string,
	isSingleTarget bool,
) []probe.Target {
	if target.BaseDomain == "" {
		return nil
	}
	// Dedup helpers across the entire function.
	emittedURL := make(map[string]struct{})
	// Skip URLs that are already in the input apiPaths set (those were
	// produced by buildProbeTargets); we don't want to re-emit them.
	priorPaths := make(map[string]struct{}, len(apiPaths))
	for _, p := range apiPaths {
		priorPaths[p] = struct{}{}
	}

	// --- §A/§B/§C: derive tree_urls / base_urls / path_with_api_urls -----
	treeURLs := newOrderedStringSet()
	baseURLs := newOrderedStringSet()
	pathWithAPIURLs := newOrderedStringSet()

	for _, d := range discovered {
		if d.Kind != types.KindNoJS {
			continue
		}
		raw := d.URL
		if !util.SameSiteOrIP(raw, target.BaseDomain) {
			continue
		}
		u, err := url.Parse(raw)
		if err != nil || u.Host == "" {
			continue
		}
		treeURL := u.Scheme + "://" + u.Host
		// §A: every same-domain no_js URL contributes its scheme://host.
		treeURLs.add(treeURL)

		// Homepage URLs ("/" or empty path) contribute the tree_url only.
		if u.Path == "" || u.Path == "/" {
			continue
		}

		// §C: path contains "api/" — truncate at the position right after
		// "api". https://x.com/prod-api/auth/login -> https://x.com/prod-api
		if idx := strings.Index(u.Path, "api/"); idx != -1 {
			withAPI := treeURL + u.Path[:idx] + "api"
			pathWithAPIURLs.add(withAPI)
			// And the parent of `withAPI` becomes a base_url candidate
			// (Python: base_url = path_with_api_url.rsplit('/', 1)[0]).
			if i := strings.LastIndexByte(withAPI, '/'); i > len(u.Scheme)+3 {
				parent := strings.TrimRight(withAPI[:i], "/")
				// urlparse(base_url).path must be non-empty (Python check):
				// drops cases where the parent equals just scheme://host.
				if pu, err := url.Parse(parent); err == nil && pu.Path != "" {
					baseURLs.add(parent)
				}
			}
			continue
		}

		// §B: truncation inference — for each extracted apiPath, if the
		// seed's URL path contains it as a substring, the prefix becomes
		// a base_url. Skip the Python "skip" conditions: empty/`/`, http*,
		// length <= 2, equals the full seed path.
		for _, api := range apiPaths {
			if api == "" || api == "/" || len(api) <= 2 {
				continue
			}
			if strings.HasPrefix(api, "http") {
				continue
			}
			if u.Path == api {
				continue
			}
			idx := strings.Index(u.Path, api)
			if idx == -1 {
				continue
			}
			candidate := strings.TrimRight(treeURL+u.Path[:idx], "/")
			// urlparse(base_url).path must be non-empty.
			if pu, perr := url.Parse(candidate); perr == nil && pu.Path != "" {
				baseURLs.add(candidate)
			}
		}
	}

	// --- §D/§E: split extracted api_paths --------------------------------
	pathWithAPIPaths := newOrderedStringSet()
	pathWithNoAPIPaths := newOrderedStringSet()
	// originHints maps the synthesised post-`api/` path back to the raw
	// extractor path (the key in apiMethodHints) so method hints survive
	// the split + cartesian.
	originHints := make(map[string]string)
	for _, api := range apiPaths {
		if api == "" || api == "/" || len(api) <= 2 {
			continue
		}
		if strings.HasPrefix(api, "http") {
			continue
		}
		if idx := strings.Index(api, "api/"); idx != -1 {
			// /{before}api → path_with_api_paths
			before := strings.TrimLeft(api[:idx], "/")
			withAPI := "/" + before + "api"
			pathWithAPIPaths.add(withAPI)
			// /{after} → path_with_no_api_paths. The leading slash is
			// added unconditionally so all permuted suffixes start with "/".
			after := api[idx+4:] // skip "api/"
			afterPath := "/" + after
			pathWithNoAPIPaths.add(afterPath)
			if _, ok := apiMethodHints[api]; ok {
				originHints[afterPath] = api
			}
		} else {
			withNoAPI := "/" + strings.TrimLeft(api, "/")
			pathWithNoAPIPaths.add(withNoAPI)
			if _, ok := apiMethodHints[api]; ok {
				originHints[withNoAPI] = api
			}
		}
	}
	// Python: append the path portion of each path_with_api_url back into
	// path_with_api_paths so the cartesian also covers the "/{...}api"
	// derived from no_js URLs.
	for _, pa := range pathWithAPIURLs.items() {
		if pu, err := url.Parse(pa); err == nil && pu.Path != "" {
			pathWithAPIPaths.add("/" + strings.TrimLeft(pu.Path, "/"))
		}
	}
	// §F: /api fallback — single-target mode only.
	fallbackOnly := false
	if pathWithAPIPaths.len() == 0 {
		if isSingleTarget {
			pathWithAPIPaths.add("/api")
			fallbackOnly = true
		} else {
			// In batch mode with no api-prefix evidence we cannot multiply
			// safely — emit nothing rather than spray /api across N hosts.
			return nil
		}
	}

	// --- §G: cartesian assembly ------------------------------------------
	// First level: (base_urls ∪ tree_urls) × path_with_api_paths.
	// In Python's special case `path_with_api_paths == ['/api']` (fallback),
	// each base is also added alone (without "/api") as a candidate. Even
	// when not a fallback, treeURLs and baseURLs themselves are already
	// scheme://host[/path]; we don't emit them directly because the probe
	// stage would just be hitting the homepage.
	bases := newOrderedStringSet()
	for _, v := range baseURLs.items() {
		bases.add(v)
	}
	for _, v := range treeURLs.items() {
		bases.add(v)
	}
	allPathWithAPIURLs := newOrderedStringSet()
	for _, b := range bases.items() {
		if fallbackOnly {
			// Python: when fallback ['/api'], also push the bare base.
			// We still skip homepage-equivalents downstream.
			allPathWithAPIURLs.add(b)
		}
		for _, p := range pathWithAPIPaths.items() {
			allPathWithAPIURLs.add(b + p)
		}
	}

	// Second level: × path_with_no_api_paths. self_api_path is omitted —
	// see the package doc comment for why.
	var out []probe.Target
	addTarget := func(u string, methods []string) {
		if u == "" || len(u) > permutateMaxURLLen {
			return
		}
		// Collapse any accidental `//` runs in the path (preserving the
		// scheme's `://`).
		u = collapseDoubleSlash(u)
		// Drop URLs that equal a probe.Target the primary pass already
		// would have produced (path is just "/" or empty post-collapse).
		pu, err := url.Parse(u)
		if err != nil || pu.Host == "" {
			return
		}
		if pu.Path == "" || pu.Path == "/" {
			return
		}
		if !util.SameSiteOrIP(u, target.BaseDomain) {
			return
		}
		if _, seen := emittedURL[u]; seen {
			return
		}
		// Dedup against the raw apiPaths input — if a permuted URL is
		// equal to an extracted path (e.g. `/auth/login` permuted onto a
		// base produced the same string the extractor emitted as a full
		// URL), skip it. priorPaths is checked against the original
		// extractor strings, not the permuted ones; the cheap correct
		// check here is "did the primary buildProbeTargets already cover
		// this exact URL?". The caller dedups across primary+permuted,
		// so this guard is best-effort: skip when the URL equals one of
		// the input apiPaths verbatim.
		if _, ok := priorPaths[u]; ok {
			return
		}
		emittedURL[u] = struct{}{}
		out = append(out, probe.Target{
			URL:     u,
			Methods: append([]string(nil), methods...),
			Source:  "permutate",
		})
	}

	for _, b := range allPathWithAPIURLs.items() {
		for _, p := range pathWithNoAPIPaths.items() {
			full := b + p
			var methods []string
			if origin, ok := originHints[p]; ok {
				if hint := apiMethodHints[origin]; hint != "" {
					methods = []string{hint}
				}
			}
			addTarget(full, methods)
		}
	}
	return out
}

// dedupTargets keeps the first occurrence of each URL and preserves that
// occurrence's Methods (no merging of mismatched hints). The probe.Prober
// already dedupes via state.Seen, but dedup upstream is cheaper.
func dedupTargets(targets []probe.Target) []probe.Target {
	seen := make(map[string]struct{}, len(targets))
	out := make([]probe.Target, 0, len(targets))
	for _, t := range targets {
		if t.URL == "" {
			continue
		}
		if _, ok := seen[t.URL]; ok {
			continue
		}
		seen[t.URL] = struct{}{}
		out = append(out, t)
	}
	return out
}

// collapseDoubleSlash collapses runs of '/' in the path component to a
// single '/'. The scheme separator `://` is preserved.
func collapseDoubleSlash(rawURL string) string {
	// Find the position after "scheme://".
	i := strings.Index(rawURL, "://")
	if i == -1 {
		return rawURL
	}
	prefix := rawURL[:i+3]
	rest := rawURL[i+3:]
	// In `rest`, the first '/' starts the path. Compact consecutive '/'s.
	var b strings.Builder
	b.Grow(len(rest))
	prevSlash := false
	for j := 0; j < len(rest); j++ {
		c := rest[j]
		if c == '/' {
			if prevSlash {
				continue
			}
			prevSlash = true
		} else {
			prevSlash = false
		}
		b.WriteByte(c)
	}
	return prefix + b.String()
}

// orderedStringSet preserves insertion order so tests (and log output)
// are deterministic.
type orderedStringSet struct {
	idx map[string]int
	arr []string
}

func newOrderedStringSet() *orderedStringSet {
	return &orderedStringSet{idx: make(map[string]int)}
}

func (s *orderedStringSet) add(v string) {
	if v == "" {
		return
	}
	if _, ok := s.idx[v]; ok {
		return
	}
	s.idx[v] = len(s.arr)
	s.arr = append(s.arr, v)
}

func (s *orderedStringSet) items() []string { return s.arr }
func (s *orderedStringSet) len() int        { return len(s.arr) }
