package extractor

import (
	"encoding/json"
	"net/url"
	"strconv"
	"strings"
)

// Found is one classified candidate emitted by the extractor.
type Found struct {
	Kind    string // "js" | "static" | "api" | "frontend_route" | "webpack"
	Value   string // cleaned URL or path candidate
	Pattern string // pattern ID, debug aid
	// Method is the HTTP verb attached to this Found when the source body
	// declared one via an axios-style url+method config (see methodpair.go).
	// Empty for Found values that did not come from such a pair, in which
	// case the probe stage falls back to its three-method fan-out.
	Method string `json:",omitempty"`
}

// FromJSBody scans body and emits JS URLs, static URLs, webpack chunks,
// and API path candidates.
//
// Phase 5: this calls into a single union-regex scan (union.go) plus the
// webpack chunk extractor (which is a structurally different pattern that
// doesn't fit the union form). Bodies larger than StreamThreshold are
// scanned chunk-by-chunk with overlap; smaller bodies are scanned whole.
//
// Pattern order is preserved by the union builder so framework-specific
// IDs win dedup over generic ones - see union.go:buildUnion for the
// alternative ordering.
func FromJSBody(body []byte) []Found {
	if len(body) == 0 {
		return nil
	}
	out := make([]Found, 0, 64)

	// Framework hints: detect any axios baseURL declaration and any
	// url+method config pairs FIRST. The baseURL gates how relative API
	// paths are resolved (we prepend it so `/auth/login` under a
	// `baseURL:"/api"` instance becomes `/api/auth/login`); method pairs
	// let the probe stage skip the three-method fan-out for endpoints that
	// declared their verb in the source.
	baseURLs := DetectBaseURLs(body)
	var baseURL string
	if len(baseURLs) > 0 {
		baseURL = baseURLs[0]
	}
	methodMap := make(map[string]string)
	for _, p := range DetectMethodPairs(body) {
		methodMap[p.Path] = p.Method
	}
	// Vue Router / SPA route declarations look identical to API paths to
	// the generic api scan (api_4: `path:"…"`). We detect them up-front so
	// the post-processing loop can reclassify any matching api Found into
	// kind=frontend_route BEFORE the baseURL prefix would otherwise paint
	// "/api/" over a frontend route. Without this, a target whose JS
	// declares both `baseURL:"/api"` and `{path:"/leaveForm", component:…}`
	// would have us probe https://target/api/leaveForm — a wrong-namespace
	// 404 that pollutes the probe output. Routes that the api scan didn't
	// pick up (relative `children:` paths, edge-case shapes) are appended
	// as separate Found entries after the loop.
	routes := DetectRoutes(body)
	routeSet := RoutePathSet(routes)

	// Webpack chunks need a body-spanning regex (`(?s).*`) and don't fit
	// the union form. Scanned separately on the whole body when small;
	// for bodies over StreamThreshold we skip it entirely because the
	// `string(body)` conversion would allocate a full copy and defeat
	// the chunked-streaming path. The webpack runtime expression rarely
	// exceeds 1 MiB, so this gate is a no-op in practice; if a target
	// genuinely has a webpack runtime inside a > StreamThreshold body,
	// edit StreamThreshold (a const in union.go) and rebuild.
	if len(body) <= StreamThreshold {
		for _, chunk := range webpackChunks(string(body)) {
			out = append(out, Found{Kind: "js", Value: chunk, Pattern: "webpack_chunk"})
		}
	}

	out = append(out, unionScanChunked(body)...)

	// Recover JS-kind emissions that the union's leftmost-first semantics
	// lose. When an api pattern (e.g. api_4: `path:"…"`) starts earlier
	// than the generic js_1 pattern, the api alternative wins and the
	// match is classified as api. The legacy per-pattern scanner also
	// emitted these matches as kind=js because js_1 ran independently;
	// we restore that emission for any api/static value whose suffix is
	// .js, .mjs, or .cjs (Nuxt 3 uses .mjs; some bundlers emit .cjs) so
	// the crawler still recurses into the JS file.
	out = backfillJSKind(out)

	// Framework post-processing in three phases:
	//
	//  1. Reclassify any api Found whose Value matches a Vue Router route
	//     into kind=frontend_route. This MUST run before the baseURL prefix
	//     and method attachment — a frontend route is not an API endpoint,
	//     so it shouldn't carry an HTTP verb hint and shouldn't get
	//     `/api/` painted over it. We also normalise the leading slash on
	//     the route value so downstream lookups (xlsx sheet, pipeline
	//     dispatch) see a single canonical form.
	//  2. Apply the detected baseURL and attach declared methods to the
	//     remaining api Founds. Order matters here too — the method map is
	//     keyed by the ORIGINAL (pre-baseURL-prefix) path, since that's how
	//     it appears in the source, so we look up the method first, THEN
	//     rewrite the Value with the baseURL prefix.
	//  3. Append a frontend_route Found for every detected route that the
	//     api scan didn't pick up. The api scan only emits paths that match
	//     api_4's `path:"…"` shape; relative `children:` entries like
	//     `path:"sub"` typically don't get an api hit and would otherwise
	//     be lost.
	existingRouteValues := make(map[string]bool, len(routes))
	for i := range out {
		if out[i].Kind != "api" {
			continue
		}
		origVal := out[i].Value
		normalised := origVal
		if !strings.HasPrefix(normalised, "/") {
			normalised = "/" + normalised
		}
		if _, isRoute := routeSet[normalised]; isRoute {
			out[i].Kind = "frontend_route"
			out[i].Value = normalised
			// Do NOT apply baseURL; do NOT attach method. Frontend routes
			// are not probed — they get handed off to chromedp navigation
			// in a later stage.
			existingRouteValues[normalised] = true
			continue
		}
		if method, ok := methodMap[origVal]; ok {
			out[i].Method = method
		}
		if baseURL != "" {
			out[i].Value = applyBaseURL(baseURL, origVal)
		}
	}
	for _, r := range routes {
		normalised := r.Path
		if !strings.HasPrefix(normalised, "/") {
			normalised = "/" + normalised
		}
		if existingRouteValues[normalised] {
			continue
		}
		existingRouteValues[normalised] = true
		out = append(out, Found{
			Kind:    "frontend_route",
			Value:   normalised,
			Pattern: "vue_router_route",
		})
	}

	return dedupFound(out)
}

// applyBaseURL prefixes an api path with the detected baseURL, unless the
// path is absolute (http:// / https://) or already starts with the baseURL.
// Behavior:
//   - "http(s)://..." -> unchanged (full URLs aren't mount-relative)
//   - value already starts with baseURL -> unchanged (idempotent)
//   - relative ("foo/bar") -> baseURL + "/" + value (with slash joining)
//   - absolute path ("/foo/bar") -> baseURL + value
//
// The detected baseURL is taken verbatim from the source; we don't try to
// validate it against the target's scheme/host because the extractor is
// host-agnostic. Downstream (pipeline.buildProbeURLs) joins it onto the
// target's scheme://host as it does for any other path-only value.
func applyBaseURL(baseURL, value string) string {
	if value == "" {
		return value
	}
	if strings.HasPrefix(value, "http://") || strings.HasPrefix(value, "https://") {
		return value
	}
	// Idempotency: if the value is already mounted under the baseURL, do
	// nothing. The prefix check uses trailing-slash-aware compare so
	// "/api" matches "/api/foo" but not "/apiv2".
	trimmedBase := strings.TrimRight(baseURL, "/")
	if trimmedBase != "" && (value == trimmedBase ||
		strings.HasPrefix(value, trimmedBase+"/") ||
		strings.HasPrefix(value, trimmedBase+"?")) {
		return value
	}
	if strings.HasPrefix(value, "/") {
		return trimmedBase + value
	}
	// Relative path — join with a slash. If baseURL is empty after the
	// trim (e.g. baseURL was literally "/"), fall through to the absolute
	// shape so we don't emit "foo/bar" with no leading slash.
	if trimmedBase == "" {
		return "/" + value
	}
	return trimmedBase + "/" + value
}

// backfillJSKind appends a synthetic Found{Kind:"js", ...} for any api or
// static result whose Value ends in ".js", ".mjs", or ".cjs" and isn't
// already emitted with kind=js. Nuxt 3 chunks use .mjs and some bundlers
// emit .cjs; both should still be classified as JS so the crawler recurses
// into them. The pattern ID is preserved so diagnostics still attribute
// the match to its original source.
func backfillJSKind(in []Found) []Found {
	existing := make(map[string]struct{}, len(in))
	for _, f := range in {
		if f.Kind == "js" {
			existing[f.Value] = struct{}{}
		}
	}
	for _, f := range in {
		if f.Kind == "js" {
			continue
		}
		if !strings.HasSuffix(f.Value, ".js") &&
			!strings.HasSuffix(f.Value, ".mjs") &&
			!strings.HasSuffix(f.Value, ".cjs") {
			continue
		}
		if _, ok := existing[f.Value]; ok {
			continue
		}
		existing[f.Value] = struct{}{}
		in = append(in, Found{Kind: "js", Value: f.Value, Pattern: f.Pattern})
	}
	return in
}

// jsFilter mirrors jsAndStaticUrlFind.py:14-35. Replaces escapes, strips
// quotes, drops domain-blacklisted candidates.
func jsFilter(s string) (string, bool) {
	s = strings.ReplaceAll(s, `\/`, "/")
	s = strings.ReplaceAll(s, " ", "")
	s = strings.ReplaceAll(s, `"`, "")
	s = strings.ReplaceAll(s, `'`, "")
	s = strings.ReplaceAll(s, "./", "/")
	s = strings.ReplaceAll(s, "%3A", ":")
	s = strings.ReplaceAll(s, "%2F", "/")
	s = strings.ReplaceAll(s, `\\`, "")
	s = strings.TrimRight(s, `\`)
	s = strings.TrimLeft(s, "=")
	for _, bl := range DomainBlacklist {
		if strings.Contains(s, bl) {
			return "", false
		}
	}
	if s == "" {
		return "", false
	}
	return s, true
}

// staticFilter mirrors staticUrlFilter at jsAndStaticUrlFind.py:38-50.
// In addition to the Python checks, it drops candidates whose host matches
// DomainBlacklist — the Python equivalent happens in the caller via a
// target-domain compare which the extractor cannot do statelessly.
func staticFilter(s string) (string, bool) {
	s = strings.TrimSpace(s)
	s = strings.Trim(s, `"'`)
	s = strings.TrimRight(s, "/")
	if len(s) < 3 ||
		strings.HasSuffix(s, ".js") ||
		strings.HasSuffix(s, ".mjs") ||
		strings.HasSuffix(s, ".cjs") {
		return "", false
	}
	low := strings.ToLower(s)
	for _, ext := range StaticFileExtBlacklist {
		if strings.Contains(low, ext) {
			return "", false
		}
	}
	for _, bl := range DomainBlacklist {
		if strings.Contains(s, bl) {
			return "", false
		}
	}
	return s, true
}

// apiURLFilter mirrors urlFilter at apiPathFind.py:276-313. Also runs the
// new false-positive predicates from §7 of the plan.
func apiURLFilter(s string) (string, bool) {
	if s == "" {
		return "", false
	}
	if ContainsMIMELike(s) {
		return "", false
	}
	stripped := strings.Trim(s, `"'`)
	stripped = strings.TrimLeft(stripped, "/")
	for _, bad := range APIRootBlacklistSpider {
		if strings.HasPrefix(stripped, bad) {
			return "", false
		}
	}
	s = strings.ReplaceAll(s, " ", "")
	s = strings.ReplaceAll(s, `\/`, "/")
	s = strings.ReplaceAll(s, `"`, "")
	s = strings.ReplaceAll(s, `'`, "")
	s = strings.Replace(s, `href="`, "", 1)
	s = strings.Replace(s, `href='`, "", 1)
	s = strings.ReplaceAll(s, "%3A", ":")
	s = strings.ReplaceAll(s, "%2F", "/")
	s = strings.ReplaceAll(s, `\\`, "")
	s = strings.TrimRight(s, `\`)
	s = strings.TrimLeft(s, "=")
	if strings.HasPrefix(s, "href=") {
		s = s[5:]
	}
	if s == "href" || s == "" {
		return "", false
	}
	if urlSubstrMatcher.ContainsString(s) {
		return "", false
	}
	base := s
	if i := strings.IndexByte(s, '?'); i >= 0 {
		base = s[:i]
	}
	lowBase := strings.ToLower(base)
	for _, ext := range FileExtBlacklist {
		if strings.HasSuffix(lowBase, ext) {
			return "", false
		}
	}
	// Compute the api_path component: strip scheme/host, keep path?query.
	path := s
	if strings.Contains(s, "://") {
		if u, err := url.Parse(s); err == nil {
			path = u.Path
			if u.RawQuery != "" {
				path += "?" + u.RawQuery
			}
		}
	}
	if path == "" {
		return "", false
	}
	if isCSSClassName(path) || isI18nKey(path) || isWebpackSymbol(path) {
		return "", false
	}
	if !hasReasonableSegments(path) {
		return "", false
	}
	return path, true
}

// strip is a tight wrapper for the common "trim quotes/whitespace, strip
// trailing slash" pattern that appears at apiPathFind.py:383.
func strip(s string) string {
	s = strings.TrimSpace(s)
	s = strings.Trim(s, "\"'")
	return strings.TrimRight(s, "/")
}

func dedupFound(in []Found) []Found {
	seen := make(map[string]struct{}, len(in))
	out := in[:0]
	for _, f := range in {
		k := f.Kind + "\x00" + f.Value
		if _, ok := seen[k]; ok {
			continue
		}
		seen[k] = struct{}{}
		out = append(out, f)
	}
	return out
}

// webpackChunks builds chunk URLs by parsing a webpack runtime. Mirrors
// webpack_js_find at jsAndStaticUrlFind.py:71-97.
func webpackChunks(text string) []string {
	m := webpackPathRe.FindStringSubmatch(text)
	if len(m) < 3 {
		return nil
	}
	base := m[1]
	mapping := m[2]

	pairs := strings.Split(mapping, ",")
	formatted := make([]string, 0, len(pairs))
	for _, p := range pairs {
		k, v, ok := splitOnce(p, ':')
		if !ok {
			continue
		}
		k = strings.TrimSpace(k)
		v = strings.TrimSpace(v)
		if !strings.HasPrefix(k, `"`) || !strings.HasPrefix(v, `"`) {
			continue
		}
		formatted = append(formatted, k+":"+v)
	}
	if len(formatted) == 0 {
		return nil
	}
	var chunkMap map[string]string
	if err := json.Unmarshal([]byte("{"+strings.Join(formatted, ",")+"}"), &chunkMap); err != nil {
		return nil
	}
	out := make([]string, 0, len(chunkMap))
	for k, v := range chunkMap {
		out = append(out, "/"+base+k+"."+v+".js")
	}
	return out
}

func splitOnce(s string, sep byte) (string, string, bool) {
	i := strings.IndexByte(s, sep)
	if i < 0 {
		return "", "", false
	}
	return s[:i], s[i+1:], true
}

// False-positive predicates — §7 of the plan.

func isCSSClassName(s string) bool {
	if len(s) >= 30 || strings.Contains(s, "/") {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z',
			c >= '0' && c <= '9' && i > 0,
			c == '-' && i > 0:
		default:
			return false
		}
	}
	return len(s) > 0
}

func isI18nKey(s string) bool {
	if strings.Contains(s, "/") || strings.Contains(s, "?") {
		return false
	}
	if strings.Count(s, ".") < 2 {
		return false
	}
	for _, part := range strings.Split(s, ".") {
		if part == "" {
			return false
		}
		for _, c := range part {
			if !(c >= 'a' && c <= 'z') && !(c >= 'A' && c <= 'Z') {
				return false
			}
		}
	}
	return true
}

func isWebpackSymbol(s string) bool {
	if strings.Contains(s, "__webpack_") {
		return true
	}
	if len(s) < 2 || s[0] != '_' {
		return false
	}
	i := 0
	for i < len(s) && s[i] == '_' {
		i++
	}
	if i == 0 {
		return false
	}
	for ; i < len(s); i++ {
		c := s[i]
		if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')) {
			return false
		}
	}
	return true
}

// hasReasonableSegments enforces the structural sanity checks from §7.
func hasReasonableSegments(path string) bool {
	bare := path
	if i := strings.IndexByte(bare, '?'); i >= 0 {
		bare = bare[:i]
	}
	if bare == "" {
		return false
	}
	segs := strings.Split(strings.Trim(bare, "/"), "/")
	if len(segs) > 8 {
		return false
	}
	letterSeg := false
	for _, s := range segs {
		if len(s) > 80 {
			return false
		}
		letters := 0
		for _, c := range s {
			if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') {
				letters++
			}
		}
		if letters >= 2 {
			letterSeg = true
		}
	}
	return letterSeg
}

func jsPatternID(i int) string     { return "js_" + strconv.Itoa(i) }
func staticPatternID(i int) string { return "static_" + strconv.Itoa(i) }
func apiPatternID(i int) string    { return "api_" + strconv.Itoa(i) }
