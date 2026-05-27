package crawler

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"encoding/xml"
	"log/slog"
	"net/url"
	"strings"
	"sync"

	"golang.org/x/sync/errgroup"
	"golang.org/x/sync/semaphore"

	"github.com/dogadmin/jsscango/internal/fetcher"
	"github.com/dogadmin/jsscango/internal/types"
)

// WellKnown fans out to a fixed list of standard endpoints (robots.txt,
// sitemap.xml, openapi.json, .well-known/*, swagger docs, actuator) and
// returns discovered URLs alongside any OpenAPI-derived endpoint+method
// pairs. It runs once per target before the homepage stage.
type WellKnown struct {
	F      fetcher.Fetcher
	Logger *slog.Logger
}

// Result is the structured output of a well-known scan.
type Result struct {
	Discovered []types.DiscoveredURL // URLs to feed into the regular pipeline
	APIPaths   []APIEndpoint         // (path, method) pairs extracted from OpenAPI docs
}

// APIEndpoint pairs a path with one or more HTTP methods. Methods is
// upper-case. Empty Methods means the path was found but its methods
// weren't declared; downstream probe should fall back to the default
// GET / POST_FORM / POST_JSON triple.
type APIEndpoint struct {
	Path    string
	Methods []string
	Source  string // "robots.txt" / "sitemap.xml" / "openapi.json" / etc.
}

// Default fan-out width. The fetcher already enforces per-host rate
// limiting, so concurrent dispatch is safe; this just caps in-flight
// goroutines so a slow target can't stall a giant fan-out.
const wellKnownWorkers = 8

// openapiPaths is the fixed list of OpenAPI/Swagger doc URLs probed in
// addition to the standard discovery endpoints. Keep this list short and
// well-known — wide path-guessing is the probe stage's job, not this one.
var openapiPaths = []string{
	"/openapi.json",
	"/swagger.json",
	"/api/swagger.json",
	"/v3/api-docs",
	"/v2/api-docs",
	"/api-docs",
	"/swagger/v1/swagger.json",
}

// actuatorPaths is the small set of Spring Boot actuator endpoints worth
// probing. /actuator/mappings often yields the full route table when
// security is misconfigured; the others are existence signals.
var actuatorPaths = []string{
	"/actuator/health",
	"/actuator/env",
	"/actuator/mappings",
}

// Probe issues GET to each well-known path concurrently and parses what
// it gets back. Honors ctx cancellation. Single-endpoint failures are
// logged at Debug and otherwise silent — the result is best-effort.
func (w *WellKnown) Probe(ctx context.Context, targetURL string) (Result, error) {
	var result Result
	if w == nil || w.F == nil {
		return result, nil
	}
	scheme, host, ok := schemeHost(targetURL)
	if !ok {
		return result, nil
	}
	base := scheme + "://" + host

	// agg is the shared sink. We collect everything under one mutex
	// because the per-endpoint parsers run in parallel goroutines.
	var aggMu sync.Mutex
	addURL := func(d types.DiscoveredURL) {
		if d.URL == "" {
			return
		}
		aggMu.Lock()
		result.Discovered = append(result.Discovered, d)
		aggMu.Unlock()
	}
	addAPI := func(e APIEndpoint) {
		if e.Path == "" {
			return
		}
		aggMu.Lock()
		result.APIPaths = append(result.APIPaths, e)
		aggMu.Unlock()
	}

	sem := semaphore.NewWeighted(int64(wellKnownWorkers))
	g, gctx := errgroup.WithContext(ctx)

	// Single-URL fetch helper that respects the worker semaphore. The
	// returned body is empty on any non-200 / error / cancellation, and
	// callers branch on len(body)==0 to skip parsing.
	fetchOne := func(reqURL string) []byte {
		if err := sem.Acquire(gctx, 1); err != nil {
			return nil
		}
		defer sem.Release(1)
		resp, err := w.F.Fetch(gctx, fetcher.Request{URL: reqURL, Method: fetcher.MethodGET})
		if err != nil {
			if w.Logger != nil {
				w.Logger.Debug("wellknown fetch failed", "url", reqURL, "err", err)
			}
			return nil
		}
		if resp == nil || resp.StatusCode != 200 || len(resp.Body) == 0 || resp.Skipped {
			return nil
		}
		return resp.Body
	}

	// robots.txt — also queues any Sitemap: directives it finds.
	g.Go(func() error {
		body := fetchOne(base + "/robots.txt")
		if len(body) == 0 {
			return nil
		}
		extraSitemaps := parseRobots(body, base, targetURL, addURL)
		for _, sm := range extraSitemaps {
			sm := sm
			g.Go(func() error {
				smBody := fetchOne(sm)
				if len(smBody) == 0 {
					return nil
				}
				parseSitemap(gctx, smBody, sm, targetURL, w.Logger, fetchOne, addURL)
				return nil
			})
		}
		return nil
	})

	// /sitemap.xml at the root (separate from robots-declared sitemaps,
	// which may live anywhere).
	g.Go(func() error {
		sm := base + "/sitemap.xml"
		body := fetchOne(sm)
		if len(body) == 0 {
			return nil
		}
		parseSitemap(gctx, body, sm, targetURL, w.Logger, fetchOne, addURL)
		return nil
	})

	// /.well-known/security.txt — existence-only signal.
	g.Go(func() error {
		u := base + "/.well-known/security.txt"
		if body := fetchOne(u); len(body) > 0 {
			addURL(types.DiscoveredURL{
				URL: u, Referer: targetURL, Kind: types.KindStatic, Source: "wellknown:security.txt",
			})
		}
		return nil
	})

	// /.well-known/openid-configuration — JSON document listing OAuth
	// endpoints; each endpoint URL becomes a discovered URL.
	g.Go(func() error {
		u := base + "/.well-known/openid-configuration"
		body := fetchOne(u)
		if len(body) == 0 {
			return nil
		}
		addURL(types.DiscoveredURL{
			URL: u, Referer: targetURL, Kind: types.KindStatic, Source: "wellknown:openid",
		})
		parseOpenIDConfig(body, targetURL, addURL)
		return nil
	})

	// OpenAPI / Swagger docs.
	for _, p := range openapiPaths {
		p := p
		g.Go(func() error {
			u := base + p
			body := fetchOne(u)
			if len(body) == 0 {
				return nil
			}
			// The doc itself is a useful static URL hit.
			addURL(types.DiscoveredURL{
				URL: u, Referer: targetURL, Kind: types.KindStatic, Source: "wellknown:openapi",
			})
			parseOpenAPI(body, targetURL, base, p, addURL, addAPI)
			return nil
		})
	}

	// Spring Boot actuator.
	for _, p := range actuatorPaths {
		p := p
		g.Go(func() error {
			u := base + p
			body := fetchOne(u)
			if len(body) == 0 {
				return nil
			}
			addURL(types.DiscoveredURL{
				URL: u, Referer: targetURL, Kind: types.KindAPIPath, Source: "wellknown:actuator",
			})
			if p == "/actuator/mappings" {
				parseActuatorMappings(body, targetURL, base, addURL, addAPI)
			}
			return nil
		})
	}

	// errgroup.Wait only surfaces errors when a child returns one; every
	// child here swallows errors at the fetch layer so Wait is effectively
	// "wait for completion". A non-nil err here means ctx was cancelled
	// mid-flight, which we surface so the pipeline can react.
	if err := g.Wait(); err != nil {
		return result, err
	}
	return result, nil
}

// schemeHost extracts scheme+host (including port) from a target URL,
// returning ok=false when the URL can't be parsed or is missing either
// half. Probe paths are joined onto "<scheme>://<host>".
func schemeHost(rawURL string) (scheme, host string, ok bool) {
	u, err := url.Parse(rawURL)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return "", "", false
	}
	return u.Scheme, u.Host, true
}

// parseRobots walks a robots.txt body, emitting each Disallow:/Allow: path
// as a discovered URL and returning any Sitemap: URLs for further fetch.
// Lines are interpreted line-by-line per RFC 9309 §2.2; group context
// (User-agent) is ignored because we're harvesting paths, not obeying.
func parseRobots(body []byte, base, target string, addURL func(types.DiscoveredURL)) []string {
	var sitemaps []string
	sc := bufio.NewScanner(bytes.NewReader(body))
	sc.Buffer(make([]byte, 64*1024), 1<<20)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		colon := strings.IndexByte(line, ':')
		if colon < 0 {
			continue
		}
		key := strings.ToLower(strings.TrimSpace(line[:colon]))
		val := strings.TrimSpace(line[colon+1:])
		// Strip inline comments — robots.txt allows "# ..." mid-line.
		if h := strings.IndexByte(val, '#'); h >= 0 {
			val = strings.TrimSpace(val[:h])
		}
		if val == "" {
			continue
		}
		switch key {
		case "disallow", "allow":
			abs := joinRobotsPath(base, val)
			if abs == "" {
				continue
			}
			kind := types.KindStatic
			if strings.Contains(val, "/api/") {
				kind = types.KindAPIPath
			}
			addURL(types.DiscoveredURL{
				URL: abs, Referer: target, Kind: kind, Source: "robots.txt",
			})
		case "sitemap":
			if strings.HasPrefix(val, "http://") || strings.HasPrefix(val, "https://") {
				sitemaps = append(sitemaps, val)
			} else {
				sitemaps = append(sitemaps, joinRobotsPath(base, val))
			}
		}
	}
	return sitemaps
}

// joinRobotsPath joins a robots.txt path fragment onto the target base.
// Strips any wildcard/anchor characters that the directive may use
// ("*", "$") so the emitted URL is fetch-able. Returns "" when the path
// reduces to nothing after stripping, contains other regex metacharacters
// that survive stripping (e.g. "\", "?", mid-string "$"), or is just
// slashes after wildcard collapse.
func joinRobotsPath(base, p string) string {
	p = strings.TrimSpace(p)
	if p == "" {
		return ""
	}
	// Strip pattern anchors — these aren't URL syntax.
	p = strings.TrimSuffix(p, "$")
	p = strings.ReplaceAll(p, "*", "")
	p = strings.TrimSpace(p)
	if p == "" {
		return ""
	}
	// Collapse adjacent slash runs left over from "/api/*/admin" → "/api//admin".
	// Safe to do unconditionally here because joinRobotsPath only handles
	// the path portion — any scheme prefix is detected later.
	for strings.Contains(p, "//") {
		p = strings.ReplaceAll(p, "//", "/")
	}
	// Drop entries whose surviving form contains regex metacharacters that
	// can't appear in a fetch-able URL path. "?" is technically valid as a
	// query separator, but in a robots.txt pattern it's almost always
	// regex/glob syntax leaking through, and we'd rather skip than 404.
	if strings.ContainsAny(p, "\\$?") {
		return ""
	}
	// Drop entries that reduce to nothing after the wildcard collapse.
	if strings.Trim(p, "/") == "" {
		return ""
	}
	if strings.HasPrefix(p, "http://") || strings.HasPrefix(p, "https://") {
		return p
	}
	if !strings.HasPrefix(p, "/") {
		p = "/" + p
	}
	return base + p
}

// sitemapURL / sitemapIndex mirror the two standard sitemap shapes. We
// only consume <loc>; lastmod/changefreq/priority are intentionally
// dropped.
type sitemapURL struct {
	XMLName xml.Name `xml:"url"`
	Loc     string   `xml:"loc"`
}

type sitemapIndexEntry struct {
	XMLName xml.Name `xml:"sitemap"`
	Loc     string   `xml:"loc"`
}

type sitemapDoc struct {
	XMLName  xml.Name            `xml:"urlset"`
	URLs     []sitemapURL        `xml:"url"`
	Sitemaps []sitemapIndexEntry `xml:"sitemap"`
}

type sitemapIndex struct {
	XMLName  xml.Name            `xml:"sitemapindex"`
	Sitemaps []sitemapIndexEntry `xml:"sitemap"`
}

// parseSitemap parses a sitemap.xml body. Standard <urlset> docs yield
// each <loc> as a KindNoJS discovered URL; <sitemapindex> docs recurse
// one level via fetchOne. Recursion stops after one level on purpose —
// adversarial sitemaps are easy to nest into a fork bomb.
// log is used to surface the "neither shape matched" case — most often a
// 200-served-as-HTML or gzip body — which would otherwise be silent.
func parseSitemap(ctx context.Context, body []byte, smURL, target string,
	log *slog.Logger, fetchOne func(string) []byte, addURL func(types.DiscoveredURL)) {
	// Try the urlset shape first.
	var doc sitemapDoc
	if err := xml.Unmarshal(body, &doc); err == nil {
		for _, u := range doc.URLs {
			loc := strings.TrimSpace(u.Loc)
			if loc == "" {
				continue
			}
			addURL(types.DiscoveredURL{
				URL: loc, Referer: target, Kind: types.KindNoJS, Source: "sitemap.xml",
			})
		}
		// Some servers mix <urlset><sitemap> entries — recurse those too
		// (one level only).
		for _, sm := range doc.Sitemaps {
			loc := strings.TrimSpace(sm.Loc)
			if loc == "" || loc == smURL {
				continue
			}
			recurseSitemap(ctx, loc, target, fetchOne, addURL)
		}
		if len(doc.URLs) > 0 || len(doc.Sitemaps) > 0 {
			return
		}
	}

	// Fall through to the index shape.
	var idx sitemapIndex
	if err := xml.Unmarshal(body, &idx); err == nil {
		for _, sm := range idx.Sitemaps {
			loc := strings.TrimSpace(sm.Loc)
			if loc == "" || loc == smURL {
				continue
			}
			recurseSitemap(ctx, loc, target, fetchOne, addURL)
		}
		if len(idx.Sitemaps) > 0 {
			return
		}
	}

	// If we got here, neither shape matched. Most likely the body is HTML
	// (404 served as 200, common on misconfigured WAFs) or gzip-encoded.
	// Logging is the only signal an operator gets — keep it at Debug.
	if log != nil {
		log.Debug("sitemap parse failed; no urlset or sitemapindex root", "url", smURL)
	}
}

// recurseSitemap fetches a nested sitemap and parses its <loc> entries,
// without further recursion. Errors swallowed by design.
func recurseSitemap(_ context.Context, smURL, target string,
	fetchOne func(string) []byte, addURL func(types.DiscoveredURL)) {
	body := fetchOne(smURL)
	if len(body) == 0 {
		return
	}
	var doc sitemapDoc
	if err := xml.Unmarshal(body, &doc); err != nil {
		return
	}
	for _, u := range doc.URLs {
		loc := strings.TrimSpace(u.Loc)
		if loc == "" {
			continue
		}
		addURL(types.DiscoveredURL{
			URL: loc, Referer: target, Kind: types.KindNoJS, Source: "sitemap.xml",
		})
	}
}

// openidConfigFields is the set of *_endpoint keys we surface from a
// /.well-known/openid-configuration document. Each value is expected to
// be a fully-qualified URL; we treat them as static URLs so the probe
// stage can revisit them.
var openidConfigFields = []string{
	"authorization_endpoint",
	"token_endpoint",
	"userinfo_endpoint",
	"jwks_uri",
	"registration_endpoint",
	"introspection_endpoint",
	"revocation_endpoint",
	"end_session_endpoint",
	"device_authorization_endpoint",
}

func parseOpenIDConfig(body []byte, target string, addURL func(types.DiscoveredURL)) {
	var m map[string]any
	if err := json.Unmarshal(body, &m); err != nil {
		return
	}
	for _, k := range openidConfigFields {
		v, ok := m[k]
		if !ok {
			continue
		}
		s, ok := v.(string)
		if !ok || s == "" {
			continue
		}
		addURL(types.DiscoveredURL{
			URL: s, Referer: target, Kind: types.KindAPIPath, Source: "wellknown:openid",
		})
	}
}

// openAPIServer is the minimal shape of an entry in OpenAPI 3.x's
// `servers` array. Only `url` is consumed; `description` / `variables`
// are ignored.
type openAPIServer struct {
	URL string `json:"url"`
}

// openAPIDoc is the minimal shape we need from an OpenAPI / Swagger
// document. `paths` is a map keyed by URL path, valued by an object whose
// keys are HTTP method names. `servers` (OpenAPI 3.x) and `host`/
// `basePath`/`schemes` (Swagger 2.0) declare the base URL the paths are
// relative to. The rest of the doc is ignored.
type openAPIDoc struct {
	Servers  []openAPIServer                       `json:"servers,omitempty"`
	BasePath string                                `json:"basePath,omitempty"` // Swagger 2.0
	Host     string                                `json:"host,omitempty"`     // Swagger 2.0
	Schemes  []string                              `json:"schemes,omitempty"`  // Swagger 2.0
	Paths    map[string]map[string]json.RawMessage `json:"paths"`
}

// parseOpenAPI walks the "paths" map of an OpenAPI/Swagger doc, emitting
// each path as a discovered URL and an APIEndpoint with the declared
// methods. Source is "openapi.json" regardless of which doc URL the body
// came from — the docURL is recorded only in the discovered URL's Source
// for debugging.
//
// Base resolution order:
//  1. OpenAPI 3.x `servers[0].url` — absolute URLs override the target.
//  2. Swagger 2.0 `host` + `basePath` (with `schemes` to pick http/https).
//  3. Caller-supplied `targetBase` (scheme://host of the target URL).
//
// Paths are emitted as fully-resolved URLs in all three cases so consumers
// downstream see a consistent shape in the JSONL `discovered_url.url` field.
func parseOpenAPI(body []byte, target, targetBase, docPath string,
	addURL func(types.DiscoveredURL), addAPI func(APIEndpoint)) {
	var doc openAPIDoc
	if err := json.Unmarshal(body, &doc); err != nil {
		return
	}
	if len(doc.Paths) == 0 {
		return
	}
	src := "openapi.json"
	if strings.Contains(docPath, "swagger") {
		src = "swagger.json"
	}

	// Compute the effective server base. Empty string falls back to the
	// caller-supplied target base.
	serverBase := resolveOpenAPIBase(doc, targetBase)

	for p, methods := range doc.Paths {
		if p == "" {
			continue
		}
		fullURL := joinServerPath(serverBase, p)
		// Emit the resolved URL. When serverBase is non-empty this is a
		// fully-qualified URL (possibly pointing at a host different from
		// the target). When empty, joinServerPath returns the raw path and
		// pipeline.buildProbeURLs will join it onto the target's base.
		addURL(types.DiscoveredURL{
			URL: fullURL, Referer: target, Kind: types.KindAPIPath, Source: src,
		})
		// Collect declared methods. OpenAPI keys are lowercase
		// ("get", "post", ...); the standard verbs are an open set, but
		// only HTTP methods are valid here.
		var ms []string
		for m := range methods {
			switch strings.ToLower(m) {
			case "get", "post", "put", "patch", "delete", "head", "options", "trace":
				ms = append(ms, strings.ToUpper(m))
			}
		}
		// Store the full URL on the APIEndpoint as well — buildProbeURLs
		// already handles both absolute URLs and raw paths.
		addAPI(APIEndpoint{Path: fullURL, Methods: ms, Source: src})
	}
}

// resolveOpenAPIBase picks the effective base URL for paths declared in
// an OpenAPI/Swagger doc. Returns "" when no explicit base is declared in
// the doc AND the caller didn't supply one — caller is then expected to
// emit raw paths and rely on downstream joining.
func resolveOpenAPIBase(doc openAPIDoc, targetBase string) string {
	// OpenAPI 3.x: servers[0].url is the authoritative base.
	if len(doc.Servers) > 0 {
		if u := strings.TrimSpace(doc.Servers[0].URL); u != "" {
			return strings.TrimRight(u, "/")
		}
	}
	// Swagger 2.0: host + basePath, with scheme picked from schemes[].
	if doc.Host != "" {
		scheme := "https"
		if len(doc.Schemes) > 0 {
			found := false
			for _, s := range doc.Schemes {
				if strings.EqualFold(s, "https") {
					scheme = "https"
					found = true
					break
				}
			}
			if !found {
				scheme = strings.ToLower(doc.Schemes[0])
			}
		}
		base := scheme + "://" + doc.Host
		if doc.BasePath != "" {
			bp := doc.BasePath
			if !strings.HasPrefix(bp, "/") {
				bp = "/" + bp
			}
			base += strings.TrimRight(bp, "/")
		}
		return base
	}
	// Fall back to the caller's target base (already scheme://host with no
	// trailing slash). May be "" when caller passes nothing.
	return strings.TrimRight(targetBase, "/")
}

// joinServerPath resolves an OpenAPI path against a base URL declared in
// the doc's servers[] field (or computed from Swagger 2.0 host/basePath).
// Returns path unchanged when base is empty (caller-side fallback to
// target-base joining via pipeline.buildProbeURLs).
func joinServerPath(base, path string) string {
	if base == "" {
		return path
	}
	base = strings.TrimRight(base, "/")
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	return base + path
}

// actuatorMappings is the minimal shape extracted from Spring Boot's
// /actuator/mappings response. Spring exposes the same data under
// slightly different keys depending on the framework version; we walk
// any "dispatcherServlets" → handler → patterns chain and any flat
// "mappings" array, falling back to a generic string walk when shape
// detection fails.
//
// base is the resolved target scheme+host (no trailing slash); each
// emitted path is prefixed with it so consumers see a consistent
// fully-qualified URL in the JSONL output.
func parseActuatorMappings(body []byte, target, base string,
	addURL func(types.DiscoveredURL), addAPI func(APIEndpoint)) {
	var raw map[string]any
	if err := json.Unmarshal(body, &raw); err != nil {
		return
	}
	base = strings.TrimRight(base, "/")
	emit := func(p string) {
		p = strings.TrimSpace(p)
		if p == "" || !strings.HasPrefix(p, "/") {
			return
		}
		fullURL := p
		if base != "" {
			fullURL = base + p
		}
		addURL(types.DiscoveredURL{
			URL: fullURL, Referer: target, Kind: types.KindAPIPath, Source: "actuator/mappings",
		})
		addAPI(APIEndpoint{Path: fullURL, Source: "actuator/mappings"})
	}
	// Generic walk: anything that looks like a request mapping ends up
	// as a slash-prefixed string in the JSON tree. Spring's many shapes
	// (Boot 1/2/3, WebFlux vs MVC) all converge on patterns containing
	// "patterns": ["/path"] or "predicate": "{GET /path}".
	var walk func(any)
	walk = func(v any) {
		switch x := v.(type) {
		case map[string]any:
			for k, val := range x {
				switch k {
				case "patterns":
					if arr, ok := val.([]any); ok {
						for _, e := range arr {
							if s, ok := e.(string); ok {
								emit(s)
							}
						}
					}
				case "predicate":
					if s, ok := val.(string); ok {
						emit(extractPathFromPredicate(s))
					}
				}
				walk(val)
			}
		case []any:
			for _, e := range x {
				walk(e)
			}
		}
	}
	walk(raw)
}

// extractPathFromPredicate pulls the path out of a Spring WebFlux
// predicate string like "{GET /api/users}" or "(GET && /api/users)".
// Returns "" when no leading-slash token is present.
func extractPathFromPredicate(s string) string {
	for _, tok := range strings.FieldsFunc(s, func(r rune) bool {
		return r == ' ' || r == '{' || r == '}' || r == '(' || r == ')' || r == '&' || r == '|' || r == ','
	}) {
		if strings.HasPrefix(tok, "/") {
			return tok
		}
	}
	return ""
}
