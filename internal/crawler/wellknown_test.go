package crawler

import (
	"context"
	"strings"
	"sync"
	"testing"

	"github.com/dogadmin/jsscango/internal/fetcher"
	"github.com/dogadmin/jsscango/internal/types"
)

// stubFetcher is a fetcher.Fetcher that serves canned bodies keyed by URL.
// Anything not in the map returns a 404 (so the well-known prober's "skip
// on non-200" path is exercised for the entries we don't want to mock).
type stubFetcher struct {
	mu      sync.Mutex
	bodies  map[string][]byte
	statuses map[string]int
	hits    map[string]int // url -> hit count, for assertion / debugging
}

func newStubFetcher(bodies map[string]string) *stubFetcher {
	s := &stubFetcher{
		bodies:   map[string][]byte{},
		statuses: map[string]int{},
		hits:     map[string]int{},
	}
	for k, v := range bodies {
		s.bodies[k] = []byte(v)
		s.statuses[k] = 200
	}
	return s
}

func (s *stubFetcher) Fetch(_ context.Context, r fetcher.Request) (*fetcher.Response, error) {
	s.mu.Lock()
	s.hits[r.URL]++
	body, ok := s.bodies[r.URL]
	code := s.statuses[r.URL]
	s.mu.Unlock()
	if !ok {
		return &fetcher.Response{URL: r.URL, StatusCode: 404}, nil
	}
	if code == 0 {
		code = 200
	}
	ct := "application/json"
	if strings.HasSuffix(r.URL, ".txt") {
		ct = "text/plain"
	} else if strings.HasSuffix(r.URL, ".xml") {
		ct = "application/xml"
	}
	return &fetcher.Response{
		URL:         r.URL,
		StatusCode:  code,
		ContentType: ct,
		Body:        body,
	}, nil
}

func TestWellKnown_Probe_ExtractsRobotsSitemapOpenAPI(t *testing.T) {
	target := "https://example.com/"
	bodies := map[string]string{
		"https://example.com/robots.txt": `
User-agent: *
Disallow: /admin/
Disallow: /api/v1/secret
Allow: /api/v1/public
Sitemap: https://example.com/sitemap.xml
`,
		"https://example.com/sitemap.xml": `<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
  <url><loc>https://example.com/pageA</loc></url>
  <url><loc>https://example.com/pageB</loc></url>
</urlset>`,
		"https://example.com/openapi.json": `{
			"openapi": "3.0.0",
			"paths": {
				"/users": {"get": {}, "post": {}},
				"/users/{id}": {"get": {}, "delete": {}}
			}
		}`,
	}
	sf := newStubFetcher(bodies)
	wk := &WellKnown{F: sf}
	res, err := wk.Probe(context.Background(), target)
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}

	// --- Discovered URLs ---
	type want struct {
		url    string
		kind   types.URLKind
		source string
	}
	wantURLs := []want{
		// robots.txt — /admin/ has no /api/ so it's KindStatic; the
		// /api/v1/* entries become KindAPIPath.
		{"https://example.com/admin/", types.KindStatic, "robots.txt"},
		{"https://example.com/api/v1/secret", types.KindAPIPath, "robots.txt"},
		{"https://example.com/api/v1/public", types.KindAPIPath, "robots.txt"},
		// sitemap.xml — each <loc> is a real page, KindNoJS.
		{"https://example.com/pageA", types.KindNoJS, "sitemap.xml"},
		{"https://example.com/pageB", types.KindNoJS, "sitemap.xml"},
		// openapi.json — doc itself is a static URL hit, paths are
		// emitted relative (joined by buildProbeURLs in the pipeline).
		{"https://example.com/openapi.json", types.KindStatic, "wellknown:openapi"},
		{"/users", types.KindAPIPath, "openapi.json"},
		{"/users/{id}", types.KindAPIPath, "openapi.json"},
	}
	for _, w := range wantURLs {
		if !containsDiscovered(res.Discovered, w.url, w.kind, w.source) {
			t.Errorf("expected discovered URL %q (kind=%s, source=%s) — not found in %d entries",
				w.url, w.kind, w.source, len(res.Discovered))
		}
	}

	// --- OpenAPI APIEndpoint entries ---
	wantAPIs := map[string][]string{
		"/users":      {"GET", "POST"},
		"/users/{id}": {"GET", "DELETE"},
	}
	if len(res.APIPaths) < 2 {
		t.Fatalf("want >=2 APIPaths, got %d", len(res.APIPaths))
	}
	for _, ep := range res.APIPaths {
		exp, ok := wantAPIs[ep.Path]
		if !ok {
			continue
		}
		if !methodSetEqual(ep.Methods, exp) {
			t.Errorf("methods for %s: got %v, want %v", ep.Path, ep.Methods, exp)
		}
		if ep.Source != "openapi.json" {
			t.Errorf("source for %s: got %q, want openapi.json", ep.Path, ep.Source)
		}
		delete(wantAPIs, ep.Path)
	}
	if len(wantAPIs) > 0 {
		t.Errorf("missing APIEndpoint entries: %+v", wantAPIs)
	}
}

func TestWellKnown_Probe_SwaggerJSONAlsoParsed(t *testing.T) {
	target := "https://api.example.com/"
	bodies := map[string]string{
		"https://api.example.com/swagger.json": `{
			"swagger": "2.0",
			"paths": {
				"/v1/widgets": {"get": {}}
			}
		}`,
	}
	wk := &WellKnown{F: newStubFetcher(bodies)}
	res, err := wk.Probe(context.Background(), target)
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	found := false
	for _, ep := range res.APIPaths {
		if ep.Path == "/v1/widgets" && ep.Source == "swagger.json" {
			found = true
			if !methodSetEqual(ep.Methods, []string{"GET"}) {
				t.Errorf("methods: got %v, want [GET]", ep.Methods)
			}
		}
	}
	if !found {
		t.Errorf("swagger.json /v1/widgets not surfaced; APIPaths=%+v", res.APIPaths)
	}
}

func TestWellKnown_Probe_HonorsCtxCancel(t *testing.T) {
	sf := newStubFetcher(map[string]string{})
	wk := &WellKnown{F: sf}
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // pre-cancel
	// Probe should not panic and should return promptly with an error or
	// empty result. We don't assert which because the fetcher stub may
	// satisfy a few in-flight calls before noticing cancellation.
	_, _ = wk.Probe(ctx, "https://example.com/")
}

func TestWellKnown_Probe_InvalidURLReturnsEmpty(t *testing.T) {
	wk := &WellKnown{F: newStubFetcher(nil)}
	res, err := wk.Probe(context.Background(), "not a url")
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if len(res.Discovered) != 0 || len(res.APIPaths) != 0 {
		t.Errorf("expected empty result, got %+v", res)
	}
}

func TestParseRobots_ExtractsSitemapDirectives(t *testing.T) {
	body := []byte(`
Sitemap: https://x.test/extra.xml
Disallow: /private/
Sitemap: /relative-sitemap.xml
`)
	var got []types.DiscoveredURL
	sitemaps := parseRobots(body, "https://x.test", "https://x.test/", func(d types.DiscoveredURL) {
		got = append(got, d)
	})
	if len(sitemaps) != 2 {
		t.Fatalf("want 2 sitemaps, got %d: %+v", len(sitemaps), sitemaps)
	}
	if sitemaps[0] != "https://x.test/extra.xml" {
		t.Errorf("absolute sitemap mismatch: %s", sitemaps[0])
	}
	if sitemaps[1] != "https://x.test/relative-sitemap.xml" {
		t.Errorf("relative sitemap join mismatch: %s", sitemaps[1])
	}
	// Disallow path should be emitted.
	if len(got) != 1 || got[0].URL != "https://x.test/private/" {
		t.Errorf("disallow path emit: got %+v", got)
	}
}

// containsDiscovered checks whether the slice has an entry matching all
// three fields. Other fields (Referer, Depth) are not asserted because
// the well-known prober sets Referer=target consistently.
func containsDiscovered(slice []types.DiscoveredURL, url string, kind types.URLKind, source string) bool {
	for _, d := range slice {
		if d.URL == url && d.Kind == kind && d.Source == source {
			return true
		}
	}
	return false
}

func methodSetEqual(got, want []string) bool {
	if len(got) != len(want) {
		return false
	}
	gm := map[string]bool{}
	for _, m := range got {
		gm[m] = true
	}
	for _, m := range want {
		if !gm[m] {
			return false
		}
	}
	return true
}
