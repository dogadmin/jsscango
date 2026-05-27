package crawler

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"testing"

	"github.com/dogadmin/jsscango/internal/extractor"
	"github.com/dogadmin/jsscango/internal/fetcher"
	"github.com/dogadmin/jsscango/internal/state"
	"github.com/dogadmin/jsscango/internal/types"
)

// mockMapFetcher is a minimal fetcher.Fetcher that returns a canned body
// for a single URL and errors for everything else. Used to exercise
// FetchAndExpand without making a real HTTP request.
type mockMapFetcher struct {
	url  string
	body []byte
	code int
	err  error
}

func (m *mockMapFetcher) Fetch(_ context.Context, r fetcher.Request) (*fetcher.Response, error) {
	if m.err != nil {
		return nil, m.err
	}
	if r.URL != m.url {
		return nil, errors.New("mock: unexpected url " + r.URL)
	}
	code := m.code
	if code == 0 {
		code = 200
	}
	return &fetcher.Response{
		URL:        r.URL,
		StatusCode: code,
		Body:       m.body,
	}, nil
}

// buildFixtureMap returns a minimal v3 source map JSON whose first source
// contains an embedded API URL. The mappings field must be a syntactically
// valid VLQ string — go-sourcemap's Parse rejects empty mappings — so we
// emit a single "AAAA" segment (gen-col 0, source 0, src-line 0, src-col 0).
func buildFixtureMap(t *testing.T) []byte {
	t.Helper()
	doc := map[string]interface{}{
		"version":  3,
		"file":     "app.min.js",
		"sources":  []string{"webpack:///./src/api.ts", "webpack:///./src/empty.ts"},
		"sourcesContent": []string{
			`const url = "/api/v1/internal/users";`,
			"", // empty entry must be skipped
		},
		"names":    []string{},
		"mappings": "AAAA",
	}
	b, err := json.Marshal(doc)
	if err != nil {
		t.Fatalf("marshal fixture: %v", err)
	}
	return b
}

func TestParseSourceMap_EmitsSourcesContent(t *testing.T) {
	body := buildFixtureMap(t)
	sources, err := parseSourceMap("https://example.test/app.min.js.map", body)
	if err != nil {
		t.Fatalf("parseSourceMap: %v", err)
	}
	if len(sources) != 1 {
		t.Fatalf("want 1 non-empty source, got %d (%+v)", len(sources), sources)
	}
	if got := string(sources[0].Content); got != `const url = "/api/v1/internal/users";` {
		t.Errorf("content mismatch: %q", got)
	}
	if sources[0].Path != "webpack:///src/api.ts" && sources[0].Path != "webpack:///./src/api.ts" {
		// go-sourcemap may rewrite the path via path.Join when sourceRoot is
		// resolved from sourcemapURL; either form is acceptable here.
		t.Logf("source path: %q", sources[0].Path)
	}
}

func TestParseSourceMap_ExtractorFindsURL(t *testing.T) {
	body := buildFixtureMap(t)
	sources, err := parseSourceMap("https://example.test/app.min.js.map", body)
	if err != nil {
		t.Fatalf("parseSourceMap: %v", err)
	}
	found := false
	for _, s := range sources {
		for _, f := range extractor.FromJSBody(s.Content) {
			if f.Value == "/api/v1/internal/users" {
				found = true
			}
		}
	}
	if !found {
		t.Fatalf("extractor did not surface /api/v1/internal/users from sourcesContent")
	}
}

func TestFetchAndExpand_UsesFetcher(t *testing.T) {
	mapURL := "https://example.test/app.min.js.map"
	mf := &mockMapFetcher{url: mapURL, body: buildFixtureMap(t), code: 200}
	sources, err := FetchAndExpand(context.Background(), mf, mapURL)
	if err != nil {
		t.Fatalf("FetchAndExpand: %v", err)
	}
	if len(sources) != 1 {
		t.Fatalf("want 1 source, got %d", len(sources))
	}
	// Sanity: extracted URL must reach the extractor too.
	found := false
	for _, f := range extractor.FromJSBody(sources[0].Content) {
		if f.Value == "/api/v1/internal/users" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected extractor to find /api/v1/internal/users in fetched source")
	}
}

func TestFetchAndExpand_PropagatesFetchError(t *testing.T) {
	mf := &mockMapFetcher{err: errors.New("boom")}
	if _, err := FetchAndExpand(context.Background(), mf, "https://x/y.map"); err == nil {
		t.Fatal("expected error from fetcher")
	}
}

func TestParseSourceMap_RejectsNonV3(t *testing.T) {
	bad := []byte(`{"version":2,"sources":[],"sourcesContent":[]}`)
	if _, err := parseSourceMap("https://x/y.map", bad); err == nil {
		t.Fatal("expected v2 source map to be rejected")
	}
}

// buildJSFixtureMap returns a minimal v3 source map JSON whose first source
// content contains a JS URL the extractor will surface as Kind="js". Used by
// the expandSourceMap-level tests below to assert the Referer field carries
// the discovering JS URL (the user-facing referer arg), not the .map URL
// (which is implementation provenance and lives in Source="sourcemap").
func buildJSFixtureMap(t *testing.T, jsURL string) []byte {
	t.Helper()
	doc := map[string]interface{}{
		"version":  3,
		"file":     "app.min.js",
		"sources":  []string{"webpack:///./src/loader.ts"},
		"sourcesContent": []string{
			// Quoting matters: the js_1 pattern matches paths inside
			// matched quotes. A literal .js suffix triggers Kind="js".
			`const chunk = "` + jsURL + `";`,
		},
		"names":    []string{},
		"mappings": "AAAA",
	}
	b, err := json.Marshal(doc)
	if err != nil {
		t.Fatalf("marshal js fixture: %v", err)
	}
	return b
}

// TestExpandSourceMap_UsesReferer verifies Fix 2: the emitted DiscoveredURL
// records the JS file that referenced the source map (the "referer" arg) as
// its Referer field, not the .map URL. The .map URL is still recoverable
// via the Source="sourcemap" tag.
func TestExpandSourceMap_UsesReferer(t *testing.T) {
	const (
		mapURL    = "https://example.test/app.min.js.map"
		refererJS = "https://example.test/app.min.js"
		markerJS  = "/static/chunks/marker-abc.js"
	)
	mf := &mockMapFetcher{url: mapURL, body: buildJSFixtureMap(t, markerJS), code: 200}

	var (
		mu       sync.Mutex
		emitted  []types.DiscoveredURL
	)
	c := &Crawler{
		F: mf,
		Emit: func(d types.DiscoveredURL) {
			mu.Lock()
			emitted = append(emitted, d)
			mu.Unlock()
		},
	}

	c.expandSourceMap(context.Background(), mapURL, refererJS)

	// The fixture's sourcesContent embeds markerJS; the extractor must surface
	// it as Kind="js", and expandSourceMap must emit it with Referer=refererJS
	// (not mapURL).
	var got *types.DiscoveredURL
	for i, d := range emitted {
		if d.Kind == types.KindJS {
			got = &emitted[i]
			break
		}
	}
	if got == nil {
		t.Fatalf("expected a Kind=js emission, got %d emissions: %+v", len(emitted), emitted)
	}
	if got.Referer != refererJS {
		t.Errorf("Referer = %q; want %q (the JS file that referenced the map, not the map URL)", got.Referer, refererJS)
	}
	if got.Referer == mapURL {
		t.Errorf("Referer must not be the .map URL %q — that's implementation detail; provenance lives in Source", mapURL)
	}
	if got.Source != "sourcemap" {
		t.Errorf("Source = %q; want %q (so callers can still recover that this came from a sourcemap)", got.Source, "sourcemap")
	}
}

// multiURLStubFetcher serves canned bodies keyed by URL for the integration
// test below. Unknown URLs return 404 so the crawler skips them cleanly.
type multiURLStubFetcher struct {
	mu     sync.Mutex
	bodies map[string][]byte
	hits   map[string]int
}

func (m *multiURLStubFetcher) Fetch(_ context.Context, r fetcher.Request) (*fetcher.Response, error) {
	m.mu.Lock()
	m.hits[r.URL]++
	body, ok := m.bodies[r.URL]
	m.mu.Unlock()
	if !ok {
		return &fetcher.Response{URL: r.URL, StatusCode: 404}, nil
	}
	return &fetcher.Response{URL: r.URL, StatusCode: 200, Body: body}, nil
}

// TestCrawler_SourceMapEnqueueAsync exercises Fix 1: a JS file whose body
// carries a sourceMappingURL directive must cause the crawler to enqueue a
// jobExpandSourceMap that runs on the worker pool. We assert success by
// observing that URLs hidden in the .map's sourcesContent surface as emitted
// DiscoveredURLs by the end of the run — which can only happen if the
// expansion actually executed.
func TestCrawler_SourceMapEnqueueAsync(t *testing.T) {
	const (
		seedJS    = "https://example.test/app.js"
		mapURL    = "https://example.test/app.js.map"
		markerURL = "/static/chunks/sourcemap-marker.js"
	)
	mf := &multiURLStubFetcher{
		bodies: map[string][]byte{
			// The seed JS body contains the sourcemap_ref directive. The
			// extractor's pattern is `//#\s*sourceMappingURL=...` (see
			// internal/extractor/patterns_extra.go).
			seedJS: []byte("//# sourceMappingURL=app.js.map\n"),
			mapURL: buildJSFixtureMap(t, markerURL),
		},
		hits: map[string]int{},
	}

	var (
		emitMu  sync.Mutex
		emitted []types.DiscoveredURL
	)
	c := &Crawler{
		F:       mf,
		Seen:    state.NewSeen(),
		Workers: 4,
		Emit: func(d types.DiscoveredURL) {
			emitMu.Lock()
			emitted = append(emitted, d)
			emitMu.Unlock()
		},
	}

	if err := c.Run(context.Background(), []types.DiscoveredURL{
		{URL: seedJS, Referer: seedJS, Kind: types.KindJS, Source: "test"},
	}); err != nil {
		t.Fatalf("Run: %v", err)
	}

	// The expansion must have fired — otherwise the marker URL never gets
	// emitted because it lives only inside the .map's sourcesContent.
	if mf.hits[mapURL] == 0 {
		t.Fatalf("crawler never fetched the .map URL %q; hits: %+v", mapURL, mf.hits)
	}
	abs := "https://example.test" + markerURL
	found := false
	var foundEmission types.DiscoveredURL
	for _, d := range emitted {
		if d.URL == abs && d.Source == "sourcemap" {
			found = true
			foundEmission = d
			break
		}
	}
	if !found {
		urls := make([]string, 0, len(emitted))
		for _, d := range emitted {
			urls = append(urls, d.URL+" (source="+d.Source+")")
		}
		t.Fatalf("expected emitted DiscoveredURL with URL=%q Source=%q after sourcemap expansion; got: %v", abs, "sourcemap", urls)
	}
	// Fix 2 sanity-check at the integration level: the Referer should be
	// the discovering JS file (seedJS), not the .map URL.
	if foundEmission.Referer != seedJS {
		t.Errorf("emitted URL has Referer=%q; want %q (the JS that referenced the map)", foundEmission.Referer, seedJS)
	}
}
