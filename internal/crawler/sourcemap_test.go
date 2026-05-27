package crawler

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/dogadmin/jsscango/internal/extractor"
	"github.com/dogadmin/jsscango/internal/fetcher"
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
