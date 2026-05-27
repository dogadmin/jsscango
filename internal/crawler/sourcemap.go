package crawler

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/go-sourcemap/sourcemap"

	"github.com/dogadmin/jsscango/internal/extractor"
	"github.com/dogadmin/jsscango/internal/fetcher"
	"github.com/dogadmin/jsscango/internal/types"
	"github.com/dogadmin/jsscango/internal/util"
)

// SourceMapSource is one decoded entry from a source map's sourcesContent
// array, paired with the matching path from the sources array. Path is the
// original source location as recorded in the map (e.g.
// "webpack:///./src/api.ts"); it is NOT a URL we can fetch — only Content
// should be fed back through the extractor.
type SourceMapSource struct {
	Path    string // original path as recorded in the map
	Content []byte // sourcesContent[i] decoded
}

// FetchAndExpand fetches the .map at mapURL, parses it, and returns each
// original source's content. Returns (nil, err) on fetch/parse failure.
// Callers typically feed each result back through extractor.FromJSBody to
// re-extract URLs from the unminified source.
//
// Sources are identified by index; the returned slice's order matches the
// "sources" array in the source-map JSON. Entries with an empty/missing
// sourcesContent slot are skipped because there is nothing to re-extract.
//
// Implementation note: go-sourcemap's Consumer is parsed to validate the
// map (version check, structural soundness), but the public API does not
// expose the sources/sourcesContent arrays as a slice — only a per-source
// lookup via Consumer.SourceContent. To enumerate every source we unmarshal
// the JSON directly. Source maps are JSON by definition (spec rev 3), so
// this is safe and avoids reflection or unsafe access into internal types.
func FetchAndExpand(ctx context.Context, f fetcher.Fetcher, mapURL string) ([]SourceMapSource, error) {
	if f == nil {
		return nil, errors.New("sourcemap: nil fetcher")
	}
	if mapURL == "" {
		return nil, errors.New("sourcemap: empty map url")
	}
	resp, err := f.Fetch(ctx, fetcher.Request{URL: mapURL, Method: fetcher.MethodGET})
	if err != nil {
		return nil, fmt.Errorf("sourcemap fetch: %w", err)
	}
	if resp == nil || len(resp.Body) == 0 {
		return nil, errors.New("sourcemap: empty body")
	}
	if resp.StatusCode != 0 && resp.StatusCode != 200 {
		return nil, fmt.Errorf("sourcemap: status %d", resp.StatusCode)
	}
	return parseSourceMap(mapURL, resp.Body)
}

// parseSourceMap validates the .map via go-sourcemap (rejects v1/v2 and
// malformed JSON) and then enumerates sources via a direct JSON unmarshal.
// Split out for testability — tests can feed bytes without a fetcher.
func parseSourceMap(mapURL string, body []byte) ([]SourceMapSource, error) {
	// Validate the map structure first. Parse() rejects non-v3 maps and
	// JSON that is not a source map.
	if _, err := sourcemap.Parse(mapURL, body); err != nil {
		return nil, fmt.Errorf("sourcemap parse: %w", err)
	}
	var raw struct {
		Sources        []string `json:"sources"`
		SourcesContent []string `json:"sourcesContent"`
		Sections       []struct {
			Map struct {
				Sources        []string `json:"sources"`
				SourcesContent []string `json:"sourcesContent"`
			} `json:"map"`
		} `json:"sections"`
	}
	if err := json.Unmarshal(body, &raw); err != nil {
		return nil, fmt.Errorf("sourcemap unmarshal: %w", err)
	}

	out := make([]SourceMapSource, 0, len(raw.SourcesContent)+8)
	collect := func(sources, contents []string) {
		for i, c := range contents {
			if c == "" {
				continue
			}
			path := ""
			if i < len(sources) {
				path = sources[i]
			}
			out = append(out, SourceMapSource{Path: path, Content: []byte(c)})
		}
	}
	collect(raw.Sources, raw.SourcesContent)
	for _, s := range raw.Sections {
		collect(s.Map.Sources, s.Map.SourcesContent)
	}
	return out, nil
}

// expandSourceMap fetches mapURL, parses it, and emits any URLs/API paths
// that the extractor finds in the original (non-minified) sources.
// Discovered URLs carry Source="sourcemap" so downstream consumers can tell
// them apart from regular crawl-time emissions. Errors are logged at Debug
// level and otherwise swallowed — a missing or malformed map should not
// abort the crawl.
//
// referer is the JS URL that pointed at the map (i.e. the URL whose body
// contained the sourceMappingURL directive). It is recorded as the Referer
// on every re-extracted URL — the JS that referenced the map is more
// useful provenance for consumers than the .map URL itself, and the .map
// URL is still recoverable from the "sourcemap" Source tag.
func (c *Crawler) expandSourceMap(ctx context.Context, mapURL, referer string) {
	sources, err := FetchAndExpand(ctx, c.F, mapURL)
	if err != nil {
		if c.Logger != nil {
			c.Logger.Debug("sourcemap fetch failed", "url", mapURL, "err", err)
		}
		return
	}
	if c.Logger != nil {
		c.Logger.Info("sourcemap expanded", "url", mapURL, "sources", len(sources))
	}
	// All re-extracted URLs use the .map URL's scheme/host as the join base.
	// Source-map source paths like "webpack:///./src/api.ts" are not real
	// URLs, so we ignore the source path itself and only re-extract from the
	// content. Absolute URLs found inside the content are kept as-is by
	// JoinNewURL, while relative ones get resolved against the .map's host.
	scheme, base, root := util.SplitBase(mapURL)
	for _, s := range sources {
		for _, f := range extractor.FromJSBody(s.Content) {
			switch f.Kind {
			case "js":
				abs := util.JoinNewURL(scheme, base, root, f.Value)
				if abs == "" {
					continue
				}
				c.emit(types.DiscoveredURL{
					URL: abs, Referer: referer, Kind: types.KindJS, Source: "sourcemap",
				})
			case "static":
				abs := util.JoinNewURL(scheme, base, root, f.Value)
				if abs == "" {
					continue
				}
				c.emit(types.DiscoveredURL{
					URL: abs, Referer: referer, Kind: types.KindStatic, Source: "sourcemap",
				})
			case "api":
				c.emit(types.DiscoveredURL{
					URL: f.Value, Referer: referer, Kind: types.KindAPIPath, Source: "sourcemap",
				})
			}
		}
	}
}
