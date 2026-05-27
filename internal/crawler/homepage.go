package crawler

import (
	"context"
	"net/url"
	"strings"

	"golang.org/x/net/html"

	"github.com/dogadmin/jsscango/internal/fetcher"
	"github.com/dogadmin/jsscango/internal/types"
)

// StaticHomepage is the requests + BeautifulSoup equivalent (no JS execution).
// Mirrors indexJsFind in getJsUrl.py:36. The interface it satisfies lives in
// the fetcher package alongside the chromedp impl - see fetcher.HomepageDiscoverer.
type StaticHomepage struct {
	F fetcher.Fetcher
}

func (s *StaticHomepage) Discover(ctx context.Context, targetURL, cookies string) ([]types.DiscoveredURL, error) {
	out := []types.DiscoveredURL{{
		URL: targetURL, Referer: targetURL, Kind: types.KindBaseURL, Source: "homepage",
	}}
	req := fetcher.Request{URL: targetURL, Method: fetcher.MethodGET}
	if cookies != "" {
		req.Headers = map[string]string{"Cookie": cookies}
	}
	resp, err := s.F.Fetch(ctx, req)
	if err != nil {
		return out, err
	}
	if resp == nil || len(resp.Body) == 0 {
		return out, nil
	}
	doc, err := html.Parse(strings.NewReader(string(resp.Body)))
	if err != nil {
		return out, nil
	}
	base, _ := url.Parse(targetURL)
	var walk func(*html.Node)
	walk = func(n *html.Node) {
		if n.Type == html.ElementNode && n.Data == "script" {
			for _, a := range n.Attr {
				if a.Key != "src" {
					continue
				}
				v := strings.TrimRight(strings.TrimSpace(a.Val), "/")
				if v == "" {
					continue
				}
				abs := v
				if base != nil {
					if u, err := base.Parse(v); err == nil {
						abs = u.String()
					}
				}
				out = append(out, types.DiscoveredURL{
					URL: abs, Referer: targetURL, Kind: types.KindJS, Source: "homepage",
				})
			}
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			walk(c)
		}
	}
	walk(doc)
	return out, nil
}
