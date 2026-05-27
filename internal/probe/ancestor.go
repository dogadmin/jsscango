package probe

import (
	"net/url"
	"strings"
)

// DeriveAncestors returns up to `depth` parent paths for the given URL.
// The original URL is NOT included in the returned slice.
//
// Rules:
//   - Query and fragment are stripped before computing ancestors.
//   - Trailing slash on input is treated as a directory marker: the last
//     segment under it counts as one "level up" already.
//   - depth=2 + input `/a/b/c/d`     -> ["/a/b/c/", "/a/b/"]
//   - depth=2 + input `/a/b/c/d/`    -> ["/a/b/c/", "/a/b/"]
//   - depth=2 + input `/a/b`         -> ["/a/"]   (only 1 ancestor possible)
//   - depth=2 + input `/a`           -> []        (no ancestor worth probing)
//   - depth=2 + input `/`            -> []
//   - depth=0                         -> []
//
// The returned ancestors always carry a trailing slash to make them
// distinguishable from "files" and to nudge any servers that treat the
// distinction (e.g. Express, Spring, nginx index lookup).
func DeriveAncestors(rawURL string, depth int) ([]string, error) {
	if depth <= 0 {
		return nil, nil
	}
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, err
	}
	u.RawQuery = ""
	u.Fragment = ""
	p := u.Path
	if p == "" || p == "/" {
		return nil, nil
	}
	// Split into non-empty segments; preserve the trailing-slash hint via
	// the natural side-effect that splitting "/a/b/" yields ["", "a", "b", ""]
	// and we drop the empties, so a trailing "/" doesn't artificially shorten.
	segs := strings.Split(p, "/")
	nonEmpty := segs[:0]
	for _, s := range segs {
		if s != "" {
			nonEmpty = append(nonEmpty, s)
		}
	}
	if len(nonEmpty) <= 1 {
		return nil, nil
	}
	out := make([]string, 0, depth)
	cur := nonEmpty
	for i := 0; i < depth && len(cur) > 1; i++ {
		cur = cur[:len(cur)-1]
		parent := *u
		parent.Path = "/" + strings.Join(cur, "/") + "/"
		out = append(out, parent.String())
	}
	return out, nil
}
