package extractor

import (
	"regexp"
	"strings"
)

// vueRouterPathPattern matches a path:"X" literal that lives in the same
// object literal as a component:... member. The 0..300 character bound
// keeps it localised to a single route object — real Vue Router route
// declarations are short (the longest in our cpic corpus is ~250 chars
// including a meta:{title:"…"} block).
//
// We try BOTH orders because minifiers don't always emit the canonical
// {path,name,component,meta} layout: alphabetical sort puts component
// before path, and hand-written configs vary.
//
// The inner window is `(?:[^{}]|\{[^{}]*\}){0,300}?` — one level of nested
// braces allowed. This is required for the common `meta:{title:"…"}` block
// that appears between path and component in real bundles. Two levels of
// nesting are dropped silently (preferable to bridging across two routes,
// which would pair a parent path with a child component in a nested
// children:[…] array).
//
// Captures:
//
//	group 1: path string when path appears BEFORE component
//	group 2: path string when component appears BEFORE path
var vueRouterPathPattern = regexp.MustCompile(
	`\bpath\s*:\s*['"]([^'"]*)['"](?:[^{}]|\{[^{}]*\}){0,300}?\bcomponent\s*:` +
		`|` +
		`\bcomponent\s*:(?:[^{}]|\{[^{}]*\}){0,300}?\bpath\s*:\s*['"]([^'"]*)['"]`,
)

// RouteFound is a single Vue Router / SPA-router route path discovered in
// source. Path is the raw declared path; it may be relative (a `children:`
// entry like "sub") or absolute ("/leaveForm"). Callers that need a single
// canonical form should pass through RoutePathSet which normalises a leading
// slash.
type RouteFound struct {
	Path string
}

// DetectRoutes scans body for Vue Router / similar SPA-router route objects.
// Returns one entry per unique non-empty path. Order is discovery order.
//
// Drops:
//   - empty paths (default-route entries like {path:""})
//   - bare "/" (the SPA root, which is not useful as a discrete route hit
//     because every SPA serves the same index at "/")
//   - "*" (the not-found catch-all)
//   - ":param" / starts with ":" (parameter-only declarations like ":id"
//     which depend on the parent route's prefix and aren't navigable on
//     their own)
//
// Routes are NOT deduplicated against the api-pattern Found list here;
// FromJSBody handles that downstream when reclassifying.
func DetectRoutes(body []byte) []RouteFound {
	if len(body) == 0 {
		return nil
	}
	matches := vueRouterPathPattern.FindAllSubmatch(body, -1)
	seen := make(map[string]bool, len(matches))
	out := make([]RouteFound, 0, len(matches))
	for _, m := range matches {
		var p string
		if len(m) > 1 && len(m[1]) > 0 {
			p = string(m[1])
		} else if len(m) > 2 && len(m[2]) > 0 {
			p = string(m[2])
		}
		p = strings.TrimSpace(p)
		if p == "" || p == "/" || p == "*" {
			continue
		}
		if strings.HasPrefix(p, ":") {
			continue
		}
		if seen[p] {
			continue
		}
		seen[p] = true
		out = append(out, RouteFound{Path: p})
	}
	return out
}

// RoutePathSet returns the set of normalised route paths (leading slash
// added if missing) for fast membership lookup. Used by FromJSBody to
// reclassify api Found values that turn out to be Vue Router routes
// BEFORE the baseURL prefix would otherwise be prepended.
func RoutePathSet(routes []RouteFound) map[string]struct{} {
	s := make(map[string]struct{}, len(routes))
	for _, r := range routes {
		p := r.Path
		if !strings.HasPrefix(p, "/") {
			p = "/" + p
		}
		s[p] = struct{}{}
	}
	return s
}
