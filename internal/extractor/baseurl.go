package extractor

import "regexp"

// baseURLPatterns detects axios/fetch baseURL declarations in JavaScript
// bodies. Modern SPA bundles routinely declare a baseURL on an axios
// instance ("axios.create({baseURL:'/api', ...})"), then issue calls with
// short, mount-relative URLs ("url:'/auth/login'"). The probe stage was
// hitting 404s on those URLs because we ignored the mount; DetectBaseURLs
// surfaces the prefix so FromJSBody can resolve it.
//
// Patterns are RE2-compatible (no backreferences, no variable-width
// lookbehind). Each captures the baseURL string literal in group 1.
var baseURLPatterns = []*regexp.Regexp{
	// axios.create({ ... baseURL: "/api" ... })
	// Also matches request.create / http.create / api.create / fetch.create
	// since some teams alias the factory. The [^}]*? bound keeps us inside
	// the same object literal — RE2's leftmost-first semantics combined
	// with the lazy quantifier yields the closest baseURL after the brace.
	regexp.MustCompile(`\b(?:axios|request|http|api|fetch)\.create\s*\(\s*\{[^}]*?\bbaseURL\s*:\s*['"]([^'"]+)['"]`),

	// Minified axios: webpack rewrites `axios.create` to a single-letter
	// identifier or even `o().create` (factory-returns-object). Catches:
	//   o.create({baseURL:"/api"...})        - direct call on imported name
	//   o().create({baseURL:"/api"...})      - factory call then .create
	//   t.default.create({baseURL:"/api"...})- default-export indirection
	// We anchor on `.create({ ... baseURL: ... }` since the literal
	// "baseURL" identifier inside an object literal is a strong axios-
	// specific signal — non-axios libraries almost never use that exact
	// member name.
	regexp.MustCompile(`\b[A-Za-z_$][\w$]*(?:\.\w+|\(\))*\.create\s*\(\s*\{[^}]*?\bbaseURL\s*:\s*['"]([^'"]+)['"]`),

	// Vue.prototype.$http = axios.create({ baseURL: "/api" })
	// Captured separately so the Vue 2 idiom is still detected when the
	// surrounding context doesn't match the bare axios.create form (e.g.
	// when the prototype assignment runs ahead of the brace).
	regexp.MustCompile(`\bVue\.prototype\.\$\w+\s*=\s*axios\.create\s*\(\s*\{[^}]*?\bbaseURL\s*:\s*['"]([^'"]+)['"]`),

	// axios.defaults.baseURL = "/api"
	// Plus instance.defaults.baseURL / request.defaults.baseURL /
	// api.defaults.baseURL for the common variants.
	regexp.MustCompile(`\b(?:axios|instance|request|api)\.defaults\.baseURL\s*=\s*['"]([^'"]+)['"]`),
}

// DetectBaseURLs returns every baseURL string declared in body. Duplicates
// are collapsed; empty bases dropped. Order of return is the order of
// discovery in the body (first axios.create wins for downstream resolution).
//
// The function is intentionally simple: a single forward pass over the
// pattern set, with a dedup map to collapse duplicates. Closest-by-offset
// resolution against a specific url:"..." literal is left to the caller;
// in practice, taking the FIRST detected base is right for the vast
// majority of SPA bundles, which declare exactly one axios instance.
func DetectBaseURLs(body []byte) []string {
	if len(body) == 0 {
		return nil
	}
	// Collect (offset, value) tuples so we can dedup while preserving the
	// order of first appearance in the body, not the order of the pattern
	// set.
	type hit struct {
		offset int
		value  string
	}
	var hits []hit
	for _, re := range baseURLPatterns {
		matches := re.FindAllSubmatchIndex(body, -1)
		for _, m := range matches {
			if len(m) < 4 || m[2] < 0 {
				continue
			}
			v := string(body[m[2]:m[3]])
			if v == "" {
				continue
			}
			hits = append(hits, hit{offset: m[0], value: v})
		}
	}
	if len(hits) == 0 {
		return nil
	}
	// Sort by offset of the match start in the source so first-appearance
	// order is independent of the pattern enumeration order. A small N
	// makes the cost negligible.
	for i := 1; i < len(hits); i++ {
		for j := i; j > 0 && hits[j-1].offset > hits[j].offset; j-- {
			hits[j-1], hits[j] = hits[j], hits[j-1]
		}
	}
	seen := make(map[string]struct{}, len(hits))
	out := make([]string, 0, len(hits))
	for _, h := range hits {
		if _, ok := seen[h.value]; ok {
			continue
		}
		seen[h.value] = struct{}{}
		out = append(out, h.value)
	}
	return out
}
