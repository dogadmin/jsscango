package extractor

import "regexp"

// Phase 4 URL-discovery patterns. These augment patterns_jsurl.go +
// patterns_apiurl.go with framework-specific endpoint shapes that the
// generic patterns miss. They produce Found values with explicit Kind so
// the crawler can route them like any other discovered URL.
//
// Each pattern carries an ID that surfaces in APIPath.Pattern / xlsx output,
// which is the lever Phase 4+ uses to tune false positives per scenario.

type extraPattern struct {
	ID    string
	Kind  string         // js | static | api
	Re    *regexp.Regexp
	Group int            // capture-group index; 0 = whole match
	Filt  func(string) (string, bool) // optional cleanup; nil = identity-keep
}

var extraPatterns = func() []extraPattern {
	mk := func(id, kind, pat string, group int, filt func(string) (string, bool)) extraPattern {
		return extraPattern{ID: id, Kind: kind, Re: regexp.MustCompile(pat), Group: group, Filt: filt}
	}
	return []extraPattern{
		// ---- Swagger / OpenAPI / GraphQL discovery -----------------------
		mk("swagger_doc", "api",
			`(?i)["'/]((?:v[0-9]+/)?(?:api-docs|swagger\.json|openapi\.json|swagger/index\.html))\b`, 1, nil),
		mk("openapi_yaml", "api",
			`(?i)["'/](openapi\.(?:ya?ml|json))\b`, 1, nil),
		mk("graphql_ep", "api",
			`(?i)["'/](graphql|gql|api/graphql)["'?]`, 1, nil),

		// ---- Source maps (point at original source paths) ----------------
		mk("sourcemap_ref", "static",
			`//#\s*sourceMappingURL=([^\s'"<>]+)`, 1, nil),

		// ---- Spring Cloud / Spring Boot service discovery ----------------
		mk("actuator_endpoint", "api",
			`["'/](actuator(?:/[a-z0-9_-]+)?)["']`, 1, nil),
		mk("eureka_endpoint", "api",
			`["'/](eureka/apps(?:/[^"'<>\s]*)?)["']`, 1, nil),

		// ---- Vite / Nuxt / Next bundle metadata --------------------------
		// Vite manifest is an asset map produced by `vite build`; finding it
		// often gives the full asset list.
		mk("vite_manifest", "api",
			`["'/]((?:assets/)?manifest\.json)["']`, 1, nil),
		// Nuxt 3 / Next chunk URLs use predictable naming.
		mk("nuxt_chunks", "js",
			`(_nuxt/[A-Za-z0-9._\-]+\.(?:js|mjs))\b`, 1, nil),
		// Next.js build ID is the most valuable thing to know - it gates
		// access to /_next/static/<buildid>/_buildManifest.js etc.
		mk("nextjs_build", "js",
			`(/_next/static/[A-Za-z0-9_\-]{8,}/_buildManifest\.js)`, 1, nil),

		// ---- Non-HTTP service URIs ---------------------------------------
		// Catches grpc://, dubbo://, nacos://, etc. embedded in JS or config.
		mk("rpc_scheme", "api",
			`\b((?:grpc|grpcs|thrift|dubbo|nacos|consul|etcd)://[^\s'"<>]+)`, 1, nil),

		// ---- Internal host references ------------------------------------
		// Catches localhost / RFC1918 / *.internal / *.corp etc leaked from
		// dev configs.
		mk("internal_host", "api",
			`(?i)\b((?:localhost|127\.0\.0\.1|10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|[a-z0-9\-]+\.(?:internal|intra|corp|lan|local))(?::\d{2,5})?)\b`, 1, nil),
	}
}()

// runExtraPatterns scans text once per extra pattern and returns Found
// candidates. Each candidate goes through the same dedup pass that
// FromJSBody applies to its main results.
func runExtraPatterns(text string) []Found {
	var out []Found
	for _, p := range extraPatterns {
		matches := p.Re.FindAllStringSubmatch(text, -1)
		for _, m := range matches {
			idx := p.Group
			if idx >= len(m) {
				idx = 0
			}
			value := m[idx]
			if p.Filt != nil {
				var ok bool
				value, ok = p.Filt(value)
				if !ok {
					continue
				}
			}
			value = strip(value)
			if value == "" {
				continue
			}
			out = append(out, Found{Kind: p.Kind, Value: value, Pattern: p.ID})
		}
	}
	return out
}
