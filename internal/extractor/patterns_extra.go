package extractor

import (
	"regexp"
	"strings"
)

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
	// normalizeSlash prepends '/' to a captured path when it is missing. Used by
	// the extras filters so a relative ref "manifest.json" and an absolute ref
	// "/manifest.json" both emit "/manifest.json" - matching the generic api_2
	// pattern's output and letting dedupFound collapse the two emissions.
	normalizeSlash := func(s string) (string, bool) {
		if s == "" {
			return "", false
		}
		if !strings.HasPrefix(s, "/") && !strings.Contains(s, "://") {
			return "/" + s, true
		}
		return s, true
	}
	return []extraPattern{
		// ---- Swagger / OpenAPI / GraphQL discovery -----------------------
		mk("swagger_doc", "api",
			`(?i)["'](/?(?:v[0-9]+/)?(?:api-docs|swagger\.json|openapi\.json|swagger/index\.html))\b`, 1, normalizeSlash),
		mk("openapi_yaml", "api",
			`(?i)["'](/?openapi\.(?:ya?ml|json))\b`, 1, normalizeSlash),
		mk("graphql_ep", "api",
			`(?i)["'](/?(?:graphql|gql|api/graphql))["'?]`, 1, normalizeSlash),

		// ---- Source maps (point at original source paths) ----------------
		mk("sourcemap_ref", "static",
			`//#\s*sourceMappingURL=([^\s'"<>]+)`, 1, nil),

		// ---- Spring Cloud / Spring Boot service discovery ----------------
		mk("actuator_endpoint", "api",
			`["'](/?actuator(?:/[a-z0-9_-]+)?)["']`, 1, normalizeSlash),
		mk("eureka_endpoint", "api",
			`["'](/?eureka/apps(?:/[^"'<>\s]*)?)["']`, 1, normalizeSlash),

		// ---- Vite / Nuxt / Next bundle metadata --------------------------
		// Vite manifest is an asset map produced by `vite build`; finding it
		// often gives the full asset list.
		mk("vite_manifest", "api",
			`["'](/?(?:assets/)?manifest\.json)["']`, 1, normalizeSlash),
		// Nuxt 3 / Next chunk URLs use predictable naming.
		mk("nuxt_chunks", "js",
			`["'](/?_nuxt/[A-Za-z0-9._\-]+\.(?:js|mjs))\b`, 1, normalizeSlash),
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

		// ---- WebSocket / SSE / GraphQL client discovery ------------------
		// WebSocket and SSE patterns capture the URL directly from the
		// constructor call. ws:// / wss:// URLs flow through the regular
		// emit path; the probe stage will fail their first GET and skip on
		// (probing real WebSocket traffic is out of scope).
		mk("websocket_url", "api",
			`(?i)new\s+WebSocket\s*\(\s*['"]([^'"]+)['"]`, 1, nil),
		mk("sse_url", "api",
			`(?i)new\s+EventSource\s*\(\s*['"]([^'"]+)['"]`, 1, nil),
		// GraphQL client capture: log the operationName from a
		// client.query({ query: "query UserDetail ..." }) call. The value
		// is not a URL but a string worth surfacing - it tells the operator
		// "this app has a GraphQL operation called UserDetail" which is
		// investigable against the /graphql endpoint emitted elsewhere.
		mk("graphql_client_query", "api",
			`(?i)(?:client|apollo|gql)\.(?:query|mutate|subscribe)\s*\(\s*\{\s*(?:[a-z]+\s*:\s*[^,}]+,\s*)*query\s*:\s*['"]\s*(?:query|mutation|subscription)\s+([A-Za-z_][A-Za-z0-9_]*)`, 1, nil),
	}
}()
