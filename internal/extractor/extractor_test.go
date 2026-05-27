package extractor

import (
	"strings"
	"testing"
)

func TestFromJSBody_FindsJSURLs(t *testing.T) {
	// The Python regexes (jsAndStaticUrlFind.py:191-196) all exclude ':' so
	// they only match quoted/assigned/root-relative .js paths. Full http(s)
	// JS URLs come in via the homepage HTML parser, not these regexes.
	body := []byte(`
		<script src="/static/js/app.abc123.js"></script>
		var u = "/lib/jquery.min.js";
		require("/chunks/runtime.js")
	`)
	got := FromJSBody(body)
	for _, want := range []string{
		"/static/js/app.abc123.js",
		"/lib/jquery.min.js",
		"/chunks/runtime.js",
	} {
		if !containsValue(got, "js", want) {
			t.Errorf("missing js result %q in %+v", want, got)
		}
	}
}

func TestFromJSBody_FullHTTPJSNotMatchedByJSPatterns(t *testing.T) {
	// Documented behavior parity with Python: full https://x.com/foo.js
	// URLs do NOT match js_patterns because ':' is in the negated class.
	// They also get filtered from static_paths by the .js suffix check.
	body := []byte(`var a = "https://cdn.acme-corp.com/lib/jquery.min.js";`)
	got := FromJSBody(body)
	for _, f := range got {
		if f.Kind == "js" && f.Value == "https://cdn.acme-corp.com/lib/jquery.min.js" {
			t.Error("full http JS URL should not be captured by js_patterns")
		}
		if f.Kind == "static" && f.Value == "https://cdn.acme-corp.com/lib/jquery.min.js" {
			t.Error("full http JS URL should be filtered from static results")
		}
	}
}

func TestFromJSBody_DomainBlacklistDropsExample(t *testing.T) {
	// The Python tool's blacklist drops example.com/github.com/etc.
	body := []byte(`var a = "/foo.js"; var b = "https://github.com/x/y";`)
	got := FromJSBody(body)
	for _, f := range got {
		if f.Kind == "static" && strings.Contains(f.Value, "github.com") {
			t.Errorf("github.com should be domain-blacklisted: %+v", f)
		}
	}
}

func TestFromJSBody_FindsAPIPaths(t *testing.T) {
	body := []byte(`
		const path = "/api/v1/user/list";
		fetch({ url: "/api/v2/auth/login", method: "POST" });
		const ENDPOINT = "/services/order/create";
	`)
	got := FromJSBody(body)
	for _, want := range []string{"/api/v1/user/list", "/api/v2/auth/login", "/services/order/create"} {
		if !containsValue(got, "api", want) {
			t.Errorf("missing api path %q in %+v", want, got)
		}
	}
}

func TestAPIFilter_RejectsFalsePositives(t *testing.T) {
	// css class, i18n key, webpack symbol — should all be filtered.
	body := []byte(`
		var cls = "header-light";
		var k = "common.button.submit.label";
		var s = "__webpack_require__";
	`)
	got := FromJSBody(body)
	for _, bad := range []string{"header-light", "common.button.submit.label", "__webpack_require__"} {
		if containsValue(got, "api", bad) {
			t.Errorf("false-positive predicate failed: %q kept as api", bad)
		}
	}
}

func TestAPIFilter_RejectsMIMELiterals(t *testing.T) {
	body := []byte(`headers["Content-Type"] = "application/json"; var b = "image/png";`)
	got := FromJSBody(body)
	for _, bad := range []string{"application/json", "image/png"} {
		if containsValue(got, "api", bad) {
			t.Errorf("MIME literal %q leaked as api", bad)
		}
	}
}

func TestJSFilter_StripsEscapes(t *testing.T) {
	in := `"\/static\/js\/app.js"`
	out, ok := jsFilter(in)
	if !ok || out != "/static/js/app.js" {
		t.Errorf("jsFilter(%q) = (%q,%v), want (/static/js/app.js,true)", in, out, ok)
	}
}

func TestJSFilter_DomainBlacklisted(t *testing.T) {
	if _, ok := jsFilter("https://github.com/x/y/foo.js"); ok {
		t.Error("github.com should be domain-blacklisted")
	}
}

func TestIsCSSClassName(t *testing.T) {
	yes := []string{"header-light", "btn", "footer"}
	no := []string{"/api/x", "Foo", "a.b.c", strings.Repeat("a", 30)}
	for _, s := range yes {
		if !isCSSClassName(s) {
			t.Errorf("isCSSClassName(%q) = false, want true", s)
		}
	}
	for _, s := range no {
		if isCSSClassName(s) {
			t.Errorf("isCSSClassName(%q) = true, want false", s)
		}
	}
}

func TestIsI18nKey(t *testing.T) {
	yes := []string{"common.button.submit", "ui.dialog.title.confirm"}
	no := []string{"/api/x", "single.dot", "a.b/c", "a.b.c?d"}
	for _, s := range yes {
		if !isI18nKey(s) {
			t.Errorf("isI18nKey(%q) = false, want true", s)
		}
	}
	for _, s := range no {
		if isI18nKey(s) {
			t.Errorf("isI18nKey(%q) = true, want false", s)
		}
	}
}

func TestWebpackChunks(t *testing.T) {
	// Real webpack runtime: the chunk map is concatenated directly without
	// the outer parens that I had in the first draft.
	body := `function jsonp(t){return e.p+"static/js/"+{"42":"abc123","57":"def456"}[t]+".js"}`
	chunks := webpackChunks(body)
	if len(chunks) != 2 {
		t.Fatalf("webpackChunks: got %d, want 2: %+v", len(chunks), chunks)
	}
	want := map[string]bool{
		"/static/js/42.abc123.js": false,
		"/static/js/57.def456.js": false,
	}
	for _, c := range chunks {
		if _, ok := want[c]; !ok {
			t.Errorf("unexpected chunk %q", c)
		}
		want[c] = true
	}
	for k, seen := range want {
		if !seen {
			t.Errorf("missing chunk %q", k)
		}
	}
}

func containsValue(found []Found, kind, value string) bool {
	for _, f := range found {
		if f.Kind == kind && f.Value == value {
			return true
		}
	}
	return false
}

func containsPattern(found []Found, patternID string) bool {
	for _, f := range found {
		if f.Pattern == patternID {
			return true
		}
	}
	return false
}

// Phase 4 new patterns coverage.

func TestExtraPatterns_Swagger(t *testing.T) {
	body := []byte(`location.href = "/v1/api-docs"; var swagger = "/swagger.json";`)
	got := FromJSBody(body)
	if !containsPattern(got, "swagger_doc") {
		t.Errorf("swagger_doc pattern not matched in %+v", got)
	}
}

func TestExtraPatterns_GraphQL(t *testing.T) {
	body := []byte(`fetch("/graphql"); axios.post("/api/graphql", q);`)
	got := FromJSBody(body)
	if !containsPattern(got, "graphql_ep") {
		t.Errorf("graphql_ep pattern not matched in %+v", got)
	}
}

func TestExtraPatterns_Sourcemap(t *testing.T) {
	body := []byte("function x(){}\n//# sourceMappingURL=app.js.map\n")
	got := FromJSBody(body)
	if !containsPattern(got, "sourcemap_ref") {
		t.Errorf("sourcemap_ref pattern not matched in %+v", got)
	}
}

func TestExtraPatterns_NextBuild(t *testing.T) {
	body := []byte(`s.src = "/_next/static/abcd1234efgh5678/_buildManifest.js";`)
	got := FromJSBody(body)
	if !containsPattern(got, "nextjs_build") {
		t.Errorf("nextjs_build pattern not matched in %+v", got)
	}
}

func TestExtraPatterns_NuxtChunks(t *testing.T) {
	body := []byte(`<script src="/_nuxt/entry.abc1.js"></script>`)
	got := FromJSBody(body)
	if !containsPattern(got, "nuxt_chunks") {
		t.Errorf("nuxt_chunks pattern not matched in %+v", got)
	}
}

func TestExtraPatterns_Actuator(t *testing.T) {
	body := []byte(`var ep = "/actuator/env";`)
	got := FromJSBody(body)
	if !containsPattern(got, "actuator_endpoint") {
		t.Errorf("actuator_endpoint pattern not matched in %+v", got)
	}
}

func TestExtraPatterns_InternalHost(t *testing.T) {
	body := []byte(`var srv = "internal-api.corp:8080"; var dev = "192.168.1.5";`)
	got := FromJSBody(body)
	if !containsPattern(got, "internal_host") {
		t.Errorf("internal_host pattern not matched in %+v", got)
	}
}

func TestExtraPatterns_RPCScheme(t *testing.T) {
	body := []byte(`provider = "dubbo://10.0.0.1:20880/Service"; nacos = "nacos://nacos.intra:8848";`)
	got := FromJSBody(body)
	if !containsPattern(got, "rpc_scheme") {
		t.Errorf("rpc_scheme pattern not matched in %+v", got)
	}
}

func TestExtraPatterns_WebSocket(t *testing.T) {
	body := []byte(`const ws = new WebSocket("wss://ws.example.com/socket");`)
	got := FromJSBody(body)
	if !containsPattern(got, "websocket_url") {
		t.Errorf("websocket_url pattern not matched in %+v", got)
	}
}

func TestExtraPatterns_SSE(t *testing.T) {
	body := []byte(`const es = new EventSource("/api/events/stream");`)
	got := FromJSBody(body)
	if !containsPattern(got, "sse_url") {
		t.Errorf("sse_url pattern not matched in %+v", got)
	}
}

func TestExtraPatterns_GraphQLClientQuery(t *testing.T) {
	body := []byte(`client.query({ variables: vars, query: "query UserDetail($id: ID!) { user(id:$id) { name } }" });`)
	got := FromJSBody(body)
	if !containsPattern(got, "graphql_client_query") {
		t.Errorf("graphql_client_query pattern not matched in %+v", got)
	}
}

// Framework-aware extraction: baseURL + method pair tests.

func TestFromJSBody_AxiosBaseURLResolves(t *testing.T) {
	body := []byte(`
		const api = axios.create({ baseURL: "/api", timeout: 5000 });
		api.get({ url: "/auth/login" });
	`)
	got := FromJSBody(body)
	if !containsValue(got, "api", "/api/auth/login") {
		t.Errorf("axios baseURL prefix not applied; want /api/auth/login in %+v", got)
	}
	// And the unprefixed value should NOT appear: it would represent the
	// old "miss the prefix" behavior.
	if containsValue(got, "api", "/auth/login") {
		t.Errorf("unprefixed /auth/login still emitted (baseURL not applied); got %+v", got)
	}
}

func TestFromJSBody_AxiosBaseURLIdempotent(t *testing.T) {
	// If the source already declared the path under the baseURL, we must
	// not double-prefix it ("/api/api/foo" is wrong).
	body := []byte(`
		const api = axios.create({ baseURL: "/api" });
		api.get({ url: "/api/already/prefixed" });
	`)
	got := FromJSBody(body)
	if !containsValue(got, "api", "/api/already/prefixed") {
		t.Errorf("idempotent baseURL: want /api/already/prefixed in %+v", got)
	}
	if containsValue(got, "api", "/api/api/already/prefixed") {
		t.Errorf("idempotent baseURL: double-prefixed value leaked in %+v", got)
	}
}

func TestFromJSBody_MethodAttached(t *testing.T) {
	body := []byte(`
		const cfg = { url: "/foo", method: "delete" };
		api(cfg);
	`)
	got := FromJSBody(body)
	found := false
	for _, f := range got {
		if f.Kind == "api" && f.Value == "/foo" && f.Method == "DELETE" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("method DELETE not attached to /foo Found; got %+v", got)
	}
}

func TestFromJSBody_BaseURLAndMethodTogether(t *testing.T) {
	// End-to-end: the scenario described in the bug report. baseURL is
	// declared on an axios instance and an inline config carries url +
	// method. The resolved Found should have both the prefix AND the verb.
	body := []byte(`
		const api = axios.create({ baseURL: "/api" });
		api({ url: "/users/42", method: "patch" });
	`)
	got := FromJSBody(body)
	ok := false
	for _, f := range got {
		if f.Kind == "api" && f.Value == "/api/users/42" && f.Method == "PATCH" {
			ok = true
			break
		}
	}
	if !ok {
		t.Errorf("expected Found{kind=api, value=/api/users/42, method=PATCH} in %+v", got)
	}
}

// TestFromJSBody_VueRouterRoutesNotApi covers the critical interaction
// between baseURL detection and Vue Router route reclassification. The
// route /leaveForm must NOT pick up the /api prefix that an axios.create
// baseURL would otherwise apply, while a real API call (/auth/login)
// must still get prefixed. Without the reclassification, the smoke run
// reported probing https://target/api/leaveForm — a wrong-namespace 404.
func TestFromJSBody_VueRouterRoutesNotApi(t *testing.T) {
	body := []byte(`
		var axios_inst = axios.create({baseURL:"/api"});
		var routes = [{path:"/leaveForm",name:"L",component:c}];
		axios_inst.get("/auth/login");
	`)
	got := FromJSBody(body)

	var foundRoute, foundAPI, leakedRouteAsAPI bool
	for _, f := range got {
		if f.Kind == "frontend_route" && f.Value == "/leaveForm" {
			foundRoute = true
		}
		if f.Kind == "api" && f.Value == "/api/auth/login" {
			foundAPI = true
		}
		// Either of these means the reclassification failed:
		//   - /leaveForm kept as api (no reclass)
		//   - /api/leaveForm leaked (reclass happened after baseURL paint)
		if f.Kind == "api" && (f.Value == "/leaveForm" || f.Value == "/api/leaveForm") {
			leakedRouteAsAPI = true
		}
	}
	if !foundRoute {
		t.Errorf("expected Found{kind=frontend_route, value=/leaveForm} in %+v", got)
	}
	if !foundAPI {
		t.Errorf("expected Found{kind=api, value=/api/auth/login} in %+v", got)
	}
	if leakedRouteAsAPI {
		t.Errorf("/leaveForm leaked as api (frontend_route reclass failed) in %+v", got)
	}
}

// TestFromJSBody_VueRouterChildrenRelativePath verifies that routes
// declared inside a children:[…] array — typically with a relative path
// like "sub" — get appended as their own frontend_route Found entries
// even when the api scan didn't pick them up.
func TestFromJSBody_VueRouterChildrenRelativePath(t *testing.T) {
	body := []byte(`var r = {path:"/parent",name:"P",component:c,children:[{path:"sub",name:"S",component:c}]};`)
	got := FromJSBody(body)
	wantValues := []string{"/parent", "/sub"}
	for _, want := range wantValues {
		found := false
		for _, f := range got {
			if f.Kind == "frontend_route" && f.Value == want {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("expected Found{kind=frontend_route, value=%q} in %+v", want, got)
		}
	}
}
