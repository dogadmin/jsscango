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
