package postprocess

import (
	"sort"
	"testing"
)

// TestWalkJSONForURLs_HATEOAS covers the canonical _links shape used by
// HAL/HATEOAS APIs. Each leaf object under _links has an href value that
// should be surfaced even though the matching key lives one level deep
// inside the nested object.
func TestWalkJSONForURLs_HATEOAS(t *testing.T) {
	body := []byte(`{"_links":{"self":{"href":"/api/v1/users/1"},"items":{"href":"/api/v1/users/1/items"}}}`)
	got := WalkJSONForURLs(body)
	want := []string{"/api/v1/users/1", "/api/v1/users/1/items"}
	if !sameSet(got, want) {
		t.Errorf("HATEOAS walk: got %v, want %v", got, want)
	}
}

// TestWalkJSONForURLs_NestedRoutes covers Vue-router-style route tables
// where path values live in array elements and a nested meta object holds
// an endpoint reference. Exercises the recursion-into-nested-map path
// from a structurally realistic JSON shape.
func TestWalkJSONForURLs_NestedRoutes(t *testing.T) {
	body := []byte(`{"routes":[{"path":"/admin/dashboard","name":"admin"},{"path":"/profile","meta":{"endpoint":"/api/v1/me"}}]}`)
	got := WalkJSONForURLs(body)
	for _, want := range []string{"/admin/dashboard", "/profile", "/api/v1/me"} {
		if !contains(got, want) {
			t.Errorf("nested routes walk: missing %q in %v", want, got)
		}
	}
}

// TestWalkJSONForURLs_JunkFiltered covers the explicit junk filters from
// the design: empty strings, bare fragments, and pseudo-URL schemes all
// drop on the floor.
func TestWalkJSONForURLs_JunkFiltered(t *testing.T) {
	cases := []struct {
		name string
		body []byte
	}{
		{"bare-fragment", []byte(`{"href":"#"}`)},
		{"data-url", []byte(`{"url":"data:image/png;base64,iVBORw0KGgo="}`)},
		{"blob-url", []byte(`{"url":"blob:https://example.com/abc"}`)},
		{"javascript-url", []byte(`{"href":"javascript:void(0)"}`)},
		{"empty-string", []byte(`{"href":""}`)},
		{"single-char", []byte(`{"href":"a"}`)},
		{"contains-newline", []byte(`{"href":"foo\nbar"}`)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := WalkJSONForURLs(tc.body)
			if len(got) != 0 {
				t.Errorf("expected junk filter to drop %s, got %v", tc.name, got)
			}
		})
	}
}

// TestWalkJSONForURLs_RequiresURLShape covers the tightened predicate:
// bare tokens that happen to live under a URL-bearing key must NOT be
// emitted as URLs (otherwise the probe stage burns three requests per
// false-positive), while values that look like real URLs - schemed,
// root-relative, relative, or slash-containing with at least one alpha
// char - still pass through.
func TestWalkJSONForURLs_RequiresURLShape(t *testing.T) {
	rejectCases := []struct {
		name string
		body []byte
	}{
		{"bare-token-submit", []byte(`{"action":"submit"}`)},
		{"bare-token-users", []byte(`{"href":"users"}`)},
		{"bare-token-true", []byte(`{"url":"true"}`)},
		{"numeric-path", []byte(`{"path":"1/2/3"}`)},
	}
	for _, tc := range rejectCases {
		t.Run(tc.name, func(t *testing.T) {
			got := WalkJSONForURLs(tc.body)
			if len(got) != 0 {
				t.Errorf("expected URL-shape filter to drop %s, got %v", tc.name, got)
			}
		})
	}

	acceptCases := []struct {
		name string
		body []byte
		want string
	}{
		{"slash-with-alpha", []byte(`{"path":"v1/users"}`), "v1/users"},
		{"relative-path", []byte(`{"href":"./assets/foo.js"}`), "./assets/foo.js"},
		{"ws-scheme", []byte(`{"url":"ws://realtime.example.com/socket"}`), "ws://realtime.example.com/socket"},
		{"root-relative", []byte(`{"endpoint":"/api/v1/users"}`), "/api/v1/users"},
		{"https-scheme", []byte(`{"href":"https://example.com/x"}`), "https://example.com/x"},
	}
	for _, tc := range acceptCases {
		t.Run(tc.name, func(t *testing.T) {
			got := WalkJSONForURLs(tc.body)
			if len(got) != 1 || got[0] != tc.want {
				t.Errorf("expected URL-shape filter to keep %s, got %v, want [%q]", tc.name, got, tc.want)
			}
		})
	}
}

// TestWalkJSONForURLs_NonJSON covers non-JSON inputs returning nil (not
// an empty non-nil slice) so the caller's `for _, u := range nil` is a
// no-op without an allocation.
func TestWalkJSONForURLs_NonJSON(t *testing.T) {
	if got := WalkJSONForURLs([]byte("not json")); got != nil {
		t.Errorf("non-JSON: got %v, want nil", got)
	}
	if got := WalkJSONForURLs(nil); got != nil {
		t.Errorf("nil body: got %v, want nil", got)
	}
	if got := WalkJSONForURLs([]byte("")); got != nil {
		t.Errorf("empty body: got %v, want nil", got)
	}
}

// TestWalkJSONForURLs_Dedup verifies that the same URL appearing under two
// different matching keys (and from two structural positions) is reported
// once, preserving first-seen order.
func TestWalkJSONForURLs_Dedup(t *testing.T) {
	body := []byte(`{"href":"/x","items":[{"url":"/x"},{"href":"/y"}]}`)
	got := WalkJSONForURLs(body)
	if len(got) != 2 {
		t.Errorf("dedup: got %v entries %v, want 2 (/x, /y)", len(got), got)
	}
	if !contains(got, "/x") || !contains(got, "/y") {
		t.Errorf("dedup: missing values in %v", got)
	}
}

// TestWalkJSONForURLs_ArrayRoot covers JSON arrays at the top level - some
// APIs return `[{...},{...}]` directly without an enclosing object.
func TestWalkJSONForURLs_ArrayRoot(t *testing.T) {
	body := []byte(`[{"url":"/a"},{"url":"/b"}]`)
	got := WalkJSONForURLs(body)
	for _, want := range []string{"/a", "/b"} {
		if !contains(got, want) {
			t.Errorf("array root: missing %q in %v", want, got)
		}
	}
}

// TestWalkJSONForURLs_IgnoresNonStringValues confirms that a matching key
// whose value is a number/bool/null is skipped (not coerced) - we only
// want to surface honest-to-goodness string values.
func TestWalkJSONForURLs_IgnoresNonStringValues(t *testing.T) {
	body := []byte(`{"href":123,"url":null,"link":true,"endpoint":"/ok"}`)
	got := WalkJSONForURLs(body)
	if len(got) != 1 || got[0] != "/ok" {
		t.Errorf("ignore non-string: got %v, want [/ok]", got)
	}
}

func contains(haystack []string, needle string) bool {
	for _, s := range haystack {
		if s == needle {
			return true
		}
	}
	return false
}

func sameSet(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	ac := append([]string{}, a...)
	bc := append([]string{}, b...)
	sort.Strings(ac)
	sort.Strings(bc)
	for i := range ac {
		if ac[i] != bc[i] {
			return false
		}
	}
	return true
}
