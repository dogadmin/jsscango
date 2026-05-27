package pipeline

import (
	"sort"
	"strings"
	"testing"

	"github.com/dogadmin/jsscango/internal/probe"
	"github.com/dogadmin/jsscango/internal/types"
)

// targetMainCom is the canonical test target: https://main.com/ with
// BaseDomain "main" (eTLD+1 short label, matching what util.BaseDomain
// returns).
func targetMainCom() types.Target {
	return types.Target{
		URL:        "https://main.com/",
		Scheme:     "https",
		Host:       "main.com",
		BaseDomain: "main",
	}
}

// urlSet pulls just the URL strings out of a slice of probe.Target for
// substring-style assertions.
func urlSet(ts []probe.Target) []string {
	out := make([]string, len(ts))
	for i, t := range ts {
		out[i] = t.URL
	}
	sort.Strings(out)
	return out
}

func containsURL(ts []probe.Target, want string) bool {
	for _, t := range ts {
		if t.URL == want {
			return true
		}
	}
	return false
}

// TestPermutate_MultiHostDerivation covers §A (tree_urls): when the
// chromedp listener captured an XHR on a sibling host (api.main.com),
// extracted apiPaths from JS on the homepage should be combined against
// that sibling-host base too. Two flavours:
//
//   - Direct attachment: when there IS api-prefix evidence (e.g. seed
//     contains "/api/" or extracted path does), tree_urls × suffix
//     produces sibling-host URLs without needing the /api fallback.
//   - /api fallback: in single-target mode without api-prefix evidence,
//     the fallback inserts /api, giving https://api.main.com/api/...
func TestPermutate_MultiHostDerivation(t *testing.T) {
	target := targetMainCom()

	t.Run("with api-prefix evidence in seed, sibling host is a base", func(t *testing.T) {
		// `/users` in the extracted paths plus a sibling-host seed
		// that ends in `/v1/users` creates the truncation inference
		// "https://api.main.com/v1" as a base.
		discovered := []types.DiscoveredURL{
			{URL: "https://api.main.com/v1/users", Kind: types.KindNoJS},
		}
		apiPaths := []string{"/users", "/api/auth/login"}
		out := PermutateTargets(target, discovered, apiPaths, nil, false)
		// "/api/auth/login" splits into prefix "/api" + suffix "/auth/login".
		// Bases include https://api.main.com (tree) and
		// https://api.main.com/v1 (truncation). So one expected URL is
		// https://api.main.com/api/auth/login.
		if !containsURL(out, "https://api.main.com/api/auth/login") {
			t.Errorf("expected permutation onto sibling host api.main.com; got %v", urlSet(out))
		}
	})

	t.Run("single-target /api fallback reaches sibling host", func(t *testing.T) {
		discovered := []types.DiscoveredURL{
			{URL: "https://api.main.com/v1/users", Kind: types.KindNoJS},
		}
		apiPaths := []string{"/auth/login"}
		out := PermutateTargets(target, discovered, apiPaths, nil, true)
		// /api fallback × /auth/login → https://api.main.com/api/auth/login.
		// AND the fallback's "bare base" special case yields
		// https://api.main.com/auth/login.
		if !containsURL(out, "https://api.main.com/api/auth/login") &&
			!containsURL(out, "https://api.main.com/auth/login") {
			t.Errorf("expected /api fallback to reach sibling host api.main.com; got %v", urlSet(out))
		}
	})
}

// TestPermutate_TruncationInference covers §B: when an extracted apiPath
// appears as a substring of a discovered seed's URL path, the prefix
// becomes a base.
func TestPermutate_TruncationInference(t *testing.T) {
	target := types.Target{
		URL:        "https://x.com/",
		Scheme:     "https",
		Host:       "x.com",
		BaseDomain: "x",
	}
	discovered := []types.DiscoveredURL{
		{URL: "https://x.com/dddd/eee/fff", Kind: types.KindNoJS},
	}
	apiPaths := []string{"/eee/fff"}

	out := PermutateTargets(target, discovered, apiPaths, nil, true)
	// base "https://x.com/dddd" + path "/eee/fff" → must appear.
	if !containsURL(out, "https://x.com/dddd/eee/fff") {
		t.Errorf("expected truncation-inferred base /dddd × /eee/fff; got %v", urlSet(out))
	}
}

// TestPermutate_APIPrefixSplitForwardAndReverse covers §C (no_js URL with
// "api/" in path) and §D (extracted path with "api/" in it).
func TestPermutate_APIPrefixSplitForwardAndReverse(t *testing.T) {
	target := types.Target{
		URL:        "https://x.com/",
		Scheme:     "https",
		Host:       "x.com",
		BaseDomain: "x",
	}
	t.Run("no_js url contributes /prod-api base", func(t *testing.T) {
		discovered := []types.DiscoveredURL{
			{URL: "https://x.com/prod-api/health", Kind: types.KindNoJS},
		}
		apiPaths := []string{"/auth/login"}
		out := PermutateTargets(target, discovered, apiPaths, nil, true)
		if !containsURL(out, "https://x.com/prod-api/auth/login") {
			t.Errorf("expected base derived from /prod-api/health combined with /auth/login; got %v", urlSet(out))
		}
	})
	t.Run("extracted /gateway/api/users splits into prefix+suffix", func(t *testing.T) {
		// No no_js URLs; only the apiPath drives both halves.
		apiPaths := []string{"/gateway/api/users"}
		out := PermutateTargets(target, nil, apiPaths, nil, true)
		// Expect a permuted URL that has the synthesised
		// "/gateway/api" prefix joined with the "/users" suffix.
		// Discovered is empty so only tree_url candidates from
		// no_js are missing — but with no bases, there's also no
		// place to attach the suffix. To make this test meaningful,
		// add a tree_url-bearing seed (the homepage itself, captured
		// as no_js).
		discovered := []types.DiscoveredURL{
			{URL: "https://x.com/", Kind: types.KindNoJS},
		}
		out = PermutateTargets(target, discovered, apiPaths, nil, true)
		want := "https://x.com/gateway/api/users"
		if !containsURL(out, want) {
			t.Errorf("expected %s in permutation; got %v", want, urlSet(out))
		}
	})
}

// TestPermutate_APIFallbackRespectsSingleTargetGate covers §F: the
// "/api" fallback only fires when isSingleTarget=true.
func TestPermutate_APIFallbackRespectsSingleTargetGate(t *testing.T) {
	target := targetMainCom()
	// no extracted api paths at all, just a homepage no_js (so we have
	// at least one tree_url to attach the fallback to).
	discovered := []types.DiscoveredURL{
		{URL: "https://main.com/", Kind: types.KindNoJS},
	}
	apiPaths := []string{} // empty → triggers fallback decision

	t.Run("single target → fallback ON, but no path_with_no_api means nothing emitted unless we have a path. Skip emission expected.", func(t *testing.T) {
		out := PermutateTargets(target, discovered, apiPaths, nil, true)
		// With apiPaths empty, path_with_no_api_paths is empty too.
		// Python's cartesian × empty = empty. So we expect no output.
		if len(out) != 0 {
			t.Errorf("with no extracted paths and no suffix to cross-product, expected 0 results; got %v", urlSet(out))
		}
	})
	t.Run("single target with a no-api extracted path triggers fallback × suffix", func(t *testing.T) {
		out := PermutateTargets(target, discovered, []string{"/users"}, nil, true)
		// /api fallback × /users → https://main.com/api/users.
		if !containsURL(out, "https://main.com/api/users") {
			t.Errorf("expected /api fallback × /users → https://main.com/api/users in single-target mode; got %v", urlSet(out))
		}
	})
	t.Run("batch target with no api evidence emits nothing", func(t *testing.T) {
		out := PermutateTargets(target, discovered, []string{"/users"}, nil, false)
		// Batch mode: the /api fallback is suppressed AND there is no
		// other api-prefix source, so path_with_api_paths is empty,
		// the cartesian collapses to zero.
		if len(out) != 0 {
			t.Errorf("expected 0 results in batch mode without api-prefix evidence; got %v", urlSet(out))
		}
	})
}

// TestPermutate_SameBaseDomainFilter ensures no_js URLs from third-party
// hosts (e.g. CDN, evil.com) are NOT used as permutation bases.
func TestPermutate_SameBaseDomainFilter(t *testing.T) {
	target := targetMainCom()
	discovered := []types.DiscoveredURL{
		{URL: "https://evil.com/prod-api/x", Kind: types.KindNoJS},
		{URL: "https://main.com/", Kind: types.KindNoJS},
	}
	apiPaths := []string{"/auth/login"}

	out := PermutateTargets(target, discovered, apiPaths, nil, true)
	for _, t2 := range out {
		if strings.Contains(t2.URL, "evil.com") {
			t.Errorf("evil.com leaked into permutation set: %s", t2.URL)
		}
	}
}

// TestPermutate_MethodHintPropagation ensures that when an extractor
// declared a method for a path, the permuted URLs derived from that
// path carry the Methods hint.
func TestPermutate_MethodHintPropagation(t *testing.T) {
	target := types.Target{
		URL:        "https://main.com/",
		Scheme:     "https",
		Host:       "main.com",
		BaseDomain: "main",
	}
	discovered := []types.DiscoveredURL{
		{URL: "https://main.com/prod-api/health", Kind: types.KindNoJS},
	}
	apiPaths := []string{"/auth/login"}
	hints := map[string]string{"/auth/login": "POST"}

	out := PermutateTargets(target, discovered, apiPaths, hints, true)
	want := "https://main.com/prod-api/auth/login"
	found := false
	for _, t2 := range out {
		if t2.URL == want {
			found = true
			if len(t2.Methods) != 1 || t2.Methods[0] != "POST" {
				t.Errorf("expected Methods=[POST] on %s; got %v", want, t2.Methods)
			}
		}
	}
	if !found {
		t.Errorf("expected %s in permutation; got %v", want, urlSet(out))
	}
}

// TestPermutate_DedupAgainstPrimary covers the case where a permuted URL
// would equal a primary buildProbeTargets URL. The caller dedupes via
// dedupTargets; we test that here.
func TestPermutate_DedupAgainstPrimary(t *testing.T) {
	primary := []probe.Target{
		{URL: "https://main.com/api/users", Methods: []string{"POST"}},
	}
	perm := []probe.Target{
		{URL: "https://main.com/api/users", Methods: []string{"GET"}}, // duplicate
		{URL: "https://main.com/api/other"},                            // unique
	}
	combined := dedupTargets(append(primary, perm...))
	if len(combined) != 2 {
		t.Fatalf("expected 2 after dedup; got %d (%v)", len(combined), urlSet(combined))
	}
	// First-occurrence wins: the primary's POST hint must survive.
	for _, c := range combined {
		if c.URL == "https://main.com/api/users" {
			if len(c.Methods) != 1 || c.Methods[0] != "POST" {
				t.Errorf("dedup should keep first-seen Methods (POST); got %v", c.Methods)
			}
		}
	}
}

// TestPermutate_CollapseDoubleSlash ensures any accidental // produced
// by base+path concatenation is squashed to /.
func TestPermutate_CollapseDoubleSlash(t *testing.T) {
	got := collapseDoubleSlash("https://x.com//api//users")
	if got != "https://x.com/api/users" {
		t.Errorf("collapseDoubleSlash failed: got %q", got)
	}
}

// TestPermutate_NoHomepageEmitted asserts the permutation never emits
// a URL whose path is empty or just "/".
func TestPermutate_NoHomepageEmitted(t *testing.T) {
	target := targetMainCom()
	discovered := []types.DiscoveredURL{
		{URL: "https://main.com/", Kind: types.KindNoJS},
	}
	apiPaths := []string{"/api/users"}

	out := PermutateTargets(target, discovered, apiPaths, nil, true)
	for _, t2 := range out {
		// Strip the scheme://host and check the remaining path.
		rest := strings.TrimPrefix(t2.URL, "https://main.com")
		if rest == "" || rest == "/" {
			t.Errorf("permutation emitted homepage-equivalent URL: %s", t2.URL)
		}
	}
}
