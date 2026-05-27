package probe

import (
	"testing"

	"github.com/dogadmin/jsscango/internal/fetcher"
)

func TestMethodsFor_HintAlwaysWins(t *testing.T) {
	// A non-empty Methods slice with a DELETE verb wins regardless of fan-out strategy.
	target := Target{URL: "https://x.com/api/leave/list", Methods: []string{"DELETE"}}
	for _, fanout := range []string{FanoutAll, FanoutConservative, FanoutActionAware, ""} {
		got := methodsFor(target, fanout)
		if len(got) != 1 || got[0] != fetcher.Method("DELETE") {
			t.Errorf("fanout=%q: hint should win; got %v", fanout, got)
		}
	}
}

func TestMethodsFor_AllFanout(t *testing.T) {
	got := methodsFor(Target{URL: "https://x.com/api/whatever"}, FanoutAll)
	want := []fetcher.Method{fetcher.MethodGET, fetcher.MethodPOSTForm, fetcher.MethodPOSTJSON}
	if !methodsEqual(got, want) {
		t.Errorf("all fanout: got %v, want %v", got, want)
	}
}

func TestMethodsFor_ConservativeFanout(t *testing.T) {
	got := methodsFor(Target{URL: "https://x.com/api/save"}, FanoutConservative)
	want := []fetcher.Method{fetcher.MethodGET}
	if !methodsEqual(got, want) {
		t.Errorf("conservative fanout: got %v, want %v", got, want)
	}
}

func TestMethodsFor_ActionAwareReadPath(t *testing.T) {
	// Paths without action words should be GET only.
	cases := []string{
		"https://x.com/api/users",
		"https://x.com/api/v2/leave/list",
		"https://x.com/api/system/info",
		"https://x.com/api/getInfo",
	}
	for _, u := range cases {
		got := methodsFor(Target{URL: u}, FanoutActionAware)
		if len(got) != 1 || got[0] != fetcher.MethodGET {
			t.Errorf("%s: expected GET only, got %v", u, got)
		}
	}
}

func TestMethodsFor_ActionAwareWritePath(t *testing.T) {
	// Paths with action words should be GET + POST_JSON.
	cases := []string{
		"https://x.com/api/user/create",
		"https://x.com/api/auth/login",
		"https://x.com/api/leave/submit",
		"https://x.com/api/user/delete/123",
		"https://x.com/api/file/upload",
	}
	for _, u := range cases {
		got := methodsFor(Target{URL: u}, FanoutActionAware)
		want := []fetcher.Method{fetcher.MethodGET, fetcher.MethodPOSTJSON}
		if !methodsEqual(got, want) {
			t.Errorf("%s: got %v, want %v", u, got, want)
		}
	}
}

func TestMethodsFor_EmptyStrategyDefaultsToActionAware(t *testing.T) {
	read := methodsFor(Target{URL: "https://x.com/api/users"}, "")
	if len(read) != 1 || read[0] != fetcher.MethodGET {
		t.Errorf("empty strategy on read path: got %v, want [GET]", read)
	}
	write := methodsFor(Target{URL: "https://x.com/api/users/create"}, "")
	want := []fetcher.Method{fetcher.MethodGET, fetcher.MethodPOSTJSON}
	if !methodsEqual(write, want) {
		t.Errorf("empty strategy on write path: got %v, want %v", write, want)
	}
}

func TestMethodsFor_UnknownStrategyFallsBackToActionAware(t *testing.T) {
	got := methodsFor(Target{URL: "https://x.com/api/users"}, "nonsense")
	if len(got) != 1 || got[0] != fetcher.MethodGET {
		t.Errorf("unknown strategy should fall back to action-aware GET, got %v", got)
	}
}

func TestMethodsFor_BadHintFallsBackToStrategy(t *testing.T) {
	// Hint contains only unrecognized verbs (CONNECT not supported) — the
	// strategy default kicks in.
	got := methodsFor(Target{URL: "https://x.com/api/users", Methods: []string{"CONNECT"}}, FanoutConservative)
	if len(got) != 1 || got[0] != fetcher.MethodGET {
		t.Errorf("bad hint + conservative: got %v, want [GET]", got)
	}
}

func methodsEqual(a, b []fetcher.Method) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
