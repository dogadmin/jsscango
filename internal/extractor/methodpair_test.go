package extractor

import (
	"testing"
)

func containsPair(pairs []MethodPair, path, method string) bool {
	for _, p := range pairs {
		if p.Path == path && p.Method == method {
			return true
		}
	}
	return false
}

func TestDetectMethodPairs_Forward(t *testing.T) {
	body := []byte(`{url:"/auth/login",method:"get"}`)
	got := DetectMethodPairs(body)
	if !containsPair(got, "/auth/login", "GET") {
		t.Errorf("DetectMethodPairs() = %v, want pair (/auth/login, GET)", got)
	}
}

func TestDetectMethodPairs_Reverse(t *testing.T) {
	body := []byte(`{method:"DELETE",url:"/user/123"}`)
	got := DetectMethodPairs(body)
	if !containsPair(got, "/user/123", "DELETE") {
		t.Errorf("DetectMethodPairs() = %v, want pair (/user/123, DELETE)", got)
	}
}

func TestDetectMethodPairs_WithHeadersBetween(t *testing.T) {
	body := []byte(`{url:"/foo",headers:{"X-Auth":"bar"},params:{a:1},method:"PATCH"}`)
	got := DetectMethodPairs(body)
	if !containsPair(got, "/foo", "PATCH") {
		t.Errorf("DetectMethodPairs() = %v, want pair (/foo, PATCH)", got)
	}
}

func TestDetectMethodPairs_LowercaseUppercased(t *testing.T) {
	body := []byte(`{url:"/x",method:"post"}`)
	got := DetectMethodPairs(body)
	if !containsPair(got, "/x", "POST") {
		t.Errorf("DetectMethodPairs() = %v, want POST (uppercased)", got)
	}
	for _, p := range got {
		if p.Method == "post" {
			t.Errorf("method should be uppercased, got %q", p.Method)
		}
	}
}

func TestDetectMethodPairs_RejectsNonVerb(t *testing.T) {
	// "method:'GET HTTP'" wouldn't even capture (regex is [A-Za-z]+ only),
	// but a captured token that's not in the verb set (e.g. "fetch") must
	// be dropped.
	body := []byte(`{url:"/x",method:"fetch"}`)
	got := DetectMethodPairs(body)
	if len(got) != 0 {
		t.Errorf("DetectMethodPairs() = %v, want empty (fetch is not a verb)", got)
	}
}

func TestDetectMethodPairs_RejectsNonVerbWithGarbage(t *testing.T) {
	// Spaces in the method value break the [A-Za-z]+ class, so the regex
	// won't capture at all — this is the failure mode we want.
	body := []byte(`{url:"/x",method:"GET HTTP"}`)
	got := DetectMethodPairs(body)
	if len(got) != 0 {
		t.Errorf("DetectMethodPairs() = %v, want empty (GET HTTP must not match)", got)
	}
}

func TestDetectMethodPairs_BoundedDistance(t *testing.T) {
	// More than 200 chars between url and method should NOT pair them.
	// Build a body with lots of filler between.
	filler := make([]byte, 250)
	for i := range filler {
		filler[i] = 'x'
	}
	body := []byte(`{url:"/path",` + string(filler) + `,method:"GET"}`)
	got := DetectMethodPairs(body)
	if containsPair(got, "/path", "GET") {
		t.Errorf("DetectMethodPairs() = %v, want NO pair when distance > 200", got)
	}
}

func TestDetectMethodPairs_MultiplePairs(t *testing.T) {
	body := []byte(`
		const cfg1 = {url:"/a",method:"get"};
		const cfg2 = {url:"/b",method:"post"};
		const cfg3 = {method:"delete",url:"/c"};
	`)
	got := DetectMethodPairs(body)
	wants := []struct{ path, method string }{
		{"/a", "GET"},
		{"/b", "POST"},
		{"/c", "DELETE"},
	}
	for _, w := range wants {
		if !containsPair(got, w.path, w.method) {
			t.Errorf("missing pair (%q, %q) in %v", w.path, w.method, got)
		}
	}
}

func TestDetectMethodPairs_Dedup(t *testing.T) {
	// Same (path, method) appearing twice — should be deduplicated.
	body := []byte(`{url:"/x",method:"GET"};{url:"/x",method:"GET"}`)
	got := DetectMethodPairs(body)
	n := 0
	for _, p := range got {
		if p.Path == "/x" && p.Method == "GET" {
			n++
		}
	}
	if n != 1 {
		t.Errorf("DetectMethodPairs() emitted (%q, %q) %d times, want 1", "/x", "GET", n)
	}
}

func TestDetectMethodPairs_EmptyBody(t *testing.T) {
	if got := DetectMethodPairs(nil); got != nil {
		t.Errorf("DetectMethodPairs(nil) = %v, want nil", got)
	}
	if got := DetectMethodPairs([]byte{}); got != nil {
		t.Errorf("DetectMethodPairs(empty) = %v, want nil", got)
	}
}
