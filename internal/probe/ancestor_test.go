package probe

import (
	"reflect"
	"testing"
)

func TestDeriveAncestors(t *testing.T) {
	cases := []struct {
		in    string
		depth int
		want  []string
	}{
		{"https://x.com/api/v2/leave/list/123", 2,
			[]string{"https://x.com/api/v2/leave/list/", "https://x.com/api/v2/leave/"}},
		{"https://x.com/api/v2/leave/list/123/", 2,
			[]string{"https://x.com/api/v2/leave/list/", "https://x.com/api/v2/leave/"}},
		{"https://x.com/a/b", 2, []string{"https://x.com/a/"}},
		{"https://x.com/a", 2, nil},
		{"https://x.com/", 2, nil},
		{"https://x.com/api/v2/leave/list/123", 0, nil},
		{"https://x.com/api/v2/leave/list/123?q=1#z", 2,
			[]string{"https://x.com/api/v2/leave/list/", "https://x.com/api/v2/leave/"}},
		// depth=5 on a 4-segment path: only 3 ancestors possible.
		{"https://x.com/a/b/c/d", 5,
			[]string{"https://x.com/a/b/c/", "https://x.com/a/b/", "https://x.com/a/"}},
	}
	for _, tc := range cases {
		got, err := DeriveAncestors(tc.in, tc.depth)
		if err != nil {
			t.Errorf("DeriveAncestors(%q, %d) unexpected err: %v", tc.in, tc.depth, err)
			continue
		}
		if !reflect.DeepEqual(got, tc.want) {
			t.Errorf("DeriveAncestors(%q, %d) = %v, want %v", tc.in, tc.depth, got, tc.want)
		}
	}
}

func TestDeriveAncestors_InvalidURL(t *testing.T) {
	_, err := DeriveAncestors("://broken", 2)
	if err == nil {
		t.Fatal("expected error from malformed URL")
	}
}

// Confirms ancestors never change the target host (cross-target safety).
// DeriveAncestors only mutates u.Path, so this is structural — the test
// pins it.
func TestDeriveAncestors_SameHost(t *testing.T) {
	parents, err := DeriveAncestors("https://api.x.com:8443/a/b/c/d", 2)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	for _, p := range parents {
		if !startsWith(p, "https://api.x.com:8443/") {
			t.Errorf("ancestor %q changed host or scheme", p)
		}
	}
}

func startsWith(s, pfx string) bool {
	return len(s) >= len(pfx) && s[:len(pfx)] == pfx
}
