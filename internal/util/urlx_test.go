package util

import "testing"

func TestJoinNewURL(t *testing.T) {
	cases := []struct {
		name, scheme, base, rootPath, path, want string
	}{
		{"empty", "https", "https://x.com", "/", "", ""},
		{"just_slash", "https", "https://x.com", "/", "/", ""},
		{"double_slash", "https", "https://x.com", "/", "//", ""},
		{"absolute_http", "https", "https://x.com", "/", "http://y.com/a.js", "http://y.com/a.js"},
		{"absolute_https", "https", "https://x.com", "/", "https://y.com/a.js", "https://y.com/a.js"},
		{"protocol_rel", "https", "https://x.com", "/", "//cdn.x.com/a.js", "https://cdn.x.com/a.js"},
		{"root_rel", "https", "https://x.com", "/static/", "/api/v1", "https://x.com/api/v1"},
		{"js_prefix", "https", "https://x.com", "/static/", "js/foo.js", "https://x.com/js/foo.js"},
		{"multi_seg", "https", "https://x.com", "/static/", "lib/util/file.js", "https://x.com/lib/util/file.js"},
		{"relative_single", "https", "https://x.com", "/static/", "foo.js", "https://x.com/static/foo.js"},
		{"relative_no_trail", "https", "https://x.com", "/static", "foo.js", "https://x.com/static/foo.js"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := JoinNewURL(c.scheme, c.base, c.rootPath, c.path)
			if got != c.want {
				t.Errorf("JoinNewURL(%q,%q,%q,%q) = %q, want %q",
					c.scheme, c.base, c.rootPath, c.path, got, c.want)
			}
		})
	}
}

func TestSplitBase(t *testing.T) {
	cases := []struct {
		in, wantScheme, wantBase, wantRoot string
	}{
		{"https://x.com/static/js/app.js", "https", "https://x.com", "/static/js/"},
		{"https://x.com/", "https", "https://x.com", "/"},
		{"https://x.com", "https", "https://x.com", "/"},
		{"http://x.com:8080/a/b/c.js", "http", "http://x.com:8080", "/a/b/"},
	}
	for _, c := range cases {
		t.Run(c.in, func(t *testing.T) {
			s, b, r := SplitBase(c.in)
			if s != c.wantScheme || b != c.wantBase || r != c.wantRoot {
				t.Errorf("SplitBase(%q) = (%q,%q,%q), want (%q,%q,%q)",
					c.in, s, b, r, c.wantScheme, c.wantBase, c.wantRoot)
			}
		})
	}
}

func TestBaseDomain(t *testing.T) {
	cases := []struct{ in, want string }{
		{"https://www.example.com/", "example"},
		{"https://api.example.co.uk/x", "example"},
		{"http://192.168.1.1:8080/", "192.168.1.1"},
		{"https://localhost/", "localhost"},
		{"", ""},
	}
	for _, c := range cases {
		t.Run(c.in, func(t *testing.T) {
			if got := BaseDomain(c.in); got != c.want {
				t.Errorf("BaseDomain(%q) = %q, want %q", c.in, got, c.want)
			}
		})
	}
}

func TestSameSiteOrIP(t *testing.T) {
	cases := []struct {
		target, base string
		want         bool
	}{
		{"https://api.example.com/x", "example", true},
		{"https://example.com/", "example", true},
		{"https://other.com/", "example", false},
		{"http://10.0.0.1/", "example", true},
		// Known TODO-marked false positive — same loose substring match as
		// the Python source. If this ever turns into a `false`, update the
		// TODO in urlx.go too.
		{"https://evil-example-attacker.com/", "example", true},
	}
	for _, c := range cases {
		t.Run(c.target, func(t *testing.T) {
			if got := SameSiteOrIP(c.target, c.base); got != c.want {
				t.Errorf("SameSiteOrIP(%q,%q) = %v, want %v", c.target, c.base, got, c.want)
			}
		})
	}
}
