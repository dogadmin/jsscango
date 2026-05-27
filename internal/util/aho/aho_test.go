package aho

import (
	"math/rand/v2"
	"strings"
	"testing"
)

func TestEmpty(t *testing.T) {
	m := New(nil)
	if m.Contains([]byte("anything")) {
		t.Error("empty matcher should never match")
	}
	m2 := New([]string{})
	if m2.ContainsString("anything") {
		t.Error("empty patterns should never match")
	}
}

func TestEmptyText(t *testing.T) {
	m := New([]string{"foo"})
	if m.ContainsString("") {
		t.Error("empty text should never match")
	}
}

func TestSinglePattern(t *testing.T) {
	m := New([]string{"foo"})
	cases := []struct {
		in   string
		want bool
	}{
		{"foo", true},
		{"the foo bar", true},
		{"foofoo", true},
		{"fo", false},
		{"oof", false},
		{"FOO", false}, // case-sensitive
	}
	for _, c := range cases {
		if got := m.ContainsString(c.in); got != c.want {
			t.Errorf("Contains(%q) = %v, want %v", c.in, got, c.want)
		}
	}
}

func TestMultiplePatterns(t *testing.T) {
	m := New([]string{"cat", "dog", "elephant"})
	for _, in := range []string{"a cat", "dogs", "elephantine"} {
		if !m.ContainsString(in) {
			t.Errorf("Contains(%q) = false, want true", in)
		}
	}
	for _, in := range []string{"bird", "fish", "zebra"} {
		if m.ContainsString(in) {
			t.Errorf("Contains(%q) = true, want false", in)
		}
	}
}

func TestSharedPrefix(t *testing.T) {
	// "he", "she", "his", "hers" - classic AC test for proper fail links.
	m := New([]string{"he", "she", "his", "hers"})
	for _, in := range []string{"he", "she", "his", "hers", "the cat is hiding", "ushers"} {
		if !m.ContainsString(in) {
			t.Errorf("Contains(%q) = false, want true", in)
		}
	}
}

func TestSubstringPattern(t *testing.T) {
	// "abc" is a substring of "abcdef". Both should match independently.
	m := New([]string{"abc", "abcdef"})
	if !m.ContainsString("xabcy") {
		t.Error("substring pattern should match")
	}
	if !m.ContainsString("xabcdefy") {
		t.Error("longer pattern should match")
	}
}

func TestUTF8(t *testing.T) {
	// Chinese BLACK_TEXT marker style.
	m := New([]string{"未找到API注册信息", "未登录"})
	if !m.ContainsString(`{"msg":"未找到API注册信息"}`) {
		t.Error("UTF-8 pattern should match")
	}
	if !m.ContainsString("用户未登录,请重试") {
		t.Error("UTF-8 short pattern should match")
	}
	if m.ContainsString("数据库连接错误") {
		t.Error("unrelated UTF-8 should not match")
	}
}

func TestParityWithStringsContains(t *testing.T) {
	patterns := []string{
		"application/json", "text/html", "image/png", "ssh-rsa AAAA",
		"BEGIN PRIVATE KEY", "Authorization: Bearer ", "AKIA", "未登录",
		"/api/v1/", "swagger-ui.html", "<title>", "{\"code\":401",
	}
	m := New(patterns)

	rng := rand.New(rand.NewPCG(1, 2))
	for trial := 0; trial < 200; trial++ {
		text := randomText(rng, 256)
		// Occasionally splice in a real pattern to ensure we exercise both
		// match and non-match branches.
		if trial%3 == 0 {
			p := patterns[trial%len(patterns)]
			pos := rng.IntN(len(text) + 1)
			text = text[:pos] + p + text[pos:]
		}

		got := m.ContainsString(text)
		want := false
		for _, p := range patterns {
			if strings.Contains(text, p) {
				want = true
				break
			}
		}
		if got != want {
			t.Fatalf("trial %d: AC=%v but strings.Contains=%v on %q",
				trial, got, want, text)
		}
	}
}

func randomText(rng *rand.Rand, n int) string {
	const alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 -_/:.{},\""
	b := make([]byte, n)
	for i := range b {
		b[i] = alphabet[rng.IntN(len(alphabet))]
	}
	return string(b)
}

// BenchmarkLinearVsAC compares the cost of "any of N substrings in body?"
// for N=256 patterns and a 64 KB body. We expect AC to be ~10-50x faster
// than the linear strings.Contains loop on this workload.
func BenchmarkLinearVsAC(b *testing.B) {
	patterns := make([]string, 256)
	rng := rand.New(rand.NewPCG(42, 42))
	for i := range patterns {
		// Realistic-length needles (8-32 chars).
		l := 8 + rng.IntN(24)
		s := make([]byte, l)
		for j := range s {
			s[j] = byte('a' + rng.IntN(26))
		}
		patterns[i] = string(s)
	}
	body := randomText(rng, 64*1024)
	// Splice in one real match near the end so neither variant gets a
	// free early-exit at the start.
	body = body + patterns[200]

	b.Run("linear", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			hit := false
			for _, p := range patterns {
				if strings.Contains(body, p) {
					hit = true
					break
				}
			}
			if !hit {
				b.Fatal("expected hit")
			}
		}
	})

	m := New(patterns)
	b.Run("aho", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			if !m.ContainsString(body) {
				b.Fatal("expected hit")
			}
		}
	})
}
