package extractor

import (
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// updateGolden, when set, rewrites the *.want.json baselines from the live
// extractor output rather than asserting against them. Mirrors the common
// `-update` idiom used by Go's stdlib (see net/http/httputil examples).
//
//	go test -run TestGolden -update ./internal/extractor/
var updateGolden = flag.Bool("update", false, "rewrite testdata/*.want.json from current extractor output")

// TestGolden locks in FromJSBody's output against committed JSON baselines.
// Each fixture_*.js under testdata/ is paired with fixture_*.want.json; the
// test loads the fixture, runs the extractor, sorts both slices on
// (Kind,Value,Pattern), and diffs element-by-element.
func TestGolden(t *testing.T) {
	matches, err := filepath.Glob(filepath.Join("testdata", "fixture_*.js"))
	if err != nil {
		t.Fatalf("glob testdata/fixture_*.js: %v", err)
	}
	if len(matches) == 0 {
		t.Fatal("no testdata/fixture_*.js fixtures found")
	}
	sort.Strings(matches)

	for _, fixture := range matches {
		fixture := fixture
		t.Run(filepath.Base(fixture), func(t *testing.T) {
			body, err := os.ReadFile(fixture)
			if err != nil {
				t.Fatalf("read fixture: %v", err)
			}
			got := FromJSBody(body)
			sortFound(got)

			wantPath := strings.TrimSuffix(fixture, ".js") + ".want.json"

			if *updateGolden {
				data, err := json.MarshalIndent(got, "", "  ")
				if err != nil {
					t.Fatalf("marshal golden: %v", err)
				}
				// Trailing newline keeps the file POSIX-clean and diff-friendly.
				data = append(data, '\n')
				if err := os.WriteFile(wantPath, data, 0o644); err != nil {
					t.Fatalf("write golden %s: %v", wantPath, err)
				}
				t.Logf("updated %s (%d entries)", wantPath, len(got))
				return
			}

			raw, err := os.ReadFile(wantPath)
			if err != nil {
				if os.IsNotExist(err) {
					t.Skipf("no golden file %s yet; run `go test -update` to create it", wantPath)
					return
				}
				t.Fatalf("read golden %s: %v", wantPath, err)
			}
			var want []Found
			if err := json.Unmarshal(raw, &want); err != nil {
				t.Fatalf("unmarshal golden %s: %v", wantPath, err)
			}
			sortFound(want)

			diffFound(t, got, want, fixture, wantPath)
		})
	}
}

// sortFound orders a Found slice in place by (Kind, Value, Pattern) so the
// golden comparison is independent of extractor pattern-order quirks.
func sortFound(fs []Found) {
	sort.Slice(fs, func(i, j int) bool {
		if fs[i].Kind != fs[j].Kind {
			return fs[i].Kind < fs[j].Kind
		}
		if fs[i].Value != fs[j].Value {
			return fs[i].Value < fs[j].Value
		}
		return fs[i].Pattern < fs[j].Pattern
	})
}

// diffFound reports element-by-element mismatches between got and want.
// Both inputs are assumed sorted. The output lists extras (in got but not
// want) and missing (in want but not got) — adequate for eyeballing without
// pulling in go-cmp.
func diffFound(t *testing.T, got, want []Found, fixture, wantPath string) {
	t.Helper()

	type key struct{ k, v, p string }
	keyOf := func(f Found) key { return key{f.Kind, f.Value, f.Pattern} }

	gotSet := make(map[key]struct{}, len(got))
	for _, f := range got {
		gotSet[keyOf(f)] = struct{}{}
	}
	wantSet := make(map[key]struct{}, len(want))
	for _, f := range want {
		wantSet[keyOf(f)] = struct{}{}
	}

	var extras, missing []Found
	for _, f := range got {
		if _, ok := wantSet[keyOf(f)]; !ok {
			extras = append(extras, f)
		}
	}
	for _, f := range want {
		if _, ok := gotSet[keyOf(f)]; !ok {
			missing = append(missing, f)
		}
	}

	if len(extras) == 0 && len(missing) == 0 {
		return
	}

	var b strings.Builder
	b.WriteString("golden mismatch for ")
	b.WriteString(fixture)
	b.WriteString("\n  want file: ")
	b.WriteString(wantPath)
	b.WriteString("\n  got ")
	b.WriteString(itoa(len(got)))
	b.WriteString(" entries, want ")
	b.WriteString(itoa(len(want)))
	b.WriteString(" entries\n")

	if len(extras) > 0 {
		b.WriteString("\n  extras (in got, missing from golden):\n")
		for _, f := range extras {
			b.WriteString("    + ")
			b.WriteString(formatFound(f))
			b.WriteByte('\n')
		}
	}
	if len(missing) > 0 {
		b.WriteString("\n  missing (in golden, missing from got):\n")
		for _, f := range missing {
			b.WriteString("    - ")
			b.WriteString(formatFound(f))
			b.WriteByte('\n')
		}
	}
	b.WriteString("\n  rerun with -update to refresh the golden file once the new output is intentional.\n")
	t.Error(b.String())
}

func formatFound(f Found) string {
	return "kind=" + f.Kind + " pattern=" + f.Pattern + " value=" + f.Value
}

// itoa is a tiny non-allocating int->string used only for diff output.
// strconv would also work; this keeps the dependency surface minimal.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}
