package extractor

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// A union groups sub-patterns of the SAME tier into a single regex so we
// can find any tier-N match in one scan of the body. We don't union across
// tiers because RE2's leftmost-first semantics would then let a generic
// pattern (e.g. static_2 `["']/...`) win over a more-specific extras
// pattern (e.g. graphql_ep `["'/](graphql|...)`) whenever the generic
// pattern can start one byte earlier. Keeping tiers separate preserves the
// per-pattern semantics of the legacy code: within a tier the patterns are
// near-disjoint in their start positions so leftmost-first lines up with
// "first matching alternative", and dedup across tiers keeps the
// higher-priority emission (extras run first).
type union struct {
	re      *regexp.Regexp
	entries []unionEntry
	slots   []int // SubexpIndex per entry, parallel to entries
}

type unionEntry struct {
	ID        string
	Kind      string
	Src       string                      // sub-pattern source (kept so finalize can wrap it)
	Filt      func(string) (string, bool) // operates on the *raw* matched substring
	SubOffset int                         // 0 = named group itself; >0 = inner capture
}

var (
	extrasUnion *union
	jsUnion     *union
	staticUnion *union
	apiUnion    *union
)

func init() {
	rebuildUnions()
}

func rebuildUnions() {
	// Extras tier - framework-specific high-signal patterns.
	{
		u := &union{}
		for _, p := range extraPatterns {
			u.add(p.Re.String(), p.ID, p.Kind, wrapExtraFilt(p.Filt), p.Group)
		}
		u.finalize()
		extrasUnion = u
	}
	// JS tier.
	{
		u := &union{}
		for i, re := range jsPatterns {
			u.add(re.String(), jsPatternID(i), "js", jsFilterRaw, 0)
		}
		u.finalize()
		jsUnion = u
	}
	// Static tier.
	{
		u := &union{}
		for i, re := range staticPatterns {
			u.add(re.String(), staticPatternID(i), "static", staticFilterRaw, 0)
		}
		u.finalize()
		staticUnion = u
	}
	// API tier.
	{
		u := &union{}
		for i, src := range apiPatternsSrc {
			u.add(src, apiPatternID(i), "api", apiURLFilterRaw, apiPatternGroups[i])
		}
		u.finalize()
		apiUnion = u
	}
}

func (u *union) add(src, id, kind string, filt func(string) (string, bool), subOff int) {
	sub, err := regexp.Compile(src)
	if err != nil {
		panic(fmt.Sprintf("union: pattern %q failed to compile: %v", id, err))
	}
	if subOff < 0 || subOff > sub.NumSubexp() {
		panic(fmt.Sprintf("union: pattern %q has %d sub-captures, asked for offset %d", id, sub.NumSubexp(), subOff))
	}
	u.entries = append(u.entries, unionEntry{ID: id, Kind: kind, Src: src, Filt: filt, SubOffset: subOff})
}

func (u *union) finalize() {
	if len(u.entries) == 0 {
		return
	}
	parts := make([]string, len(u.entries))
	for i, e := range u.entries {
		parts[i] = "(?P<u" + strconv.Itoa(i) + ">" + e.Src + ")"
	}
	u.re = regexp.MustCompile(strings.Join(parts, "|"))
	u.slots = make([]int, len(u.entries))
	for i := range u.entries {
		u.slots[i] = u.re.SubexpIndex("u" + strconv.Itoa(i))
		if u.slots[i] <= 0 {
			panic(fmt.Sprintf("union: SubexpIndex for u%d not found", i))
		}
	}
}

// scan runs this tier's union over text and returns one Found per match.
func (u *union) scan(text string) []Found {
	if u == nil || u.re == nil || len(text) == 0 {
		return nil
	}
	matches := u.re.FindAllStringSubmatchIndex(text, -1)
	if len(matches) == 0 {
		return nil
	}
	out := make([]Found, 0, len(matches))
	for _, m := range matches {
		for i, namedIdx := range u.slots {
			if namedIdx*2 >= len(m) {
				continue
			}
			if m[namedIdx*2] < 0 {
				continue
			}
			e := u.entries[i]
			valIdx := namedIdx + e.SubOffset
			if valIdx*2+1 >= len(m) {
				continue
			}
			vStart, vEnd := m[valIdx*2], m[valIdx*2+1]
			if vStart < 0 {
				continue
			}
			v, ok := e.Filt(text[vStart:vEnd])
			if !ok {
				break
			}
			out = append(out, Found{Kind: e.Kind, Value: v, Pattern: e.ID})
			break
		}
	}
	return out
}

// unionScan runs the four tier-unions in priority order (extras > js >
// static > api) so when dedupFound later collapses duplicates, the more
// specific pattern ID wins. Returned slice is NOT deduplicated; that
// happens in FromJSBody.
func unionScan(text string) []Found {
	out := make([]Found, 0, 64)
	out = append(out, extrasUnion.scan(text)...)
	out = append(out, jsUnion.scan(text)...)
	out = append(out, staticUnion.scan(text)...)
	out = append(out, apiUnion.scan(text)...)
	return out
}

// jsFilterRaw / staticFilterRaw / apiURLFilterRaw / wrapExtraFilt all take
// the *raw* matched substring (with surrounding quotes / whitespace) and
// return the cleaned value + keep/drop. They compose the per-kind filter
// after a strip() pass so the legacy semantics are preserved exactly.

func jsFilterRaw(s string) (string, bool)     { return jsFilter(strip(s)) }
func staticFilterRaw(s string) (string, bool) { return staticFilter(strip(s)) }
func apiURLFilterRaw(s string) (string, bool) { return apiURLFilter(strip(s)) }

func wrapExtraFilt(filt func(string) (string, bool)) func(string) (string, bool) {
	return func(raw string) (string, bool) {
		v := strip(raw)
		if v == "" {
			return "", false
		}
		if filt != nil {
			return filt(v)
		}
		return v, true
	}
}

// Streaming knobs. Bodies under StreamThreshold are scanned in a single
// pass. Larger bodies are split into ChunkSize windows with ChunkOverlap
// bytes shared between adjacent chunks - the overlap must exceed the
// longest possible regex match (~250 chars from the api patterns).
const (
	StreamThreshold = 4 << 20  // 4 MiB
	ChunkSize       = 1 << 20  // 1 MiB
	ChunkOverlap    = 16 << 10 // 16 KiB
)

// unionScanChunked applies unionScan to overlapping windows of body when
// body is larger than StreamThreshold. Matches that span a chunk boundary
// are recovered by the overlap. Results are deduplicated across chunks at
// the (kind, value) level so a match found in two adjacent chunks does
// not pollute the output.
func unionScanChunked(body []byte) []Found {
	if len(body) <= StreamThreshold {
		return unionScan(string(body))
	}
	var out []Found
	seen := make(map[string]struct{}, 256)
	add := func(f Found) {
		k := f.Kind + "\x00" + f.Value
		if _, ok := seen[k]; ok {
			return
		}
		seen[k] = struct{}{}
		out = append(out, f)
	}
	step := ChunkSize - ChunkOverlap
	for start := 0; start < len(body); start += step {
		end := start + ChunkSize
		if end > len(body) {
			end = len(body)
		}
		for _, f := range unionScan(string(body[start:end])) {
			add(f)
		}
		if end == len(body) {
			break
		}
	}
	return out
}
