package extractor

import (
	"encoding/json"
	"net/url"
	"strconv"
	"strings"
)

// Found is one classified candidate emitted by the extractor.
type Found struct {
	Kind    string // "js" | "static" | "api" | "webpack"
	Value   string // cleaned URL or path candidate
	Pattern string // pattern ID, debug aid
}

// FromJSBody scans body and emits JS URLs, static URLs, webpack chunks,
// and API path candidates. This is the central one-pass extraction; in
// Phase 4 we'll combine the regexes into a union for fewer scans.
func FromJSBody(body []byte) []Found {
	text := string(body)
	out := make([]Found, 0, 64)

	for i, re := range jsPatterns {
		for _, m := range re.FindAllString(text, -1) {
			if v, ok := jsFilter(strip(m)); ok {
				out = append(out, Found{Kind: "js", Value: v, Pattern: jsPatternID(i)})
			}
		}
	}

	for i, re := range staticPatterns {
		for _, m := range re.FindAllString(text, -1) {
			if v, ok := staticFilter(strip(m)); ok {
				out = append(out, Found{Kind: "static", Value: v, Pattern: staticPatternID(i)})
			}
		}
	}

	for _, chunk := range webpackChunks(text) {
		out = append(out, Found{Kind: "js", Value: chunk, Pattern: "webpack_chunk"})
	}

	out = append(out, runAPIPatterns(text)...)

	return dedupFound(out)
}

func runAPIPatterns(text string) []Found {
	var out []Found
	for i, re := range apiPatterns {
		group := apiPatternGroups[i]
		matches := re.FindAllStringSubmatch(text, -1)
		for _, m := range matches {
			var raw string
			if group < len(m) {
				raw = m[group]
			} else {
				raw = m[0]
			}
			v, ok := apiURLFilter(strip(raw))
			if !ok {
				continue
			}
			out = append(out, Found{Kind: "api", Value: v, Pattern: apiPatternID(i)})
		}
	}
	return out
}

// jsFilter mirrors jsAndStaticUrlFind.py:14-35. Replaces escapes, strips
// quotes, drops domain-blacklisted candidates.
func jsFilter(s string) (string, bool) {
	s = strings.ReplaceAll(s, `\/`, "/")
	s = strings.ReplaceAll(s, " ", "")
	s = strings.ReplaceAll(s, `"`, "")
	s = strings.ReplaceAll(s, `'`, "")
	s = strings.ReplaceAll(s, "./", "/")
	s = strings.ReplaceAll(s, "%3A", ":")
	s = strings.ReplaceAll(s, "%2F", "/")
	s = strings.ReplaceAll(s, `\\`, "")
	s = strings.TrimRight(s, `\`)
	s = strings.TrimLeft(s, "=")
	for _, bl := range DomainBlacklist {
		if strings.Contains(s, bl) {
			return "", false
		}
	}
	if s == "" {
		return "", false
	}
	return s, true
}

// staticFilter mirrors staticUrlFilter at jsAndStaticUrlFind.py:38-50.
// In addition to the Python checks, it drops candidates whose host matches
// DomainBlacklist — the Python equivalent happens in the caller via a
// target-domain compare which the extractor cannot do statelessly.
func staticFilter(s string) (string, bool) {
	s = strings.TrimSpace(s)
	s = strings.Trim(s, `"'`)
	s = strings.TrimRight(s, "/")
	if len(s) < 3 || strings.HasSuffix(s, ".js") {
		return "", false
	}
	low := strings.ToLower(s)
	for _, ext := range StaticFileExtBlacklist {
		if strings.Contains(low, ext) {
			return "", false
		}
	}
	for _, bl := range DomainBlacklist {
		if strings.Contains(s, bl) {
			return "", false
		}
	}
	return s, true
}

// apiURLFilter mirrors urlFilter at apiPathFind.py:276-313. Also runs the
// new false-positive predicates from §7 of the plan.
func apiURLFilter(s string) (string, bool) {
	if s == "" {
		return "", false
	}
	if ContainsMIMELike(s) {
		return "", false
	}
	stripped := strings.Trim(s, `"'`)
	stripped = strings.TrimLeft(stripped, "/")
	for _, bad := range APIRootBlacklistSpider {
		if strings.HasPrefix(stripped, bad) {
			return "", false
		}
	}
	s = strings.ReplaceAll(s, " ", "")
	s = strings.ReplaceAll(s, `\/`, "/")
	s = strings.ReplaceAll(s, `"`, "")
	s = strings.ReplaceAll(s, `'`, "")
	s = strings.Replace(s, `href="`, "", 1)
	s = strings.Replace(s, `href='`, "", 1)
	s = strings.ReplaceAll(s, "%3A", ":")
	s = strings.ReplaceAll(s, "%2F", "/")
	s = strings.ReplaceAll(s, `\\`, "")
	s = strings.TrimRight(s, `\`)
	s = strings.TrimLeft(s, "=")
	if strings.HasPrefix(s, "href=") {
		s = s[5:]
	}
	if s == "href" || s == "" {
		return "", false
	}
	for _, bl := range URLSubstrBlacklist {
		if strings.Contains(s, bl) {
			return "", false
		}
	}
	base := s
	if i := strings.IndexByte(s, '?'); i >= 0 {
		base = s[:i]
	}
	lowBase := strings.ToLower(base)
	for _, ext := range FileExtBlacklist {
		if strings.HasSuffix(lowBase, ext) {
			return "", false
		}
	}
	// Compute the api_path component: strip scheme/host, keep path?query.
	path := s
	if strings.Contains(s, "://") {
		if u, err := url.Parse(s); err == nil {
			path = u.Path
			if u.RawQuery != "" {
				path += "?" + u.RawQuery
			}
		}
	}
	if path == "" {
		return "", false
	}
	if isCSSClassName(path) || isI18nKey(path) || isWebpackSymbol(path) {
		return "", false
	}
	if !hasReasonableSegments(path) {
		return "", false
	}
	return path, true
}

// strip is a tight wrapper for the common "trim quotes/whitespace, strip
// trailing slash" pattern that appears at apiPathFind.py:383.
func strip(s string) string {
	s = strings.TrimSpace(s)
	s = strings.Trim(s, "\"'")
	return strings.TrimRight(s, "/")
}

func dedupFound(in []Found) []Found {
	seen := make(map[string]struct{}, len(in))
	out := in[:0]
	for _, f := range in {
		k := f.Kind + "\x00" + f.Value
		if _, ok := seen[k]; ok {
			continue
		}
		seen[k] = struct{}{}
		out = append(out, f)
	}
	return out
}

// webpackChunks builds chunk URLs by parsing a webpack runtime. Mirrors
// webpack_js_find at jsAndStaticUrlFind.py:71-97.
func webpackChunks(text string) []string {
	m := webpackPathRe.FindStringSubmatch(text)
	if len(m) < 3 {
		return nil
	}
	base := m[1]
	mapping := m[2]

	pairs := strings.Split(mapping, ",")
	formatted := make([]string, 0, len(pairs))
	for _, p := range pairs {
		k, v, ok := splitOnce(p, ':')
		if !ok {
			continue
		}
		k = strings.TrimSpace(k)
		v = strings.TrimSpace(v)
		if !strings.HasPrefix(k, `"`) || !strings.HasPrefix(v, `"`) {
			continue
		}
		formatted = append(formatted, k+":"+v)
	}
	if len(formatted) == 0 {
		return nil
	}
	var chunkMap map[string]string
	if err := json.Unmarshal([]byte("{"+strings.Join(formatted, ",")+"}"), &chunkMap); err != nil {
		return nil
	}
	out := make([]string, 0, len(chunkMap))
	for k, v := range chunkMap {
		out = append(out, "/"+base+k+"."+v+".js")
	}
	return out
}

func splitOnce(s string, sep byte) (string, string, bool) {
	i := strings.IndexByte(s, sep)
	if i < 0 {
		return "", "", false
	}
	return s[:i], s[i+1:], true
}

// False-positive predicates — §7 of the plan.

func isCSSClassName(s string) bool {
	if len(s) >= 30 || strings.Contains(s, "/") {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z',
			c >= '0' && c <= '9' && i > 0,
			c == '-' && i > 0:
		default:
			return false
		}
	}
	return len(s) > 0
}

func isI18nKey(s string) bool {
	if strings.Contains(s, "/") || strings.Contains(s, "?") {
		return false
	}
	if strings.Count(s, ".") < 2 {
		return false
	}
	for _, part := range strings.Split(s, ".") {
		if part == "" {
			return false
		}
		for _, c := range part {
			if !(c >= 'a' && c <= 'z') && !(c >= 'A' && c <= 'Z') {
				return false
			}
		}
	}
	return true
}

func isWebpackSymbol(s string) bool {
	if strings.Contains(s, "__webpack_") {
		return true
	}
	if len(s) < 2 || s[0] != '_' {
		return false
	}
	i := 0
	for i < len(s) && s[i] == '_' {
		i++
	}
	if i == 0 {
		return false
	}
	for ; i < len(s); i++ {
		c := s[i]
		if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')) {
			return false
		}
	}
	return true
}

// hasReasonableSegments enforces the structural sanity checks from §7.
func hasReasonableSegments(path string) bool {
	bare := path
	if i := strings.IndexByte(bare, '?'); i >= 0 {
		bare = bare[:i]
	}
	if bare == "" {
		return false
	}
	segs := strings.Split(strings.Trim(bare, "/"), "/")
	if len(segs) > 8 {
		return false
	}
	letterSeg := false
	for _, s := range segs {
		if len(s) > 80 {
			return false
		}
		letters := 0
		for _, c := range s {
			if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') {
				letters++
			}
		}
		if letters >= 2 {
			letterSeg = true
		}
	}
	return letterSeg
}

func jsPatternID(i int) string     { return "js_" + strconv.Itoa(i) }
func staticPatternID(i int) string { return "static_" + strconv.Itoa(i) }
func apiPatternID(i int) string    { return "api_" + strconv.Itoa(i) }
