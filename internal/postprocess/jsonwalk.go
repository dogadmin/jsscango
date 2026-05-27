package postprocess

import (
	"encoding/json"
	"strings"
)

// WalkJSONForURLs decodes body as JSON and recursively visits every node.
// Returns a deduplicated list of strings that look like URL-bearing values
// from well-known fields: href, url, link, endpoint, action, path.
//
// Returns nil on non-JSON or unparseable bodies.
//
// Rationale: rule-based regex scanning catches obvious URL literals embedded
// in HTML/JS bodies, but a JSON API response often contains HATEOAS links
// or route tables where the URL is a value of a known key. Walking the
// parsed structure catches these without paying the false-positive cost of
// running another regex pass.
func WalkJSONForURLs(body []byte) []string {
	if len(body) == 0 {
		return nil
	}
	var v interface{}
	if err := json.Unmarshal(body, &v); err != nil {
		return nil
	}
	out := &walkState{
		seen: make(map[string]struct{}),
	}
	walkJSON(v, out)
	return out.list
}

type walkState struct {
	seen map[string]struct{}
	list []string
}

// addCandidate runs the junk filter and dedup against a string value
// captured from a matching key. Preserves first-seen order.
func (w *walkState) addCandidate(s string) {
	if !isURLLikeValue(s) {
		return
	}
	if _, ok := w.seen[s]; ok {
		return
	}
	w.seen[s] = struct{}{}
	w.list = append(w.list, s)
}

// walkJSON does a DFS over the decoded JSON tree. For maps it inspects
// each key against the URL-bearing set, recording the value when the key
// matches AND the value is a non-empty string, then recurses into the
// value (so nested maps/slices still get visited). For slices it recurses
// into each element. Scalars other than strings under a matching key are
// ignored.
func walkJSON(v interface{}, w *walkState) {
	switch t := v.(type) {
	case map[string]interface{}:
		for k, val := range t {
			if isURLBearingKey(k) {
				if s, ok := val.(string); ok {
					w.addCandidate(s)
				}
			}
			walkJSON(val, w)
		}
	case []interface{}:
		for _, el := range t {
			walkJSON(el, w)
		}
	}
}

// isURLBearingKey reports whether a JSON object key, case-insensitively,
// matches one of the well-known URL-carrying fields. Kept narrow on
// purpose: broader matches (e.g. "name", "id") would surface too many
// non-URL strings. The covered set is the union of common JSON-API,
// HATEOAS, Vue/React router, and form-action conventions.
func isURLBearingKey(k string) bool {
	switch strings.ToLower(k) {
	case "href", "url", "link", "endpoint", "action", "path":
		return true
	}
	return false
}

// isURLLikeValue applies the junk filter described in the design:
// drop empty / single-char strings, anything with a newline, and the
// pseudo-URL schemes (data:, blob:, javascript:) and bare fragments (#...).
// Leaves the rest alone - the caller wants raw values so downstream
// stages can decide on probing.
func isURLLikeValue(s string) bool {
	if len(s) < 2 {
		return false
	}
	if strings.Contains(s, "\n") {
		return false
	}
	low := strings.ToLower(s)
	switch {
	case strings.HasPrefix(low, "data:"),
		strings.HasPrefix(low, "blob:"),
		strings.HasPrefix(low, "javascript:"):
		return false
	}
	if strings.HasPrefix(s, "#") {
		return false
	}
	return true
}
