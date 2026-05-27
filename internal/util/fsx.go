package util

import (
	"net/url"
	"regexp"
	"strings"
)

var nonNameChar = regexp.MustCompile(`[^a-zA-Z0-9._-]`)

// SanitizeName converts a URL or string to a safe filesystem name. Replaces
// every char outside [a-zA-Z0-9._-] with "_". Mirrors the
// `re.sub(r'[^a-zA-Z0-9\.]', '_', url)` pattern used at jsAndStaticUrlFind.py:150
// and apiUrlReqNoParameter.py:22.
func SanitizeName(s string) string {
	s = nonNameChar.ReplaceAllString(s, "_")
	if len(s) > 200 {
		s = s[:200]
	}
	return s
}

// TargetFolder returns the per-target results folder name (just the leaf, no
// parent dir). Strips the scheme so different schemes for the same host collide
// intentionally.
func TargetFolder(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil || u.Host == "" {
		return SanitizeName(rawURL)
	}
	leaf := u.Host
	if u.Path != "" && u.Path != "/" {
		leaf += "_" + strings.TrimLeft(u.Path, "/")
	}
	return SanitizeName(leaf)
}
