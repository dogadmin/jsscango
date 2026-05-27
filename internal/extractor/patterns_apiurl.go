package extractor

import "regexp"

// apiPatterns mirrors apiPathFind.py:350-372. Some original patterns used
// variable-width lookbehind (Python's `re` allowed (?<=path:)\s?) which RE2
// does not support — those are rewritten as non-capturing prefixes with
// captured groups, paired with a group index in apiPatternGroups.
//
// Each entry yields a candidate URL/path string that runs through urlFilter
// (urlnorm.go / extractor.RunAPI).
var apiPatternsSrc = []string{
	`["']http[^\s'’"><)(]{2,250}?["']`,
	`=http[^\s'’"><)(]{2,250}`,
	`["']/[^\s'’"><:)(\x{4e00}-\x{9fa5}]{1,250}?["']`,
	`["'][^\s'’"><:)(\x{4e00}-\x{9fa5}]{1,250}?/[^\s'’"><:)(\x{4e00}-\x{9fa5}]{1,250}?/[^\s'’"><:)(\x{4e00}-\x{9fa5}]{1,250}?["']`,
	// keyword-prefixed: path:"…" path :"…" path="…" path ="…"
	`(?i)path\s*[:=]\s*(["'][^\s'’"><:)(\x{4e00}-\x{9fa5}]{1,250}?["'])`,
	`(?i)url\s*[:=]\s*(["'][^\s'’"><:)(\x{4e00}-\x{9fa5}]{1,250}?["'])`,
	`(?i)index\s*[:=]\s*(["'][^\s'’"><:)(\x{4e00}-\x{9fa5}]{1,250}?["'])`,
	`(?i)(?:href|action).{0,3}=.{0,3}["'][^\s'’"><)(]{2,250}`,
	`(?i)(?:href|action).{0,3}=.{0,3}[^\s'’"><)(]{2,250}`,
	`["'](\/[^"'<>` + "`" + `]+)["']`,
}

// apiPatternGroups specifies which capture group (0=whole match) to use for
// each pattern. -1 means "whole match minus surrounding quotes".
var apiPatternGroups = []int{0, 0, 0, 0, 1, 1, 1, 0, 0, 1}

var apiPatterns = func() []*regexp.Regexp {
	out := make([]*regexp.Regexp, len(apiPatternsSrc))
	for i, e := range apiPatternsSrc {
		out[i] = regexp.MustCompile(e)
	}
	return out
}()
