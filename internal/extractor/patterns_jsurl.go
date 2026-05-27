package extractor

import "regexp"

// jsPatterns mirror jsAndStaticUrlFind.py:191-196. They locate JS file URLs
// in arbitrary text. Each capture is the entire match; jsFilter cleans it.
var jsPatterns = mustCompile(
	`http[^\s'’"><:()\[,]+?\.js\b`,
	`["']/[^\s'’"><:()\[,]+?\.js\b`,
	`=[^\s'’"><:()\[,]+?\.js\b`,
	`=["'][^\s'’"><:()\[,]+?\.js\b`,
)

// staticPatterns mirror jsAndStaticUrlFind.py:198-203.
var staticPatterns = mustCompile(
	`["']http[^\s'’"><)(]+?["']`,
	`=http[^\s'’"><)(]+`,
	`["']/[^\s'’"><:)(\x{4e00}-\x{9fa5}]+?["']`,
)

// webpackPathRe extracts the public path and the chunk-id JSON map from a
// webpack runtime. jsAndStaticUrlFind.py:74.
//
// Example match: `return e.p+"static/js/" ... {"foo":"bar","baz":"qux"}[t]+".js"}`
// The pattern is greedy on purpose to capture the largest valid mapping;
// the dot-all flag (?s) lets it span the minified runtime.
var webpackPathRe = regexp.MustCompile(`(?s)return [a-zA-Z]\.p\+"([^"]+).*\{(.*)\}\[[a-zA-Z]\]\+"\.js"\}`)

func mustCompile(exprs ...string) []*regexp.Regexp {
	out := make([]*regexp.Regexp, len(exprs))
	for i, e := range exprs {
		out[i] = regexp.MustCompile(e)
	}
	return out
}
