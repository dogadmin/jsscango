package fetcher

import _ "embed"

//go:embed stealth.js
var stealthJS string

// StealthJS returns the JavaScript blob that is injected into every new
// chromedp tab via Page.addScriptToEvaluateOnNewDocument. It patches
// detection surfaces commonly used by anti-bot products. Returns the
// concatenated script; safe to call any number of times.
func StealthJS() string { return stealthJS }
