package fetcher

import (
	"fmt"
	"log/slog"
	"os"

	"github.com/go-rod/rod/lib/launcher"
)

// CachedChromePath returns the path to a previously-downloaded Chromium
// binary in go-rod's launcher cache (default $XDG_CACHE_HOME/rod/browser
// on Linux, %LOCALAPPDATA%\rod\browser on Windows). Returns "" if no
// cached binary is present. Does NOT trigger a download.
//
// Used by findChromePath as a fallback when the system PATH and the
// standard install locations don't have Chrome - so a user who ran
// `jsscango chrome download` once can use chromedp without installing
// system Chrome.
func CachedChromePath() string {
	b := launcher.NewBrowser()
	// Validate checks the cached binary without triggering a download.
	if err := b.Validate(); err != nil {
		return ""
	}
	// At this point the cache is valid; Get() is a resolve-only call.
	bin, err := b.Get()
	if err != nil {
		return ""
	}
	if _, err := os.Stat(bin); err != nil {
		return ""
	}
	return bin
}

// DownloadChrome fetches the pinned Chromium revision into the launcher
// cache and returns the path to the chrome binary. Reuses an existing
// cache when present, so calling this repeatedly is cheap after the
// first run. The first run downloads ~150 MB; on slow links it can take
// a few minutes.
func DownloadChrome(log *slog.Logger) (string, error) {
	if log != nil {
		log.Info("chrome: ensuring cached chromium via go-rod launcher",
			"revision", launcher.RevisionDefault)
	}
	b := launcher.NewBrowser()
	path, err := b.Get()
	if err != nil {
		return "", fmt.Errorf("download chromium: %w", err)
	}
	if log != nil {
		log.Info("chrome: ready", "path", path)
	}
	return path, nil
}
