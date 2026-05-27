package fetcher

import (
	"context"
	"fmt"
	"log/slog"
	"net/url"
	"os"
	"os/exec"
	"path"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/chromedp/cdproto/network"
	"github.com/chromedp/cdproto/page"
	"github.com/chromedp/chromedp"

	"github.com/dogadmin/jsscango/internal/types"
)

// HomepageDiscoverer locates the initial set of URLs for a target. The static
// implementation parses <script src> via x/net/html; the chromedp
// implementation drives a real headless browser and captures every network
// request via CDP, catching SPA/async-loaded JS that requests cannot see.
//
// Both implementations are defined here so the pipeline can switch on
// --chrome=on|off|auto without dragging chromedp into the static-only path.
type HomepageDiscoverer interface {
	Discover(ctx context.Context, targetURL, cookies string) ([]types.DiscoveredURL, error)
}

// Headless drives Chrome/Chromium via CDP. One allocator per process, one tab
// per target. Concurrency-safe.
type Headless struct {
	NavTimeout time.Duration // per-target navigation timeout; default 30s
	Logger     *slog.Logger  // optional; defaults to slog.Default()
	NoStealth  bool          // when true, skip injecting the anti-detection stealth script

	once     sync.Once
	allocCtx context.Context
	cancel   context.CancelFunc
	chromeAt string // resolved Chrome binary path, for logging
	initErr  error
}

// NewHeadless constructs the discoverer but does not yet start Chrome; the
// browser is spawned lazily on the first Discover call.
func NewHeadless() *Headless {
	return &Headless{NavTimeout: 30 * time.Second}
}

func (h *Headless) log() *slog.Logger {
	if h.Logger != nil {
		return h.Logger
	}
	return slog.Default()
}

// Close terminates the underlying Chrome allocator. Safe to call multiple
// times; safe to call before Discover (no-op).
func (h *Headless) Close() {
	if h.cancel != nil {
		h.cancel()
		h.cancel = nil
	}
}

func (h *Headless) ensureAllocator(parent context.Context) {
	h.once.Do(func() {
		opts := append(chromedp.DefaultExecAllocatorOptions[:],
			chromedp.Flag("headless", "new"),
			chromedp.Flag("no-sandbox", true),
			chromedp.Flag("disable-gpu", true),
			chromedp.Flag("ignore-certificate-errors", true),
			chromedp.Flag("ignore-ssl-errors", true),
			chromedp.Flag("disable-dev-shm-usage", true),
			chromedp.Flag("disable-blink-features", "AutomationControlled"),
			chromedp.WindowSize(1920, 1080),
		)
		// Resolve a Chrome binary on systems where the default lookup fails.
		if p := findChromePath(); p != "" {
			opts = append(opts, chromedp.ExecPath(p))
			h.chromeAt = p
		}
		h.log().Info("headless: initializing chrome allocator", "binary", h.chromeAt)
		// We deliberately do not derive from `parent` here - the allocator
		// must outlive any single target's ctx. Closing happens via
		// Headless.Close().
		h.allocCtx, h.cancel = chromedp.NewExecAllocator(context.Background(), opts...)
	})
}

// Discover navigates to targetURL in a headless Chrome tab and returns every
// URL the browser asked for, classified by extension (mirrors
// process_network_events in webdriverFind.py:64).
func (h *Headless) Discover(ctx context.Context, targetURL, cookies string) ([]types.DiscoveredURL, error) {
	log := h.log()
	h.ensureAllocator(ctx)
	if h.initErr != nil {
		log.Warn("headless: allocator init failed", "err", h.initErr)
		return nil, h.initErr
	}

	log.Info("headless: opening tab", "url", targetURL, "nav_timeout", h.NavTimeout)
	tabCtx, tabCancel := chromedp.NewContext(h.allocCtx)
	defer tabCancel()

	navCtx, navCancel := context.WithTimeout(tabCtx, h.NavTimeout)
	defer navCancel()
	if d, ok := ctx.Deadline(); ok {
		// Honour the per-target deadline if it's tighter than NavTimeout.
		navCtx2, navCancel2 := context.WithDeadline(navCtx, d)
		defer navCancel2()
		navCtx = navCtx2
	}

	// Capture network events into a deduplicated slice. The listener runs in
	// the chromedp event goroutine, so the slice is protected by a mutex.
	type netURL struct {
		url, referer string
	}
	var mu sync.Mutex
	seen := make(map[string]struct{}, 64)
	var captured []netURL
	captureCount := func() int {
		mu.Lock()
		defer mu.Unlock()
		return len(captured)
	}

	chromedp.ListenTarget(tabCtx, func(ev interface{}) {
		e, ok := ev.(*network.EventRequestWillBeSent)
		if !ok {
			return
		}
		u := e.Request.URL
		if u == "" || strings.HasPrefix(u, "data:") || strings.HasPrefix(u, "blob:") {
			return
		}
		mu.Lock()
		if _, dup := seen[u]; !dup {
			seen[u] = struct{}{}
			captured = append(captured, netURL{url: u, referer: targetURL})
		}
		mu.Unlock()
	})

	tasks := chromedp.Tasks{
		network.Enable(),
	}
	if !h.NoStealth {
		tasks = append(tasks, chromedp.ActionFunc(func(ctx context.Context) error {
			if _, err := page.AddScriptToEvaluateOnNewDocument(StealthJS()).Do(ctx); err != nil {
				log.Warn("headless: stealth injection failed", "err", err)
			} else {
				log.Debug("headless: stealth script injected")
			}
			return nil // never fail the whole nav over a stealth issue
		}))
	}
	if cookies != "" {
		tasks = append(tasks, network.SetExtraHTTPHeaders(network.Headers{"Cookie": cookies}))
	}
	tasks = append(tasks,
		chromedp.ActionFunc(func(_ context.Context) error {
			log.Info("headless: navigating", "url", targetURL)
			return nil
		}),
		chromedp.Navigate(targetURL),
		chromedp.ActionFunc(func(_ context.Context) error {
			log.Debug("headless: navigated, settling 3s for async chunks", "captured", captureCount())
			return nil
		}),
		// Settle period. We deliberately DO NOT use WaitReady("body") here:
		// it hangs indefinitely on SPAs that re-mount body during hydration
		// (observed on real targets) even though the event listener has
		// already captured 100+ URLs. Since chromedp.ListenTarget runs
		// independently of the task chain, the listener fills our slice
		// throughout the navigation; this Sleep just gives async chunks
		// time to fire their requests before we tear down the tab.
		chromedp.Sleep(3*time.Second),
	)

	start := time.Now()
	err := chromedp.Run(navCtx, tasks)
	elapsed := time.Since(start)
	finalCount := captureCount()

	if err != nil {
		// Even on nav error, we keep any URLs captured before the failure.
		log.Warn("headless: run failed", "err", err, "elapsed", elapsed, "captured", finalCount)
		if finalCount == 0 {
			return nil, fmt.Errorf("headless: %w", err)
		}
	} else {
		log.Info("headless: navigation complete", "url", targetURL, "elapsed", elapsed, "captured", finalCount)
	}

	mu.Lock()
	defer mu.Unlock()
	out := make([]types.DiscoveredURL, 0, len(captured)+1)
	out = append(out, types.DiscoveredURL{
		URL: targetURL, Referer: targetURL, Kind: types.KindBaseURL, Source: "chromedp",
	})
	for _, c := range captured {
		if c.url == targetURL {
			continue
		}
		out = append(out, types.DiscoveredURL{
			URL:     c.url,
			Referer: c.referer,
			Kind:    classifyNetworkURL(c.url),
			Source:  "chromedp",
		})
	}
	return out, nil
}

// classifyNetworkURL mirrors webdriverFind.py:49 - .js files become KindJS,
// paths without a file extension become KindNoJS (those are usually API
// requests), everything else falls into KindStatic.
func classifyNetworkURL(rawURL string) types.URLKind {
	u, err := url.Parse(rawURL)
	if err != nil {
		return types.KindStatic
	}
	ext := strings.ToLower(path.Ext(u.Path))
	switch ext {
	case ".js":
		return types.KindJS
	case "":
		return types.KindNoJS
	default:
		return types.KindStatic
	}
}

// LookupChromePath is the exported version of findChromePath, used by the
// `chrome path` subcommand. Returns "" when no usable binary is found.
func LookupChromePath() string { return findChromePath() }

// findChromePath looks for a Chrome/Chromium binary. Returns "" if not found
// (chromedp's default lookup will try too; we just give it a head start on
// Windows where PATH typically doesn't include Chrome's install dir).
func findChromePath() string {
	candidates := []string{"google-chrome", "google-chrome-stable", "chromium", "chromium-browser", "chrome"}
	if runtime.GOOS == "windows" {
		candidates = []string{"chrome.exe"}
	}
	for _, c := range candidates {
		if p, err := exec.LookPath(c); err == nil {
			return p
		}
	}
	if runtime.GOOS == "windows" {
		// Common Windows install locations.
		for _, p := range []string{
			`C:\Program Files\Google\Chrome\Application\chrome.exe`,
			`C:\Program Files (x86)\Google\Chrome\Application\chrome.exe`,
			`C:\Program Files\Microsoft\Edge\Application\msedge.exe`,
			`C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe`,
		} {
			if _, err := os.Stat(p); err == nil {
				return p
			}
		}
	}
	// Finally check the go-rod launcher cache - populated by
	// `jsscango chrome download`. This lets Linux deployments use
	// chromedp without a system Chrome install.
	if p := CachedChromePath(); p != "" {
		return p
	}
	return ""
}

// HeadlessAvailable reports whether a Chrome/Chromium binary can be located
// on this system. Used by --chrome=auto to decide whether to fall back to
// the static homepage discoverer.
func HeadlessAvailable() bool {
	return findChromePath() != ""
}
