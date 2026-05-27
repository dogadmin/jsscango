package fetcher

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"path"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/chromedp/cdproto/network"
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

	once     sync.Once
	allocCtx context.Context
	cancel   context.CancelFunc
	initErr  error
}

// NewHeadless constructs the discoverer but does not yet start Chrome; the
// browser is spawned lazily on the first Discover call.
func NewHeadless() *Headless {
	return &Headless{NavTimeout: 30 * time.Second}
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
		}
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
	h.ensureAllocator(ctx)
	if h.initErr != nil {
		return nil, h.initErr
	}

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
	if cookies != "" {
		tasks = append(tasks, network.SetExtraHTTPHeaders(network.Headers{"Cookie": cookies}))
	}
	tasks = append(tasks,
		chromedp.Navigate(targetURL),
		chromedp.WaitReady("body", chromedp.ByQuery),
		// Brief pause lets async chunks fire their network requests before
		// we tear down the tab. SPAs that issue requests on idle benefit
		// from this; static sites are unaffected since events are already
		// captured by the time WaitReady returns.
		chromedp.Sleep(1500*time.Millisecond),
	)

	if err := chromedp.Run(navCtx, tasks); err != nil {
		// Even on nav error, we keep any URLs captured before the failure.
		if len(captured) == 0 {
			return nil, fmt.Errorf("headless: %w", err)
		}
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
	return ""
}

// HeadlessAvailable reports whether a Chrome/Chromium binary can be located
// on this system. Used by --chrome=auto to decide whether to fall back to
// the static homepage discoverer.
func HeadlessAvailable() bool {
	return findChromePath() != ""
}
