package crawler

import (
	"context"
	"log/slog"
	"sync"

	"golang.org/x/sync/errgroup"
	"golang.org/x/sync/semaphore"

	"github.com/dogadmin/jsscango/internal/extractor"
	"github.com/dogadmin/jsscango/internal/fetcher"
	"github.com/dogadmin/jsscango/internal/state"
	"github.com/dogadmin/jsscango/internal/types"
	"github.com/dogadmin/jsscango/internal/util"
)

// Crawler does the BFS JS/static-URL recursion that the Python version
// implements in plugins/jsAndStaticUrlFind.py:js_find_api.
//
// Differences from the Python version:
//   - bounded worker pool (semaphore + errgroup), not 300 raw threads;
//   - per-target Seen map prevents O(n) list scans and races;
//   - --max-depth caps BFS so cyclic imports terminate;
//   - HEAD is not used (the Python version commented it out, we follow).
type Crawler struct {
	F          fetcher.Fetcher
	Seen       *state.Seen
	Workers    int
	MaxDepth   uint8
	BaseDomain string
	Logger     *slog.Logger
	Emit       func(types.DiscoveredURL)
}

type job struct {
	url     string
	referer string
	depth   uint8
}

// Run starts the BFS from `seeds`. It returns when the queue is drained or
// ctx is cancelled.
func (c *Crawler) Run(ctx context.Context, seeds []types.DiscoveredURL) error {
	if c.Workers <= 0 {
		c.Workers = 32
	}
	sem := semaphore.NewWeighted(int64(c.Workers))
	g, gctx := errgroup.WithContext(ctx)

	queue := make(chan job, c.Workers*4)
	var pending sync.WaitGroup

	enqueue := func(j job) {
		if j.url == "" {
			return
		}
		if !c.Seen.AddURL(j.url) {
			return
		}
		if c.BaseDomain != "" && !util.SameSiteOrIP(j.url, c.BaseDomain) {
			return
		}
		pending.Add(1)
		select {
		case <-gctx.Done():
			pending.Done()
		case queue <- j:
		}
	}

	// emit + enqueue every seed
	for _, s := range seeds {
		if c.Emit != nil {
			c.Emit(s)
		}
		if s.Kind == types.KindJS || s.Kind == types.KindNoJS || s.Kind == types.KindBaseURL {
			enqueue(job{url: s.URL, referer: s.Referer, depth: 0})
		}
	}

	g.Go(func() error {
		go func() {
			pending.Wait()
			close(queue)
		}()
		for j := range queue {
			j := j
			if err := sem.Acquire(gctx, 1); err != nil {
				// Acquire failed (typically ctx cancelled). Decrement the
				// pending counter for the job we just pulled, then drain
				// any items currently in the buffer so the closer goroutine
				// can finish and we don't leak it. In-flight producers will
				// self-cancel via the gctx.Done() case in enqueue().
				pending.Done()
				for {
					select {
					case <-queue:
						pending.Done()
					default:
						return err
					}
				}
			}
			g.Go(func() error {
				defer sem.Release(1)
				defer pending.Done()
				c.process(gctx, j, enqueue)
				return nil
			})
		}
		return nil
	})

	return g.Wait()
}

func (c *Crawler) process(ctx context.Context, j job, enqueue func(job)) {
	if ctx.Err() != nil {
		return
	}
	resp, err := c.F.Fetch(ctx, fetcher.Request{URL: j.url, Method: fetcher.MethodGET})
	if err != nil {
		if c.Logger != nil {
			c.Logger.Debug("crawl fetch failed", "url", j.url, "err", err)
		}
		return
	}
	if resp.StatusCode != 200 || resp.Skipped || len(resp.Body) == 0 {
		return
	}
	scheme, base, root := util.SplitBase(j.url)
	found := extractor.FromJSBody(resp.Body)
	for _, f := range found {
		switch f.Kind {
		case "js":
			abs := util.JoinNewURL(scheme, base, root, f.Value)
			if abs == "" {
				continue
			}
			c.emit(types.DiscoveredURL{
				URL: abs, Referer: j.url, Kind: types.KindJS, Depth: j.depth + 1, Source: "crawl",
			})
			if j.depth+1 < c.MaxDepth {
				enqueue(job{url: abs, referer: j.url, depth: j.depth + 1})
			}
		case "static":
			abs := util.JoinNewURL(scheme, base, root, f.Value)
			if abs == "" {
				continue
			}
			c.emit(types.DiscoveredURL{
				URL: abs, Referer: j.url, Kind: types.KindStatic, Depth: j.depth + 1, Source: "crawl",
			})
		case "api":
			// API path discovery is also emitted here so consumers see the
			// path attached to its source JS file. The pipeline post-processes
			// these into API URLs separately.
			c.emit(types.DiscoveredURL{
				URL: f.Value, Referer: j.url, Kind: types.KindAPIPath, Depth: j.depth + 1, Source: "crawl",
			})
		}
	}
}

func (c *Crawler) emit(d types.DiscoveredURL) {
	if c.Emit == nil {
		return
	}
	c.Emit(d)
}
