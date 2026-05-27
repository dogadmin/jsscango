package cli

import (
	"log/slog"
	"net/http"
	_ "net/http/pprof" // registers /debug/pprof handlers on http.DefaultServeMux
)

// startPprof spawns a background HTTP listener for the standard library's
// pprof endpoints when addr is non-empty. We deliberately use the default
// mux so the well-known /debug/pprof/* paths just work.
//
// Profiles are reachable at e.g.
//
//	go tool pprof http://localhost:6060/debug/pprof/profile?seconds=30
//	go tool pprof http://localhost:6060/debug/pprof/heap
//
// Errors are logged but don't abort the scan - profiling is opt-in
// observability, not load-bearing.
func startPprof(addr string, logger *slog.Logger) {
	if addr == "" {
		return
	}
	srv := &http.Server{Addr: addr}
	go func() {
		logger.Info("pprof listener started", "addr", addr)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Warn("pprof listener exited", "err", err)
		}
	}()
}
