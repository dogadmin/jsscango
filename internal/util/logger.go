package util

import (
	"context"
	"io"
	"log/slog"
	"os"
	"strings"
)

// NewLogger creates a slog.Logger that writes to dest at the given level
// ("debug", "info", "warn", "error"). dest "" or "stderr" → os.Stderr.
func NewLogger(level, dest string) (*slog.Logger, error) {
	return NewLoggerWithWriter(level, dest, nil)
}

// NewLoggerWithWriter behaves like NewLogger but, when dest is empty or
// "stderr", routes log output through stderrWrap instead of os.Stderr
// directly. This is the seam used by internal/progress.Tracker so the live
// spinner can clear the status line before each slog write. A nil stderrWrap
// is equivalent to passing os.Stderr.
//
// When dest names a real file, stderrWrap is ignored - file logs should not
// be wrapped because the spinner is a TTY-only feature.
func NewLoggerWithWriter(level, dest string, stderrWrap io.Writer) (*slog.Logger, error) {
	var w io.Writer = os.Stderr
	if dest != "" && dest != "stderr" {
		f, err := os.OpenFile(dest, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
		if err != nil {
			return nil, err
		}
		w = f
	} else if stderrWrap != nil {
		w = stderrWrap
	}
	var lvl slog.Level
	switch strings.ToLower(level) {
	case "debug":
		lvl = slog.LevelDebug
	case "warn":
		lvl = slog.LevelWarn
	case "error":
		lvl = slog.LevelError
	default:
		lvl = slog.LevelInfo
	}
	h := slog.NewTextHandler(w, &slog.HandlerOptions{Level: lvl})
	return slog.New(h), nil
}

// NewSplitLogger writes the same record to two destinations at independent
// levels: a file (typically the verbose tail) and the wrapped stderr writer
// (typically quiet, only WARN+). When filePath is empty no file handler is
// created; when stderrWrap is nil os.Stderr is used directly. Either side
// being unconfigured does not error — the logger just becomes single-handler.
//
// Used by the scan CLI to keep the interactive window quiet (progress only +
// WARN+ slog spillover) while still capturing the full INFO/DEBUG trail to
// disk for post-run debugging.
func NewSplitLogger(filePath string, fileLevel string, stderrWrap io.Writer, stderrLevel string) (*slog.Logger, error) {
	var handlers []slog.Handler
	if filePath != "" && filePath != "stderr" {
		f, err := os.OpenFile(filePath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
		if err != nil {
			return nil, err
		}
		handlers = append(handlers, slog.NewTextHandler(f, &slog.HandlerOptions{Level: parseLevel(fileLevel)}))
	}
	var sw io.Writer = os.Stderr
	if stderrWrap != nil {
		sw = stderrWrap
	}
	handlers = append(handlers, slog.NewTextHandler(sw, &slog.HandlerOptions{Level: parseLevel(stderrLevel)}))
	if len(handlers) == 1 {
		return slog.New(handlers[0]), nil
	}
	return slog.New(&multiHandler{hs: handlers}), nil
}

func parseLevel(s string) slog.Level {
	switch strings.ToLower(s) {
	case "debug":
		return slog.LevelDebug
	case "warn":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}

// multiHandler fans out a slog.Record to multiple downstream handlers; each
// downstream applies its own level filter.
type multiHandler struct {
	hs []slog.Handler
}

func (m *multiHandler) Enabled(ctx context.Context, l slog.Level) bool {
	for _, h := range m.hs {
		if h.Enabled(ctx, l) {
			return true
		}
	}
	return false
}

func (m *multiHandler) Handle(ctx context.Context, r slog.Record) error {
	for _, h := range m.hs {
		if h.Enabled(ctx, r.Level) {
			_ = h.Handle(ctx, r)
		}
	}
	return nil
}

func (m *multiHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	out := make([]slog.Handler, len(m.hs))
	for i, h := range m.hs {
		out[i] = h.WithAttrs(attrs)
	}
	return &multiHandler{hs: out}
}

func (m *multiHandler) WithGroup(name string) slog.Handler {
	out := make([]slog.Handler, len(m.hs))
	for i, h := range m.hs {
		out[i] = h.WithGroup(name)
	}
	return &multiHandler{hs: out}
}
