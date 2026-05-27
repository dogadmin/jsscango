package util

import (
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
