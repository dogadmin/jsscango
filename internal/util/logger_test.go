package util

import (
	"bytes"
	"context"
	"log/slog"
	"strings"
	"testing"
)

// newMultiForTest exposes the multiHandler shape for testing without
// touching the disk (Windows TempDir cleanup races with open log files).
func newMultiForTest(file, stderr *bytes.Buffer, fileLevel, stderrLevel string) *slog.Logger {
	fh := slog.NewTextHandler(file, &slog.HandlerOptions{Level: parseLevel(fileLevel)})
	sh := slog.NewTextHandler(stderr, &slog.HandlerOptions{Level: parseLevel(stderrLevel)})
	return slog.New(&multiHandler{hs: []slog.Handler{fh, sh}})
}

func TestSplitHandler_FileGetsInfoStderrGetsWarn(t *testing.T) {
	var fileBuf, stderrBuf bytes.Buffer
	logger := newMultiForTest(&fileBuf, &stderrBuf, "info", "warn")

	logger.Info("read-side detail", "rows", 1419)
	logger.Warn("possible 401 wall", "kept", 0)
	logger.Error("network blip", "host", "x.com")

	// Stderr (warn level): warn + error, no info.
	se := stderrBuf.String()
	if strings.Contains(se, "read-side detail") {
		t.Errorf("stderr should not contain INFO line, got: %q", se)
	}
	if !strings.Contains(se, "possible 401 wall") {
		t.Errorf("stderr should contain WARN line, got: %q", se)
	}
	if !strings.Contains(se, "network blip") {
		t.Errorf("stderr should contain ERROR line, got: %q", se)
	}

	// File (info level): all three.
	fc := fileBuf.String()
	for _, expect := range []string{"read-side detail", "possible 401 wall", "network blip"} {
		if !strings.Contains(fc, expect) {
			t.Errorf("file should contain %q, got: %q", expect, fc)
		}
	}
}

func TestSplitHandler_DebugFiltered(t *testing.T) {
	// Both ends at info — DEBUG record should appear nowhere.
	var fileBuf, stderrBuf bytes.Buffer
	logger := newMultiForTest(&fileBuf, &stderrBuf, "info", "info")
	logger.Debug("nope")
	if strings.Contains(fileBuf.String()+stderrBuf.String(), "nope") {
		t.Errorf("DEBUG should be filtered when both handlers are at info; got file=%q stderr=%q",
			fileBuf.String(), stderrBuf.String())
	}
}

func TestSplitHandler_EnabledIsUnionOfChildren(t *testing.T) {
	// multiHandler.Enabled must return true if ANY child is enabled at that
	// level — otherwise Handle never gets called and the more verbose
	// child silently drops records.
	fh := slog.NewTextHandler(&bytes.Buffer{}, &slog.HandlerOptions{Level: slog.LevelDebug})
	sh := slog.NewTextHandler(&bytes.Buffer{}, &slog.HandlerOptions{Level: slog.LevelError})
	mh := &multiHandler{hs: []slog.Handler{fh, sh}}
	if !mh.Enabled(context.Background(), slog.LevelInfo) {
		t.Errorf("Enabled(INFO) should be true when file child is at DEBUG")
	}
	if !mh.Enabled(context.Background(), slog.LevelError) {
		t.Errorf("Enabled(ERROR) should be true when stderr child is at ERROR")
	}
}

func TestParseLevel(t *testing.T) {
	cases := []struct {
		in   string
		want slog.Level
	}{
		{"debug", slog.LevelDebug},
		{"DEBUG", slog.LevelDebug},
		{"info", slog.LevelInfo},
		{"warn", slog.LevelWarn},
		{"error", slog.LevelError},
		{"", slog.LevelInfo},
		{"nonsense", slog.LevelInfo},
	}
	for _, c := range cases {
		if got := parseLevel(c.in); got != c.want {
			t.Errorf("parseLevel(%q) = %v, want %v", c.in, got, c.want)
		}
	}
}
