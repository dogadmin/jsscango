// Package progress implements a small TTY-aware live status indicator used by
// the `scan` subcommand. The Tracker renders a single line that updates ~8 Hz
// with the current pipeline stage, elapsed time in that stage, and a few
// named counters that the pipeline pushes into it.
//
// When the writer it is constructed with is not a terminal (CI logs, pipes,
// redirection to a file), every method is a cheap no-op. The pipeline's
// existing INFO-level stage transition logs already provide complete
// visibility in those environments, so the tracker stays out of their way.
package progress

import (
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"time"

	"golang.org/x/term"
)

// spinnerFrames is the braille spinner glyph rotation. With a 120 ms tick the
// effective refresh rate is ~8 Hz.
var spinnerFrames = []string{
	"⠋", // ⠋
	"⠙", // ⠙
	"⠹", // ⠹
	"⠸", // ⠸
	"⠼", // ⠼
	"⠴", // ⠴
	"⠦", // ⠦
	"⠧", // ⠧
	"⠇", // ⠇
	"⠏", // ⠏
}

// ANSI escape that erases the current line and parks the cursor at column 0.
// We always begin a refresh by writing this, so the tracker overwrites itself
// in place and slog-pushed lines that go through Writer() can clear the
// spinner before printing.
const clearLine = "\x1b[2K\r"

const tickInterval = 120 * time.Millisecond

// Tracker shows a live one-line status indicator when its output is a TTY.
// When the output is not a TTY, all methods are cheap no-ops. The zero value
// is not usable; construct one with New.
type Tracker struct {
	w     io.Writer
	isTTY bool

	mu         sync.Mutex
	started    bool
	stopped    bool
	stopCh     chan struct{}
	doneCh     chan struct{}
	stage      string
	stageStart time.Time
	frame      int
	// counters is the live map; keys is the insertion-order list of names
	// observed via SetCount, so the rendered line is stable across ticks.
	counters map[string]int64
	keys     []string
	// lastRender holds the most recently rendered line (without the leading
	// clearLine escape). Writer() needs to know whether anything is on screen
	// before printing log output so we know to clear first.
	lastRender string
}

// New creates a Tracker writing to w. TTY detection is via x/term.IsTerminal
// on the underlying *os.File (if w is one); anything else is treated as
// non-TTY and the tracker becomes a no-op.
func New(w io.Writer) *Tracker {
	t := &Tracker{w: w, counters: make(map[string]int64)}
	if f, ok := w.(*os.File); ok {
		if term.IsTerminal(int(f.Fd())) {
			t.isTTY = true
		}
	}
	return t
}

// Start spawns the render goroutine. Safe to call multiple times - subsequent
// calls are ignored.
func (t *Tracker) Start() {
	if t == nil || !t.isTTY {
		return
	}
	t.mu.Lock()
	if t.started || t.stopped {
		t.mu.Unlock()
		return
	}
	t.started = true
	t.stopCh = make(chan struct{})
	t.doneCh = make(chan struct{})
	if t.stageStart.IsZero() {
		t.stageStart = time.Now()
	}
	t.mu.Unlock()

	go t.run()
}

// Stop stops the render goroutine and clears the current status line. Safe to
// call before Start or repeatedly; only the first call has any effect.
func (t *Tracker) Stop() {
	if t == nil || !t.isTTY {
		return
	}
	t.mu.Lock()
	if t.stopped {
		t.mu.Unlock()
		return
	}
	t.stopped = true
	started := t.started
	stopCh := t.stopCh
	doneCh := t.doneCh
	t.mu.Unlock()

	if !started {
		// Best-effort: clear any partial output that callers may have written
		// (none from us, but be tidy).
		_, _ = io.WriteString(t.w, clearLine)
		return
	}
	close(stopCh)
	<-doneCh
	// Final clear so the terminal cursor lands on a fresh line.
	t.mu.Lock()
	_, _ = io.WriteString(t.w, clearLine)
	t.lastRender = ""
	t.mu.Unlock()
}

// SetStage transitions to a new stage. Counters accumulate across stages so
// the operator can see running totals at a glance; only the per-stage elapsed
// clock resets.
func (t *Tracker) SetStage(name string) {
	if t == nil || !t.isTTY {
		return
	}
	t.mu.Lock()
	t.stage = name
	t.stageStart = time.Now()
	t.mu.Unlock()
}

// SetCount sets the value of a named counter. The first time a key is seen
// it is appended to the display order; subsequent updates only change the
// value. This keeps the rendered line layout stable.
func (t *Tracker) SetCount(key string, value int) {
	if t == nil || !t.isTTY {
		return
	}
	t.mu.Lock()
	if _, ok := t.counters[key]; !ok {
		t.keys = append(t.keys, key)
	}
	t.counters[key] = int64(value)
	t.mu.Unlock()
}

// Writer returns an io.Writer that the slog handler should use. Writes
// through this writer first emit a clear-line escape so log output does not
// interleave with the spinner; after the write completes the next render
// tick redraws the status line beneath the log.
//
// The returned writer is safe for concurrent use; it serializes against the
// render goroutine via the tracker's mutex.
func (t *Tracker) Writer() io.Writer {
	if t == nil {
		// Defensive: a nil Tracker should still produce a usable writer so
		// callers can plumb it unconditionally. We return a discard-only
		// proxy by way of a stdlib helper; in practice callers don't pass nil.
		return discardWriter{}
	}
	return &trackerWriter{t: t}
}

func (t *Tracker) run() {
	ticker := time.NewTicker(tickInterval)
	defer ticker.Stop()
	defer close(t.doneCh)

	for {
		select {
		case <-t.stopCh:
			return
		case <-ticker.C:
			t.render()
		}
	}
}

func (t *Tracker) render() {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.stopped {
		return
	}
	line := t.formatLineLocked()
	t.frame = (t.frame + 1) % len(spinnerFrames)
	// Always lead with clearLine so partial prior frames or stray log bytes
	// disappear before the new frame goes down.
	_, _ = io.WriteString(t.w, clearLine+line)
	t.lastRender = line
}

// formatLineLocked builds the status line. Caller must hold t.mu.
func (t *Tracker) formatLineLocked() string {
	glyph := spinnerFrames[t.frame%len(spinnerFrames)]
	stage := t.stage
	if stage == "" {
		stage = "init"
	}
	elapsed := time.Since(t.stageStart)
	var sb strings.Builder
	sb.WriteString(glyph)
	sb.WriteByte(' ')
	sb.WriteByte('[')
	sb.WriteString(stage)
	sb.WriteByte(']')
	sb.WriteString(" elapsed=")
	sb.WriteString(formatElapsed(elapsed))
	for _, k := range t.keys {
		sb.WriteByte(' ')
		sb.WriteString(k)
		sb.WriteByte('=')
		sb.WriteString(fmt.Sprintf("%d", t.counters[k]))
	}
	return sb.String()
}

// formatElapsed renders a duration with one decimal of seconds when under a
// minute, and m:ss above that. This matches the example in the spec:
//
//	elapsed=12.4s
func formatElapsed(d time.Duration) string {
	if d < 0 {
		d = 0
	}
	if d < time.Minute {
		// Round to one decimal of a second.
		s := d.Seconds()
		return fmt.Sprintf("%.1fs", s)
	}
	mins := int(d / time.Minute)
	secs := int((d % time.Minute) / time.Second)
	return fmt.Sprintf("%dm%02ds", mins, secs)
}

// trackerWriter is the io.Writer adapter handed to slog. Each Write clears
// the on-screen spinner line first, then writes the caller's bytes. The next
// render tick (within ~120 ms) repaints the spinner below the log message.
type trackerWriter struct{ t *Tracker }

func (tw *trackerWriter) Write(p []byte) (int, error) {
	t := tw.t
	t.mu.Lock()
	defer t.mu.Unlock()
	// If the tracker isn't active (non-TTY, or never started, or already
	// stopped), skip the clear escape - just write the bytes through.
	if t.isTTY && !t.stopped && t.lastRender != "" {
		_, _ = io.WriteString(t.w, clearLine)
		t.lastRender = ""
	}
	return t.w.Write(p)
}

// discardWriter satisfies io.Writer for nil-tracker plumbing. Bytes are
// dropped; used only as a defensive fallback.
type discardWriter struct{}

func (discardWriter) Write(p []byte) (int, error) { return len(p), nil }
