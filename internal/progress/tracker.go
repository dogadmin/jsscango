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

// ANSI escapes used to manage the live status block.
//
//	clearLine — erase the cursor's current row and park at column 0.
//	cursorUp1 — move the cursor up exactly one row, keeping column.
//
// The tracker may render 1 or 2 rows ("scan progress" header + per-stage
// spinner). On each refresh we clear the previously rendered rows, walk
// the cursor back to the top of the block, and emit the new block.
const (
	clearLine = "\x1b[2K\r"
	cursorUp1 = "\x1b[1A"
)

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
	// Scan-level progress (independent of per-stage counters). Shown on a
	// dedicated line above the spinner when ProgressActive is true.
	scanTotal, scanAlive, scanDone int
	scanProgressActive             bool
	// lastLines remembers how many rows are currently painted on screen,
	// so Writer()'s pre-write clear and render's redraw both know how far
	// the cursor needs to walk back.
	lastLines int
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
	// Final clear so the terminal cursor lands on a fresh line — wipes
	// both the spinner row and the scan-progress row when both were live.
	t.mu.Lock()
	t.clearOnScreenLocked()
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

// SetScanProgress activates the top-row scan-progress line. Call once with
// the total target count after loadTargets, again after liveness completes
// with the alive count, and on every target completion to advance done.
// Passing total=0 deactivates the line (the spinner stays).
//
// done, alive, total are all int — the tracker shows:
//
//	存活 <alive>/<total> (<alive/total>%)  完成 <done>/<alive> (<done/alive>%)
//
// Both percentages are computed safely when the denominator is 0.
func (t *Tracker) SetScanProgress(done, alive, total int) {
	if t == nil || !t.isTTY {
		return
	}
	t.mu.Lock()
	t.scanDone = done
	t.scanAlive = alive
	t.scanTotal = total
	t.scanProgressActive = total > 0
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
	t.frame = (t.frame + 1) % len(spinnerFrames)
	var lines []string
	if t.scanProgressActive {
		lines = append(lines, t.formatScanLineLocked())
	}
	lines = append(lines, t.formatLineLocked())
	t.clearOnScreenLocked()
	for i, line := range lines {
		if i > 0 {
			_, _ = io.WriteString(t.w, "\n")
		}
		_, _ = io.WriteString(t.w, line)
	}
	t.lastLines = len(lines)
}

// clearOnScreenLocked erases the previously-painted rows and returns the
// cursor to the top-of-block column 0. Caller must hold t.mu. After this
// returns t.lastLines == 0 — the screen has no live tracker rows.
func (t *Tracker) clearOnScreenLocked() {
	if t.lastLines == 0 {
		return
	}
	// Cursor is at the end of the LAST rendered line. Clear it, then walk
	// up + clear each row above. End with the cursor parked at column 0
	// of the TOP row, ready for the next paint.
	_, _ = io.WriteString(t.w, clearLine)
	for i := 1; i < t.lastLines; i++ {
		_, _ = io.WriteString(t.w, cursorUp1+clearLine)
	}
	t.lastLines = 0
}

// formatScanLineLocked builds the top-row "scan-level progress" line.
// Caller must hold t.mu.
func (t *Tracker) formatScanLineLocked() string {
	alivePct := pct(t.scanAlive, t.scanTotal)
	donePct := pct(t.scanDone, t.scanAlive)
	return fmt.Sprintf(
		"  存活 %d/%d (%.1f%%)  完成 %d/%d (%.1f%%)",
		t.scanAlive, t.scanTotal, alivePct,
		t.scanDone, t.scanAlive, donePct,
	)
}

// pct returns 100*num/den, or 0 when den == 0. Avoids the division-by-zero
// case for un-set counters.
func pct(num, den int) float64 {
	if den <= 0 {
		return 0
	}
	return 100 * float64(num) / float64(den)
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
	// Otherwise erase the whole rendered block (1 or 2 rows) so the log
	// line lands on a clean canvas; the next render tick repaints below.
	if t.isTTY && !t.stopped && t.lastLines > 0 {
		t.clearOnScreenLocked()
	}
	return t.w.Write(p)
}

// discardWriter satisfies io.Writer for nil-tracker plumbing. Bytes are
// dropped; used only as a defensive fallback.
type discardWriter struct{}

func (discardWriter) Write(p []byte) (int, error) { return len(p), nil }
