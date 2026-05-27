package output

import (
	"bufio"
	"context"
	"encoding/csv"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"

	"github.com/dogadmin/jsscango/internal/types"
)

// CSV streams report events to three flat files at <OutDir>/:
//
//	probes.csv        Kept probe responses (probe events with Kept=true).
//	fingerprints.csv  Fingerprint + vuln rule_hit events.
//	sensitive.csv     Sensitive rule_hit events.
//
// Designed for tens-of-thousands-of-target runs where XLSX's all-in-memory
// model is unviable and the other XLSX sheets (URLs / JS / static /
// api_paths / frontend_routes) are noise. Each writer is buffered + mutex
// guarded so concurrent target goroutines can write safely; rows always
// carry their Target column.
//
// One set of files for the whole run regardless of target count — there's
// no per-target rollover. Per-target subdirs still hold response bodies
// and state.json (handled by other sinks).
type CSV struct {
	OutDir string

	mu sync.Mutex
	// Each output is a *csv.Writer over a *bufio.Writer over the *os.File.
	// Files are opened lazily on the first Start so a no-op run doesn't
	// litter the output dir.
	probesFile, fpsFile, sensFile *os.File
	probesBuf, fpsBuf, sensBuf    *bufio.Writer
	probes, fps, sens             *csv.Writer
	started                       bool
}

func NewCSV(outDir string) *CSV { return &CSV{OutDir: outDir} }

func (c *CSV) Start(_ context.Context, targetFolder string) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Per-target subdir for the rest of the pipeline (response bodies,
	// state.json). Always created, regardless of whether we've opened the
	// CSV files yet.
	if err := os.MkdirAll(filepath.Join(c.OutDir, targetFolder), 0o755); err != nil {
		return fmt.Errorf("mkdir target subdir: %w", err)
	}

	if c.started {
		return nil
	}
	if err := os.MkdirAll(c.OutDir, 0o755); err != nil {
		return fmt.Errorf("mkdir out: %w", err)
	}
	var err error
	c.probesFile, c.probesBuf, c.probes, err = openCSV(
		filepath.Join(c.OutDir, "probes.csv"),
		[]string{"Target", "URL", "Method", "Status", "Content-Type", "Size", "Body Path", "SHA256", "Source"},
	)
	if err != nil {
		return err
	}
	c.fpsFile, c.fpsBuf, c.fps, err = openCSV(
		filepath.Join(c.OutDir, "fingerprints.csv"),
		[]string{"Target", "Rule ID", "Kind", "Group", "Matches", "File", "URL"},
	)
	if err != nil {
		_ = c.probesFile.Close()
		return err
	}
	c.sensFile, c.sensBuf, c.sens, err = openCSV(
		filepath.Join(c.OutDir, "sensitive.csv"),
		[]string{"Target", "Rule ID", "Group", "Matches", "File", "URL"},
	)
	if err != nil {
		_ = c.probesFile.Close()
		_ = c.fpsFile.Close()
		return err
	}
	c.started = true
	return nil
}

// openCSV opens path for append+write, wraps it in a buffered writer + csv
// writer, and writes the header on first creation (when the file was empty
// before this call so re-running a scan doesn't double the header line).
func openCSV(path string, header []string) (*os.File, *bufio.Writer, *csv.Writer, error) {
	st, statErr := os.Stat(path)
	isNew := os.IsNotExist(statErr) || (statErr == nil && st.Size() == 0)
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("open %s: %w", path, err)
	}
	buf := bufio.NewWriterSize(f, 64*1024)
	w := csv.NewWriter(buf)
	if isNew {
		if err := w.Write(header); err != nil {
			_ = f.Close()
			return nil, nil, nil, err
		}
	}
	return f, buf, w, nil
}

func (c *CSV) Write(r types.Report) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.started {
		return nil
	}
	switch r.Event {
	case "probe":
		if r.Probe == nil || !r.Probe.Kept {
			return nil
		}
		target := r.Probe.Target
		if target == "" {
			target = r.Target
		}
		return c.probes.Write([]string{
			target,
			r.Probe.URL,
			r.Probe.Method,
			strconv.Itoa(r.Probe.StatusCode),
			r.Probe.ContentType,
			strconv.FormatInt(r.Probe.Size, 10),
			r.Probe.BodyPath,
			r.Probe.BodySHA256,
			r.Probe.Source,
		})
	case "rule_hit":
		if r.Hit == nil {
			return nil
		}
		target := r.Hit.Target
		if target == "" {
			target = r.Target
		}
		matches := strings.Join(r.Hit.Matches, " | ")
		switch r.Hit.Kind {
		case "sensitive":
			return c.sens.Write([]string{
				target, r.Hit.RuleID, r.Hit.Group, matches, r.Hit.File, r.Hit.URL,
			})
		default: // fingerprint, vuln, anything else lands here
			return c.fps.Write([]string{
				target, r.Hit.RuleID, r.Hit.Kind, r.Hit.Group, matches, r.Hit.File, r.Hit.URL,
			})
		}
	}
	return nil
}

func (c *CSV) Flush() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.started {
		return nil
	}
	c.probes.Flush()
	c.fps.Flush()
	c.sens.Flush()
	var firstErr error
	if err := c.probesBuf.Flush(); err != nil && firstErr == nil {
		firstErr = err
	}
	if err := c.fpsBuf.Flush(); err != nil && firstErr == nil {
		firstErr = err
	}
	if err := c.sensBuf.Flush(); err != nil && firstErr == nil {
		firstErr = err
	}
	return firstErr
}

func (c *CSV) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.started {
		return nil
	}
	var firstErr error
	closeOne := func(w *csv.Writer, buf *bufio.Writer, f *os.File) {
		w.Flush()
		if err := buf.Flush(); err != nil && firstErr == nil {
			firstErr = err
		}
		if err := f.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	closeOne(c.probes, c.probesBuf, c.probesFile)
	closeOne(c.fps, c.fpsBuf, c.fpsFile)
	closeOne(c.sens, c.sensBuf, c.sensFile)
	c.started = false
	return firstErr
}
