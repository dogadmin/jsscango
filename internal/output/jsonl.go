package output

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"github.com/dogadmin/jsscango/internal/types"
)

// JSONL writes Report events to either a per-target report.jsonl at
// <outDir>/<targetFolder>/report.jsonl (the default, single-target or
// serial multi-target case) OR a single combined <outDir>/report.jsonl
// when Combined is true (set by the CLI when ConcurrentTargets > 1).
//
// The combined-file path keeps writes thread-safe with a single mutex,
// which is what we want when many targets are streaming events
// simultaneously — the alternative (a map[folder]*writer) is more
// surface area and an extra failure mode for marginal benefit.
type JSONL struct {
	OutDir   string
	Combined bool // when true: one shared <OutDir>/report.jsonl, no per-target rollover

	mu     sync.Mutex
	file   *os.File
	writer *bufio.Writer
}

func NewJSONL(outDir string) *JSONL { return &JSONL{OutDir: outDir} }

func (j *JSONL) Start(_ context.Context, targetFolder string) error {
	j.mu.Lock()
	defer j.mu.Unlock()

	if j.Combined {
		// Combined mode: open the shared file once on the first Start,
		// then leave it alone. Subsequent target Starts only need to
		// ensure the per-target subdir exists (the rest of the pipeline
		// still writes response bodies and state.json under that dir).
		if err := os.MkdirAll(filepath.Join(j.OutDir, targetFolder), 0o755); err != nil {
			return fmt.Errorf("mkdir target subdir: %w", err)
		}
		if j.writer != nil {
			return nil
		}
		if err := os.MkdirAll(j.OutDir, 0o755); err != nil {
			return fmt.Errorf("mkdir out: %w", err)
		}
		f, err := os.OpenFile(filepath.Join(j.OutDir, "report.jsonl"),
			os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
		if err != nil {
			return err
		}
		j.file = f
		j.writer = bufio.NewWriterSize(f, 64*1024)
		return nil
	}

	// Per-target mode: flush + close any prior target's file before
	// opening the next one; each target gets its own per-folder
	// report.jsonl. This is the legacy single-target / serial-loop path.
	if j.writer != nil {
		_ = j.writer.Flush()
		j.writer = nil
	}
	if j.file != nil {
		_ = j.file.Close()
		j.file = nil
	}
	dir := filepath.Join(j.OutDir, targetFolder)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("mkdir: %w", err)
	}
	f, err := os.OpenFile(filepath.Join(dir, "report.jsonl"),
		os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return err
	}
	j.file = f
	j.writer = bufio.NewWriterSize(f, 64*1024)
	return nil
}

func (j *JSONL) Write(r types.Report) error {
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.writer == nil {
		return nil
	}
	b, err := json.Marshal(r)
	if err != nil {
		return err
	}
	if _, err := j.writer.Write(b); err != nil {
		return err
	}
	if err := j.writer.WriteByte('\n'); err != nil {
		return err
	}
	return nil
}

func (j *JSONL) Flush() error {
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.writer == nil {
		return nil
	}
	return j.writer.Flush()
}

func (j *JSONL) Close() error {
	j.mu.Lock()
	defer j.mu.Unlock()
	var firstErr error
	if j.writer != nil {
		if err := j.writer.Flush(); err != nil {
			firstErr = err
		}
		j.writer = nil
	}
	if j.file != nil {
		if err := j.file.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
		j.file = nil
	}
	return firstErr
}
