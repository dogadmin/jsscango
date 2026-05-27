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

// JSONL writes one Report per line to <outDir>/<targetFolder>/report.jsonl.
type JSONL struct {
	OutDir string

	mu     sync.Mutex
	file   *os.File
	writer *bufio.Writer
}

func NewJSONL(outDir string) *JSONL { return &JSONL{OutDir: outDir} }

func (j *JSONL) Start(_ context.Context, targetFolder string) error {
	j.mu.Lock()
	defer j.mu.Unlock()
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
