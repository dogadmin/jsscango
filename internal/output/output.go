package output

import (
	"context"

	"github.com/dogadmin/jsscango/internal/types"
)

// Sink consumes Report events; the pipeline fans every event out to every
// registered sink so output format selection is a flag, not a code path.
type Sink interface {
	Start(ctx context.Context, target string) error
	Write(r types.Report) error
	Flush() error
	Close() error
}

// Multi fans Write to several sinks. Errors from later sinks do not short-
// circuit; the first error is returned at Close.
type Multi struct{ Sinks []Sink }

func (m *Multi) Start(ctx context.Context, target string) error {
	for _, s := range m.Sinks {
		if err := s.Start(ctx, target); err != nil {
			return err
		}
	}
	return nil
}

func (m *Multi) Write(r types.Report) error {
	var firstErr error
	for _, s := range m.Sinks {
		if err := s.Write(r); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

func (m *Multi) Flush() error {
	var firstErr error
	for _, s := range m.Sinks {
		if err := s.Flush(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

func (m *Multi) Close() error {
	var firstErr error
	for _, s := range m.Sinks {
		if err := s.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}
