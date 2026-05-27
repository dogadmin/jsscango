package cli

import (
	"os"
	"os/signal"
	"syscall"
)

// installSignalHandler returns a channel that fires on SIGINT/SIGTERM and a
// stop func the caller must invoke to release the signal-notify registration.
// Returning the stop hook avoids leaking the underlying handler when the
// caller wakes up early (e.g. after a graceful drain).
func installSignalHandler() (<-chan os.Signal, func()) {
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, os.Interrupt, syscall.SIGTERM)
	return ch, func() { signal.Stop(ch) }
}
