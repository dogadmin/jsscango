package cli

import (
	"os"
	"os/signal"
	"syscall"
)

func installSignalHandler() <-chan os.Signal {
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, os.Interrupt, syscall.SIGTERM)
	return ch
}
