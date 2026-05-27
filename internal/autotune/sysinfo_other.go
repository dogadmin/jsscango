//go:build !linux && !windows

package autotune

import "errors"

// sysTotalRAM is a stub for platforms we don't have a dedicated reader
// for (macOS, *BSD, Solaris, ...). Detect treats a (0, err) return as
// "unknown" and degrades to the CPU-only gate; in practice that means
// macOS/BSD users still get a tier picked by CPU count alone, which is
// the same outcome as Linux when /proc/meminfo is somehow unreadable.
func sysTotalRAM() (uint64, error) {
	return 0, errors.New("unsupported")
}
