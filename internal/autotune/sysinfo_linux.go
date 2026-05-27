//go:build linux

package autotune

import (
	"bufio"
	"os"
	"strconv"
	"strings"
)

// sysTotalRAM reads /proc/meminfo and returns the total RAM in bytes.
// Linux-only — /proc/meminfo is the standard interface and avoids the
// libc/cgo dependency that sysconf-via-cgo would impose.
//
// The MemTotal line is documented in kilobytes (the "kB" suffix is
// historical; real value is KiB = 1024 bytes). We multiply by 1024 and
// return the byte count. Returns (0, err) on any IO or parse failure;
// the caller (Detect) treats a zero RAM as "unknown" and falls back to
// the CPU-only gate.
func sysTotalRAM() (uint64, error) {
	f, err := os.Open("/proc/meminfo")
	if err != nil {
		return 0, err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		if !strings.HasPrefix(line, "MemTotal:") {
			continue
		}
		fields := strings.Fields(line)
		// "MemTotal:       16267804 kB"
		if len(fields) < 2 {
			continue
		}
		kib, err := strconv.ParseUint(fields[1], 10, 64)
		if err != nil {
			return 0, err
		}
		return kib * 1024, nil
	}
	if err := sc.Err(); err != nil {
		return 0, err
	}
	return 0, nil
}
