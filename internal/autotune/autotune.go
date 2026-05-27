package autotune

import "runtime"

// Detect picks the strongest tier the current host can sustain. Falls
// back to Tiers[0] ("tiny") if neither CPU nor RAM can be read.
//
// The selection rule is intentionally simple: pick the LAST tier whose
// MinCPU and MinRAMBytes thresholds the host meets. The Tiers table is
// ordered smallest → largest so the "last match wins" rule yields the
// strongest applicable profile.
//
// If sysTotalRAM returns 0 (unsupported platform, parse failure), we
// degrade gracefully by ignoring the RAM gate — the CPU gate alone
// still produces a reasonable choice. If CPU is also 0 (impossible
// under runtime.NumCPU but defended against), we return Tiers[0].
func Detect() Tier {
	cpu := runtime.NumCPU()
	ram, _ := sysTotalRAM()
	return pickTier(cpu, ram)
}

// pickTier is the pure selection helper, exposed for tests so they can
// drive arbitrary CPU/RAM values without touching real syscalls.
func pickTier(cpu int, ram uint64) Tier {
	if cpu <= 0 && ram == 0 {
		return Tiers[0]
	}
	chosen := Tiers[0]
	for _, t := range Tiers {
		if cpu < t.MinCPU {
			continue
		}
		// RAM == 0 means "unknown" — accept anything CPU lets through.
		if ram != 0 && ram < t.MinRAMBytes {
			continue
		}
		chosen = t
	}
	return chosen
}
