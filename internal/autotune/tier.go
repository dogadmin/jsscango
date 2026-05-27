// Package autotune chooses a sensible parallelism profile ("tier") for the
// scan based on the host's detected CPU count and RAM. Operators can either
// let Detect() pick the strongest tier the host can sustain or pin one by
// name via the CLI (--tune=<name>).
//
// The whole point of this package is to avoid the all-too-common
// 30k-target scan getting stuck because the operator hand-tuned for a
// laptop and then ran it on a 16-core box (or vice versa). The defaults
// here are deliberately conservative — every tier value is comfortably
// supportable on the named hardware floor.
package autotune

import "strings"

// Tier names a baked-in configuration profile keyed by detected
// CPU + RAM. Operators pick by name with --tune=<tier>, OR let
// Detect() choose for them.
type Tier struct {
	Name              string
	MinCPU            int    // host must have at least this many logical CPUs
	MinRAMBytes       uint64 // and at least this much RAM
	Workers           int
	WorkersCrawl      int
	WorkersProbe      int
	PerHostQPS        float64
	ConcurrentTargets int
}

// Tiers is the ordered tier table — Detect picks the LAST tier whose
// thresholds the host satisfies. Order: smallest → largest. Operators
// who want predictability can pin a specific tier by name via the CLI.
var Tiers = []Tier{
	{"tiny", 1, 1 << 30, 16, 16, 32, 3, 1},          // 1 CPU, 1 GiB
	{"small", 2, 2 << 30, 32, 32, 64, 5, 2},         // 2 CPU, 2 GiB
	{"small-fat", 2, 4 << 30, 48, 48, 96, 5, 2},     // 2 CPU, 4 GiB
	{"medium", 4, 4 << 30, 64, 64, 128, 8, 4},       // 4 CPU, 4 GiB
	{"medium-fat", 4, 8 << 30, 96, 96, 192, 10, 4},  // 4 CPU, 8 GiB
	{"big", 8, 8 << 30, 128, 128, 256, 15, 8},       // 8 CPU, 8 GiB
	{"big-fat", 8, 16 << 30, 192, 192, 384, 20, 8},  // 8 CPU, 16 GiB
	{"huge", 16, 16 << 30, 256, 256, 512, 25, 16},   // 16 CPU, 16 GiB
	{"huge-fat", 16, 32 << 30, 384, 384, 768, 30, 16}, // 16 CPU, 32 GiB
}

// ByName looks up a tier by its Name (case-insensitive). Returns the
// zero Tier and ok=false on no match.
func ByName(name string) (Tier, bool) {
	want := strings.ToLower(strings.TrimSpace(name))
	if want == "" {
		return Tier{}, false
	}
	for _, t := range Tiers {
		if strings.ToLower(t.Name) == want {
			return t, true
		}
	}
	return Tier{}, false
}
