package autotune

import "testing"

// TestDetect_RespectsLowerBound exercises pickTier (the pure helper
// behind Detect) with the "host is reporting nothing" floor case. Both
// the CPU and RAM gates failing must fall back to the smallest tier so
// we never accidentally select a profile the host can't sustain.
func TestDetect_RespectsLowerBound(t *testing.T) {
	got := pickTier(0, 0)
	if got.Name != "tiny" {
		t.Fatalf("pickTier(0,0) = %q, want %q", got.Name, "tiny")
	}
}

// TestDetect_PicksStrongestApplicable verifies the "last match wins"
// rule against the table. A 16-CPU / 32 GiB host should land on the
// largest tier; an 8-CPU / 8 GiB box should land on "big".
func TestDetect_PicksStrongestApplicable(t *testing.T) {
	cases := []struct {
		cpu  int
		ram  uint64
		want string
	}{
		{1, 1 << 30, "tiny"},
		{2, 2 << 30, "small"},
		{2, 4 << 30, "small-fat"},
		{4, 4 << 30, "medium"},
		{4, 8 << 30, "medium-fat"},
		{8, 8 << 30, "big"},
		{8, 16 << 30, "big-fat"},
		{16, 16 << 30, "huge"},
		{16, 32 << 30, "huge-fat"},
		// Over-spec host (32 CPU / 64 GiB) still maps to the last tier
		// in the table; we don't extrapolate beyond what's defined.
		{32, 64 << 30, "huge-fat"},
		// Edge: enough CPU for "huge" but not enough RAM — should
		// degrade to the largest tier the RAM also clears ("big").
		{16, 8 << 30, "big"},
		// CPU known, RAM unknown (0) — RAM gate is bypassed, CPU
		// alone drives the pick. cpu=8 clears up to big-fat (MinCPU=8);
		// huge requires MinCPU=16.
		{8, 0, "big-fat"},
		{16, 0, "huge-fat"},
	}
	for _, c := range cases {
		got := pickTier(c.cpu, c.ram)
		if got.Name != c.want {
			t.Errorf("pickTier(%d, %d) = %q, want %q", c.cpu, c.ram, got.Name, c.want)
		}
	}
}

// TestByName_KnownAndUnknown covers the case-insensitive lookup. Empty
// and unknown names must return ok=false.
func TestByName_KnownAndUnknown(t *testing.T) {
	if got, ok := ByName("tiny"); !ok || got.Name != "tiny" {
		t.Errorf(`ByName("tiny") = (%v, %v), want ({tiny ...}, true)`, got, ok)
	}
	if got, ok := ByName("HUGE-FAT"); !ok || got.Name != "huge-fat" {
		t.Errorf(`ByName("HUGE-FAT") = (%v, %v), want ({huge-fat ...}, true)`, got, ok)
	}
	if got, ok := ByName("  Medium  "); !ok || got.Name != "medium" {
		t.Errorf(`ByName("  Medium  ") = (%v, %v), want ({medium ...}, true)`, got, ok)
	}
	if _, ok := ByName(""); ok {
		t.Error(`ByName("") = ok=true, want ok=false`)
	}
	if _, ok := ByName("nonexistent-tier"); ok {
		t.Error(`ByName("nonexistent-tier") = ok=true, want ok=false`)
	}
}

// TestTiers_Monotonic locks in the invariant that every tier's MinCPU
// is >= the previous tier's, and every tier's MinRAMBytes is also >=
// the previous tier's. Detect's "last match wins" rule depends on this
// ordering; if a future edit reorders the table, this test catches it.
//
// We also check the Workers/PerHostQPS/ConcurrentTargets columns are
// non-decreasing — the whole point of bigger tiers is to dial UP the
// concurrency, not waver.
func TestTiers_Monotonic(t *testing.T) {
	for i := 1; i < len(Tiers); i++ {
		prev, cur := Tiers[i-1], Tiers[i]
		if cur.MinCPU < prev.MinCPU {
			t.Errorf("Tiers[%d].MinCPU=%d < Tiers[%d].MinCPU=%d (must be non-decreasing)", i, cur.MinCPU, i-1, prev.MinCPU)
		}
		if cur.MinRAMBytes < prev.MinRAMBytes {
			t.Errorf("Tiers[%d].MinRAMBytes=%d < Tiers[%d].MinRAMBytes=%d (must be non-decreasing)", i, cur.MinRAMBytes, i-1, prev.MinRAMBytes)
		}
		if cur.Workers < prev.Workers {
			t.Errorf("Tiers[%d].Workers=%d < Tiers[%d].Workers=%d (must be non-decreasing)", i, cur.Workers, i-1, prev.Workers)
		}
		if cur.WorkersProbe < prev.WorkersProbe {
			t.Errorf("Tiers[%d].WorkersProbe=%d < Tiers[%d].WorkersProbe=%d (must be non-decreasing)", i, cur.WorkersProbe, i-1, prev.WorkersProbe)
		}
		if cur.PerHostQPS < prev.PerHostQPS {
			t.Errorf("Tiers[%d].PerHostQPS=%f < Tiers[%d].PerHostQPS=%f (must be non-decreasing)", i, cur.PerHostQPS, i-1, prev.PerHostQPS)
		}
		if cur.ConcurrentTargets < prev.ConcurrentTargets {
			t.Errorf("Tiers[%d].ConcurrentTargets=%d < Tiers[%d].ConcurrentTargets=%d (must be non-decreasing)", i, cur.ConcurrentTargets, i-1, prev.ConcurrentTargets)
		}
	}
}
