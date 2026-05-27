package extractor

import (
	"strings"
	"testing"
)

// TestUnionScanChunkedBoundary exercises the chunked-streaming path in
// FromJSBody, which is only taken when len(body) exceeds StreamThreshold.
// The first sub-test places a distinctive URL marker at an offset that
// falls within the overlapping window between adjacent chunks so the
// overlap-based recovery in unionScanChunked has to do the work — a match
// landing exclusively in chunk N's tail and chunk N+1's leading overlap.
// The second sub-test places the same marker entirely within the first
// chunk to confirm the normal in-chunk scan path still emits the value.
func TestUnionScanChunkedBoundary(t *testing.T) {
	const marker = `"/api/v1/distinctive-marker"`
	const wantValue = "/api/v1/distinctive-marker"

	// filler is a benign repeating JS-ish snippet that contains nothing
	// matching the API URL patterns we care about. The leading space
	// breaks up adjacent quoted literals so neighboring filler chunks
	// can't accidentally form a longer match that overlaps the marker.
	const filler = " var _padding = 0; "

	// makeBody produces a []byte of exactly size bytes, with the marker
	// embedded starting at offset. The bytes outside the marker are
	// filled with a repeating filler pattern.
	makeBody := func(size, offset int) []byte {
		if offset < 0 || offset+len(marker) > size {
			t.Fatalf("invalid offset/size: offset=%d marker=%d size=%d", offset, len(marker), size)
		}
		b := make([]byte, size)
		for i := 0; i < size; i++ {
			b[i] = filler[i%len(filler)]
		}
		copy(b[offset:], marker)
		return b
	}

	t.Run("StraddlesChunkBoundary", func(t *testing.T) {
		// Chunks step forward by (ChunkSize - ChunkOverlap), so chunk 0
		// covers [0, ChunkSize) and chunk 1 covers
		// [ChunkSize-ChunkOverlap, 2*ChunkSize-ChunkOverlap).
		//
		// Place the marker so it straddles position ChunkSize (the byte
		// just past the end of chunk 0). The marker starts BEFORE
		// ChunkSize - so chunk 0 holds only the marker's leading bytes
		// (not the whole thing) - and ends AFTER ChunkSize. Because the
		// actual chunk 1 starts at (ChunkSize - ChunkOverlap), which is
		// before the marker's start, chunk 1's slice contains the full
		// marker and unionScan fires there.
		//
		// If ChunkOverlap were 0, chunk 1 would start at exactly
		// ChunkSize - i.e. AFTER the marker's first byte - and the
		// marker would be split across chunk 0 (start) and chunk 1
		// (end) with neither slice holding it whole. unionScan runs the
		// regex per-chunk over a string(chunk) view and cannot stitch
		// a match across chunk slices, so the marker would be lost.
		// This test therefore genuinely requires the overlap to do its
		// job - shrinking ChunkOverlap below (len(marker) - 2) would
		// regress it.
		offset := ChunkSize - len(marker) + 2
		// Sanity: marker must extend past chunk-0 end so chunk 0 alone
		// does NOT contain it whole.
		if offset+len(marker) <= ChunkSize {
			t.Fatalf("invariant: marker must extend past chunk-0 end; got offset=%d marker=%d ChunkSize=%d",
				offset, len(marker), ChunkSize)
		}
		// Sanity: marker must start before ChunkSize so that, in a
		// hypothetical zero-overlap world, chunk 1 (starting at
		// ChunkSize) would NOT contain the marker's leading bytes -
		// proving the test exercises the overlap path.
		if offset >= ChunkSize {
			t.Fatalf("invariant: marker must start before ChunkSize so chunk-0 holds its leading bytes; got offset=%d ChunkSize=%d",
				offset, ChunkSize)
		}
		// Body must exceed StreamThreshold to take the chunked path.
		// ChunkSize (1 MiB) is well under StreamThreshold (4 MiB), so
		// we size the body to StreamThreshold + 4096 to force chunking
		// without allocating an extra chunk's worth of memory.
		size := StreamThreshold + 4096
		body := makeBody(size, offset)

		got := FromJSBody(body)
		if !hasFoundValue(got, wantValue) {
			t.Errorf("marker %q not found in chunked scan; got %d results", wantValue, len(got))
			// Debug aid: surface any near-matches so we can tell whether
			// the chunked scan dropped the marker or returned a mangled
			// fragment of it.
			for _, f := range got {
				if strings.Contains(f.Value, "distinctive") {
					t.Logf("  near-match: kind=%s value=%s pattern=%s", f.Kind, f.Value, f.Pattern)
				}
			}
		}
	})

	t.Run("WithinFirstChunk", func(t *testing.T) {
		// Confirm the normal in-chunk path also still finds the marker
		// when it sits well inside the first chunk window. Size only
		// needs to exceed StreamThreshold to trigger the chunked path;
		// no need to allocate an extra ChunkSize.
		offset := 1024
		size := StreamThreshold + 4096 // still triggers chunked path
		body := makeBody(size, offset)

		got := FromJSBody(body)
		if !hasFoundValue(got, wantValue) {
			t.Errorf("marker %q not found when placed at offset %d in chunked body", wantValue, offset)
		}
	})
}

// hasFoundValue reports whether any Found in fs has the given Value.
// We match on Value alone because the marker may legitimately be
// emitted under multiple Kind/Pattern combinations (e.g. both api and
// the union's catch-all path pattern).
func hasFoundValue(fs []Found, value string) bool {
	for _, f := range fs {
		if f.Value == value {
			return true
		}
	}
	return false
}
