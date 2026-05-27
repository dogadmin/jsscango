package state

import (
	"crypto/sha256"
	"encoding/hex"
	"sync"
)

// Seen is a per-target dedup gate for URLs and response bodies. Concurrency
// safe.
type Seen struct {
	mu       sync.Mutex
	urls     map[string]struct{}
	bodyHash map[[32]byte]string
}

func NewSeen() *Seen {
	return &Seen{
		urls:     make(map[string]struct{}, 256),
		bodyHash: make(map[[32]byte]string, 64),
	}
}

// AddURL returns true if u was new (and stores it). Replaces the
// list-membership check + append at jsAndStaticUrlFind.py:226 and the
// equivalent at apiPathFind.py:397.
func (s *Seen) AddURL(u string) bool {
	if u == "" {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.urls[u]; ok {
		return false
	}
	s.urls[u] = struct{}{}
	return true
}

// HasURL reports whether u was already seen.
func (s *Seen) HasURL(u string) bool {
	s.mu.Lock()
	_, ok := s.urls[u]
	s.mu.Unlock()
	return ok
}

// AddBody hashes b and records the first URL seen for that hash. Returns
// (firstSeenURL, isNew). When isNew=false the caller may skip saving the
// body to disk — the dedup in postprocess will use the existing copy.
func (s *Seen) AddBody(b []byte, u string) (string, bool) {
	h := sha256.Sum256(b)
	s.mu.Lock()
	defer s.mu.Unlock()
	if prev, ok := s.bodyHash[h]; ok {
		return prev, false
	}
	s.bodyHash[h] = u
	return u, true
}

// SHA returns the hex sha256 of b. Convenience for ProbeResult.BodySHA256.
func SHA(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

// Snapshot returns a copy of the current URL set. Useful for state.json.
func (s *Seen) Snapshot() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]string, 0, len(s.urls))
	for u := range s.urls {
		out = append(out, u)
	}
	return out
}
