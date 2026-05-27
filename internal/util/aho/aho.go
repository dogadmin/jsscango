// Package aho is a minimal byte-level Aho-Corasick multi-pattern substring
// matcher. It replaces the O(N*M) "contains-any-of-N-strings" linear scans
// in the extractor and rules packages with a single O(N) trie walk.
//
// The matcher works on raw bytes, which is what we want: every input we
// scan is UTF-8 encoded, and so are the patterns; matching at the byte
// level over UTF-8 has the same semantics as matching at the rune level
// because UTF-8 is prefix-free.
package aho

// node is one state in the AC trie. We intentionally store the goto edges
// in a map rather than a fixed-size [256]int because real workloads use
// only a handful of distinct bytes per state, keeping memory low.
type node struct {
	next     map[byte]int
	fail     int
	terminal bool
}

// Matcher is built once via New and then safe for concurrent reads.
type Matcher struct {
	nodes []node
}

// New builds the AC automaton over patterns. Empty patterns are ignored.
// Duplicate patterns are accepted (they collapse to one terminal node).
//
// Time:   O(sum-of-pattern-lengths)
// Memory: ~one node per distinct prefix-byte across all patterns.
func New(patterns []string) *Matcher {
	m := &Matcher{nodes: []node{{next: make(map[byte]int)}}} // root
	for _, p := range patterns {
		if p == "" {
			continue
		}
		cur := 0
		for i := 0; i < len(p); i++ {
			b := p[i]
			nxt, ok := m.nodes[cur].next[b]
			if !ok {
				nxt = len(m.nodes)
				m.nodes = append(m.nodes, node{next: make(map[byte]int)})
				m.nodes[cur].next[b] = nxt
			}
			cur = nxt
		}
		m.nodes[cur].terminal = true
	}
	m.buildFailLinks()
	return m
}

// buildFailLinks computes the suffix/fail links via BFS from root. After this
// step a node is `terminal` iff its own pattern OR any pattern that ends as
// a suffix of the current prefix matched - the latter is propagated by
// checking the fail target.
func (m *Matcher) buildFailLinks() {
	// Initialize: depth-1 nodes all fall back to root.
	queue := make([]int, 0, 32)
	for _, n := range m.nodes[0].next {
		m.nodes[n].fail = 0
		queue = append(queue, n)
	}
	for len(queue) > 0 {
		cur := queue[0]
		queue = queue[1:]
		for b, child := range m.nodes[cur].next {
			// Walk fail links from parent to find longest proper suffix
			// that the trie can follow on byte b.
			f := m.nodes[cur].fail
			for {
				if next, ok := m.nodes[f].next[b]; ok && next != child {
					m.nodes[child].fail = next
					break
				}
				if f == 0 {
					m.nodes[child].fail = 0
					break
				}
				f = m.nodes[f].fail
			}
			// Propagate terminal via fail link so we can early-exit
			// without walking the suffix chain at match time.
			if m.nodes[m.nodes[child].fail].terminal {
				m.nodes[child].terminal = true
			}
			queue = append(queue, child)
		}
	}
}

// Contains reports whether text contains any of the patterns. Early-exits at
// first hit. Returns false for an empty matcher or empty text.
func (m *Matcher) Contains(text []byte) bool {
	if m == nil || len(m.nodes) <= 1 {
		return false
	}
	cur := 0
	for i := 0; i < len(text); i++ {
		b := text[i]
		// Follow goto edges; if none, fall back via fail links.
		for {
			if next, ok := m.nodes[cur].next[b]; ok {
				cur = next
				break
			}
			if cur == 0 {
				break
			}
			cur = m.nodes[cur].fail
		}
		if m.nodes[cur].terminal {
			return true
		}
	}
	return false
}

// ContainsString is a convenience wrapper that avoids a []byte conversion at
// the call site. Internally it still operates on the string's byte view.
func (m *Matcher) ContainsString(text string) bool {
	if m == nil || len(m.nodes) <= 1 {
		return false
	}
	cur := 0
	for i := 0; i < len(text); i++ {
		b := text[i]
		for {
			if next, ok := m.nodes[cur].next[b]; ok {
				cur = next
				break
			}
			if cur == 0 {
				break
			}
			cur = m.nodes[cur].fail
		}
		if m.nodes[cur].terminal {
			return true
		}
	}
	return false
}

// Size returns the node count - useful for tests and sizing assertions.
func (m *Matcher) Size() int {
	if m == nil {
		return 0
	}
	return len(m.nodes)
}
