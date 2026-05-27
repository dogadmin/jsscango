package state

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

const stateFileName = "state.json"
const ResumeSchemaVersion = "jsscango-state/v1"

// Stage names. Use these constants when calling Resume.Done / Resume.IsDone
// so a typo in one site doesn't silently break resume.
const (
	StageWellKnown       = "wellknown"
	StageHomepage        = "homepage"
	StageCrawl           = "crawl"
	StageProbe           = "probe"
	StageAncestorRecurse = "ancestor_recurse"
	StagePostprocess     = "postprocess"
)

// File is the on-disk shape, serialized as JSON.
type File struct {
	Schema      string          `json:"schema"`
	Target      string          `json:"target"`
	StartedAt   time.Time       `json:"started_at"`
	UpdatedAt   time.Time       `json:"updated_at"`
	FinishedAt  *time.Time      `json:"finished_at,omitempty"`
	StagesDone  map[string]bool `json:"stages_done"`
	SeenURLs    []string        `json:"seen_urls,omitempty"`
	Stats       map[string]int  `json:"stats,omitempty"`
}

// Resume is the in-memory state tracker. It owns its file path so callers
// just call Done / IsDone / Save without juggling paths.
type Resume struct {
	mu   sync.Mutex
	path string
	file File
}

// LoadOrInit reads <dir>/state.json if it exists, otherwise initializes a
// fresh state. The "loaded" return distinguishes a resume from a first run.
func LoadOrInit(dir, target string) (r *Resume, loaded bool, err error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, false, err
	}
	path := filepath.Join(dir, stateFileName)
	r = &Resume{
		path: path,
		file: File{
			Schema:     ResumeSchemaVersion,
			Target:     target,
			StartedAt:  time.Now(),
			UpdatedAt:  time.Now(),
			StagesDone: map[string]bool{},
			Stats:      map[string]int{},
		},
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return r, false, nil
		}
		return nil, false, err
	}
	var f File
	if err := json.Unmarshal(data, &f); err != nil {
		// Corrupt state file - log and start fresh rather than refusing to run.
		return r, false, fmt.Errorf("state.json corrupt, starting fresh: %w", err)
	}
	if f.Target != "" && f.Target != target {
		return r, false, fmt.Errorf("state.json target mismatch (%q vs %q)", f.Target, target)
	}
	if f.StagesDone == nil {
		f.StagesDone = map[string]bool{}
	}
	if f.Stats == nil {
		f.Stats = map[string]int{}
	}
	r.file = f
	return r, true, nil
}

// IsDone reports whether the named stage was completed in a previous run.
func (r *Resume) IsDone(stage string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.file.StagesDone[stage]
}

// Done marks a stage complete and persists the state to disk. Use Save
// directly if you've made multiple updates that should hit disk in one go.
func (r *Resume) Done(stage string) error {
	r.mu.Lock()
	r.file.StagesDone[stage] = true
	r.file.UpdatedAt = time.Now()
	r.mu.Unlock()
	return r.Save()
}

// SetStat records or overwrites a named counter.
func (r *Resume) SetStat(name string, n int) {
	r.mu.Lock()
	r.file.Stats[name] = n
	r.mu.Unlock()
}

// SetSeenURLs replaces the persisted URL set. Called once at the end of the
// crawl stage so subsequent runs can hydrate Seen and skip work.
func (r *Resume) SetSeenURLs(urls []string) {
	r.mu.Lock()
	cp := make([]string, len(urls))
	copy(cp, urls)
	r.file.SeenURLs = cp
	r.mu.Unlock()
}

// SeenURLs returns the persisted URL set (empty on fresh run).
func (r *Resume) SeenURLs() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	cp := make([]string, len(r.file.SeenURLs))
	copy(cp, r.file.SeenURLs)
	return cp
}

// Finish marks the run as fully complete and persists.
func (r *Resume) Finish() error {
	r.mu.Lock()
	now := time.Now()
	r.file.FinishedAt = &now
	r.file.UpdatedAt = now
	r.mu.Unlock()
	return r.Save()
}

// Save serializes the state atomically via tmp-file + rename.
func (r *Resume) Save() error {
	r.mu.Lock()
	r.file.UpdatedAt = time.Now()
	data, err := json.MarshalIndent(r.file, "", "  ")
	r.mu.Unlock()
	if err != nil {
		return err
	}
	tmp := r.path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, r.path)
}

// HydrateSeen seeds a *Seen with the URLs persisted in this state so the
// crawler won't re-fetch them.
func (r *Resume) HydrateSeen(s *Seen) {
	for _, u := range r.SeenURLs() {
		s.AddURL(u)
	}
}
