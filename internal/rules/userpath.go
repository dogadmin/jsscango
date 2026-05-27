package rules

import (
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
)

// userConfigSubdir is the per-app folder appended to os.UserConfigDir(); the
// final rules file lives at <userConfigDir>/jsscango/rules.yaml.
const userConfigSubdir = "jsscango"

// userRulesFilename is the basename of the materialized rules file. Kept in
// lock-step with the embedded asset name on disk so dump/reset round-trips
// stay symmetric.
const userRulesFilename = "rules.yaml"

// EnvRulesPath names the environment variable that, when set non-empty,
// overrides both the user-config path and the embedded default. It does not
// override an explicit --rules CLI flag.
const EnvRulesPath = "JSSCANGO_RULES_PATH"

// UserRulesPath returns the conventional per-user rules.yaml path.
//
// Returns an empty string when os.UserConfigDir() fails on this platform
// (e.g. no $HOME on a stripped Linux env). The returned path may not exist
// yet - callers should fall back gracefully.
func UserRulesPath() string {
	dir, err := os.UserConfigDir()
	if err != nil || dir == "" {
		return ""
	}
	return filepath.Join(dir, userConfigSubdir, userRulesFilename)
}

// EnsureUserRulesFile writes the embedded default rules.yaml to the user
// config path if and only if no file exists there yet. Returns the path
// it considered (even on error), whether it actually wrote anything, and
// any error encountered.
//
// When err is non-nil, callers should still continue with the embedded
// defaults - this is a best-effort materialization. Pass nil logger to
// silence the trace-level "materialized" message.
func EnsureUserRulesFile(log *slog.Logger) (path string, created bool, err error) {
	path = UserRulesPath()
	if path == "" {
		return "", false, errors.New("os.UserConfigDir unavailable on this platform")
	}
	// Fast-path: file already exists. We intentionally don't compare content
	// or attempt to "heal" a broken file here; that's the job of `rules reset`.
	if _, statErr := os.Stat(path); statErr == nil {
		return path, false, nil
	} else if !errors.Is(statErr, os.ErrNotExist) {
		// Permission denied, etc. Surface to caller; they fall back to embedded.
		return path, false, fmt.Errorf("stat %s: %w", path, statErr)
	}
	// Ensure parent directory exists. 0o755 is the conventional perm for
	// dotfile config dirs; the file itself gets 0o644.
	if mkErr := os.MkdirAll(filepath.Dir(path), 0o755); mkErr != nil {
		return path, false, fmt.Errorf("mkdir %s: %w", filepath.Dir(path), mkErr)
	}
	data := EmbeddedRulesYAML()
	if len(data) == 0 {
		return path, false, errors.New("embedded rules.yaml is empty")
	}
	if writeErr := os.WriteFile(path, data, 0o644); writeErr != nil {
		return path, false, fmt.Errorf("write %s: %w", path, writeErr)
	}
	if log != nil {
		log.Info("materialized user rules.yaml from embedded defaults", "path", path)
	}
	return path, true, nil
}
