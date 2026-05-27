package rules

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadDefault(t *testing.T) {
	s, err := Load("")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(s.Rules) == 0 {
		t.Fatal("no rules loaded")
	}
	if len(s.BlackText) == 0 {
		t.Fatal("no black text markers")
	}
	if errs := s.CompileErrors(); len(errs) > 0 {
		for id, err := range errs {
			t.Errorf("rule %q failed to compile: %v", id, err)
		}
	}
}

func TestApplyFindsJWT(t *testing.T) {
	s, err := Load("")
	if err != nil {
		t.Fatal(err)
	}
	body := []byte(`Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NSIsIm5hbWUiOiJBbGljZSJ9.5lABDsT0Q3JaQwBJ1lYU0L8aRl5GckkBdLb0sH9_pjE`)
	hits := s.Apply(body)
	gotJWT := false
	// After the HaE merge the JWT rule lives under "fp-json-web-token"; the
	// historical "jwt_token" id was superseded. Accept either so the test is
	// robust against rule renames.
	jwtIDs := map[string]bool{"jwt_token": true, "fp-json-web-token": true}
	for _, h := range hits {
		if jwtIDs[h.RuleID] {
			gotJWT = true
			if len(h.Matches) == 0 {
				t.Errorf("%s matched but Matches is empty", h.RuleID)
			}
		}
	}
	if !gotJWT {
		t.Errorf("expected JWT match (jwt_token or fp-json-web-token), got rules: %v", ruleIDs(hits))
	}
}

// TestRuleCount sanity-checks that the merged HaE+jsscango rule set is at
// least roughly the size we expect after the upstream HaE Config.yml import.
// Bumping this floor is fine when upstream adds more rules; a drop below this
// threshold suggests the merge regressed.
func TestRuleCount(t *testing.T) {
	s, err := Load("")
	if err != nil {
		t.Fatal(err)
	}
	const minRules = 60
	if len(s.Rules) < minRules {
		t.Errorf("expected at least %d rules after HaE merge, got %d", minRules, len(s.Rules))
	}
	counts := s.Count()
	if counts[KindFingerprint] == 0 {
		t.Error("no fingerprint rules in merged set")
	}
	if counts[KindSensitive] == 0 {
		t.Error("no sensitive rules in merged set")
	}
}

func TestIsBlackText(t *testing.T) {
	s, err := Load("")
	if err != nil {
		t.Fatal(err)
	}
	if !s.IsBlackText([]byte(`some response containing "未找到API注册信息" mid-string`)) {
		t.Error("expected BLACK_TEXT match for 未找到API注册信息")
	}
	if s.IsBlackText([]byte(`a perfectly fine response`)) {
		t.Error("false positive on benign response")
	}
}

func ruleIDs(hits []Hit) []string {
	out := make([]string, 0, len(hits))
	for _, h := range hits {
		out = append(out, h.RuleID)
	}
	return out
}

func TestEmbeddedFiles(t *testing.T) {
	files := EmbeddedFiles()
	for _, name := range []string{"rules.yaml", "blacktext.yaml"} {
		b, ok := files[name]
		if !ok {
			t.Errorf("EmbeddedFiles missing key %q", name)
			continue
		}
		if len(b) == 0 {
			t.Errorf("EmbeddedFiles[%q] is empty", name)
		}
	}
	if len(EmbeddedRulesYAML()) == 0 {
		t.Error("EmbeddedRulesYAML returned empty bytes")
	}
	if len(EmbeddedBlackTextYAML()) == 0 {
		t.Error("EmbeddedBlackTextYAML returned empty bytes")
	}
}

// isolateUserConfigDir points os.UserConfigDir() at a fresh tempdir for the
// duration of the test. Different platforms key off different env vars; we
// scrub all of them and set the one this OS uses.
//
// The exhaustive scrub is deliberate: if a developer happens to have
// $XDG_CONFIG_HOME set, the macOS path-builder still honors $HOME unless we
// neutralize it here.
func isolateUserConfigDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	// Linux / generic XDG.
	t.Setenv("XDG_CONFIG_HOME", dir)
	// Windows.
	t.Setenv("AppData", dir)
	// macOS uses $HOME/Library/Application Support.
	t.Setenv("HOME", dir)
	return dir
}

// TestLoad_EmbeddedFallback verifies that when no flag and no env are set
// AND the user-config write fails, Load still returns the embedded defaults
// without erroring. We force the user-config write to fail by pointing
// XDG_CONFIG_HOME at a path that can never be created (a file masquerading
// as a directory).
func TestLoad_EmbeddedFallback(t *testing.T) {
	t.Setenv(EnvRulesPath, "")
	// Create a regular file at XDG_CONFIG_HOME so MkdirAll fails.
	dir := t.TempDir()
	blocker := filepath.Join(dir, "blocker")
	if err := os.WriteFile(blocker, []byte("not a dir"), 0o644); err != nil {
		t.Fatalf("create blocker file: %v", err)
	}
	t.Setenv("XDG_CONFIG_HOME", blocker)
	t.Setenv("AppData", blocker)
	t.Setenv("HOME", blocker)

	set, err := Load("")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if set.Source != "embedded" {
		t.Errorf("Source = %q, want %q", set.Source, "embedded")
	}
	if len(set.Rules) == 0 {
		t.Error("no rules loaded from embedded fallback")
	}
}

// TestLoad_UserConfigPath verifies the env-var override path: writing a
// custom rules.yaml to a tempdir, pointing $JSSCANGO_RULES_PATH at it, and
// confirming Load reads from there with the correct Source tag.
func TestLoad_UserConfigPath(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "custom.yaml")
	// A minimal but valid rules YAML with exactly one fingerprint rule so
	// we can tell it apart from the embedded defaults.
	yaml := []byte(`rules:
  - id: __test_marker__
    kind: fingerprint
    group: testing
    pattern: "TEST_MARKER_LITERAL"
`)
	if err := os.WriteFile(path, yaml, 0o644); err != nil {
		t.Fatalf("write custom rules: %v", err)
	}
	t.Setenv(EnvRulesPath, path)

	set, err := Load("")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if want := "env:" + path; set.Source != want {
		t.Errorf("Source = %q, want %q", set.Source, want)
	}
	if len(set.Rules) != 1 || set.Rules[0].ID != "__test_marker__" {
		t.Errorf("unexpected rules loaded: %+v", set.Rules)
	}
}

// TestLoad_FlagWinsOverEnv verifies the documented precedence: an explicit
// --rules path beats $JSSCANGO_RULES_PATH.
func TestLoad_FlagWinsOverEnv(t *testing.T) {
	dir := t.TempDir()
	envPath := filepath.Join(dir, "env.yaml")
	flagPath := filepath.Join(dir, "flag.yaml")
	envYAML := []byte("rules:\n  - id: env_rule\n    kind: vuln\n    pattern: ENV\n")
	flagYAML := []byte("rules:\n  - id: flag_rule\n    kind: vuln\n    pattern: FLAG\n")
	if err := os.WriteFile(envPath, envYAML, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(flagPath, flagYAML, 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv(EnvRulesPath, envPath)

	set, err := Load(flagPath)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !strings.HasPrefix(set.Source, "flag:") {
		t.Errorf("Source = %q, want flag:* prefix", set.Source)
	}
	if len(set.Rules) != 1 || set.Rules[0].ID != "flag_rule" {
		t.Errorf("flag path lost to env: %+v", set.Rules)
	}
}

// TestEnsureUserRulesFile_FirstRun verifies the lazy-materialization
// happy path: a fresh user-config dir gets the embedded YAML written into
// it and the function reports created=true.
func TestEnsureUserRulesFile_FirstRun(t *testing.T) {
	dir := isolateUserConfigDir(t)
	t.Setenv(EnvRulesPath, "")

	path, created, err := EnsureUserRulesFile(nil)
	if err != nil {
		t.Fatalf("EnsureUserRulesFile: %v", err)
	}
	if !created {
		t.Error("expected created=true on first run, got false")
	}
	if path == "" {
		t.Fatal("returned empty path")
	}
	if !strings.HasPrefix(path, dir) {
		t.Errorf("path %q does not start with %q", path, dir)
	}
	// Verify the file is on disk and matches the embedded bytes.
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read materialized file: %v", err)
	}
	if string(got) != string(EmbeddedRulesYAML()) {
		t.Error("materialized content differs from EmbeddedRulesYAML()")
	}
}

// TestEnsureUserRulesFile_Idempotent verifies that a second call after the
// file exists is a no-op (created=false, contents untouched).
func TestEnsureUserRulesFile_Idempotent(t *testing.T) {
	isolateUserConfigDir(t)
	t.Setenv(EnvRulesPath, "")

	path, created, err := EnsureUserRulesFile(nil)
	if err != nil {
		t.Fatalf("first EnsureUserRulesFile: %v", err)
	}
	if !created {
		t.Fatal("expected created=true on first call")
	}
	// User-edits the file: replace with garbage that wouldn't parse. The
	// idempotent code path must NOT overwrite this.
	marker := []byte("# user edit do not touch\nrules: []\n")
	if err := os.WriteFile(path, marker, 0o644); err != nil {
		t.Fatalf("user edit: %v", err)
	}

	_, created2, err := EnsureUserRulesFile(nil)
	if err != nil {
		t.Fatalf("second EnsureUserRulesFile: %v", err)
	}
	if created2 {
		t.Error("expected created=false on second call (file already existed)")
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("re-read after second call: %v", err)
	}
	if string(after) != string(marker) {
		t.Errorf("second call clobbered user edits; got %q want %q", after, marker)
	}
}

// TestLoad_UserPathAutoMaterialize verifies the end-to-end flow that motivates
// this feature: fresh config dir, no flags, no env -> Load creates the file
// AND reads from it, reporting source="user:<path>".
func TestLoad_UserPathAutoMaterialize(t *testing.T) {
	isolateUserConfigDir(t)
	t.Setenv(EnvRulesPath, "")

	set, err := Load("")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !strings.HasPrefix(set.Source, "user:") {
		t.Errorf("Source = %q, want user:* prefix", set.Source)
	}
	// The materialized file must now exist on disk.
	userPath := UserRulesPath()
	if _, err := os.Stat(userPath); err != nil {
		t.Errorf("user file not on disk after Load: %v", err)
	}
}
