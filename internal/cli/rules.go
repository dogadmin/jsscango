package cli

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"sort"

	"github.com/spf13/cobra"

	"github.com/dogadmin/jsscango/internal/rules"
)

// newRulesCmd builds the `rules` subcommand tree for inspecting and exporting
// the regex rule set used for sensitive/fingerprint/vuln detection.
func newRulesCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "rules",
		Short: "Manage the regex rule set used for sensitive/fingerprint/vuln detection",
		Long: `Inspect and export the embedded rule set.

The scanner ships with default rules embedded into the binary. Use these
subcommands to dump them to disk for editing, list what is currently loaded,
or validate a hand-edited YAML file before passing it to "scan --rules".`,
	}
	cmd.AddCommand(newRulesDumpCmd())
	cmd.AddCommand(newRulesListCmd())
	cmd.AddCommand(newRulesValidateCmd())
	cmd.AddCommand(newRulesPathCmd())
	cmd.AddCommand(newRulesResetCmd())
	return cmd
}

func newRulesDumpCmd() *cobra.Command {
	var outDir string
	var force bool
	cmd := &cobra.Command{
		Use:   "dump",
		Short: "Write the embedded YAML rule files to a directory",
		Long: `Write the embedded default rule YAMLs (rules.yaml and blacktext.yaml)
to a directory so they can be edited.

The scanner's --rules flag only takes a path to a rules.yaml file; the
blacktext.yaml stays embedded. Users typically override the regex rules but
rarely tweak the literal blacklist, so blacktext.yaml is dumped for reference
only.

Example:
  jsscango rules dump
  # edit ./rules/rules.yaml as needed
  jsscango scan -u https://example.com --rules ./rules/rules.yaml`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if err := os.MkdirAll(outDir, 0o755); err != nil {
				return fmt.Errorf("create out dir: %w", err)
			}
			files := rules.EmbeddedFiles()

			// Determine a stable iteration order so output is deterministic.
			names := make([]string, 0, len(files))
			for k := range files {
				names = append(names, k)
			}
			sort.Strings(names)

			// Pre-flight: refuse to clobber anything unless --force was given.
			if !force {
				for _, name := range names {
					p := filepath.Join(outDir, name)
					if _, err := os.Stat(p); err == nil {
						return fmt.Errorf("refusing to overwrite %s (use --force to replace)", p)
					}
				}
			}

			out := cmd.OutOrStdout()
			for _, name := range names {
				data := files[name]
				p := filepath.Join(outDir, name)
				if err := os.WriteFile(p, data, 0o644); err != nil {
					return fmt.Errorf("write %s: %w", p, err)
				}
				fmt.Fprintf(out, "wrote %s (%d bytes)\n", p, len(data))
			}
			fmt.Fprintln(out)
			fmt.Fprintln(out, "To use:")
			fmt.Fprintf(out, "  jsscango scan -u <url> --rules %s\n", filepath.Join(outDir, "rules.yaml"))
			return nil
		},
	}
	cmd.Flags().StringVar(&outDir, "out", filepath.Join(".", "rules"), "directory to write the YAML files into")
	cmd.Flags().BoolVar(&force, "force", false, "overwrite existing files in the output directory")
	return cmd
}

func newRulesListCmd() *cobra.Command {
	var path string
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List loaded rule IDs grouped by kind",
		Long: `Load the rule set (embedded defaults unless --rules is given) and print
one rule per line, grouped by Kind (fingerprint, vuln, sensitive). The rule
ID is left-aligned within each group and the pattern is truncated to 60
characters for readability.`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			set, err := rules.Load(path)
			if err != nil {
				return err
			}
			// Report compile errors first so they're not lost in a long listing.
			if errs := set.CompileErrors(); len(errs) > 0 {
				ids := make([]string, 0, len(errs))
				for id := range errs {
					ids = append(ids, id)
				}
				sort.Strings(ids)
				fmt.Fprintf(cmd.ErrOrStderr(), "warning: %d rule(s) failed to compile:\n", len(errs))
				for _, id := range ids {
					fmt.Fprintf(cmd.ErrOrStderr(), "  %s: %v\n", id, errs[id])
				}
			}

			// Group by Kind, preserving the canonical order rather than relying
			// on map iteration.
			order := []rules.Kind{rules.KindFingerprint, rules.KindVuln, rules.KindSensitive}
			groups := map[rules.Kind][]*rules.Rule{}
			for _, r := range set.Rules {
				groups[r.Kind] = append(groups[r.Kind], r)
			}

			out := cmd.OutOrStdout()
			for _, k := range order {
				rs := groups[k]
				if len(rs) == 0 {
					continue
				}
				sort.SliceStable(rs, func(i, j int) bool { return rs[i].ID < rs[j].ID })
				maxID := 0
				for _, r := range rs {
					if n := len(r.ID); n > maxID {
						maxID = n
					}
				}
				fmt.Fprintf(out, "%s (%d)\n", string(k), len(rs))
				for _, r := range rs {
					fmt.Fprintf(out, "  %-*s  f_regex=%s\n", maxID, r.ID, truncatePattern(r.Pattern, 60))
				}
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&path, "rules", "", "load this YAML instead of the embedded defaults")
	return cmd
}

func newRulesValidateCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "validate <path>",
		Short: "Parse and compile a user-provided rules YAML",
		Long: `Load the given YAML file as if it were passed to "scan --rules" and
report any compile errors. Exits non-zero if any rule fails to compile or the
file cannot be parsed.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			path := args[0]
			set, err := rules.Load(path)
			if err != nil {
				return err
			}
			out := cmd.OutOrStdout()
			if errs := set.CompileErrors(); len(errs) > 0 {
				ids := make([]string, 0, len(errs))
				for id := range errs {
					ids = append(ids, id)
				}
				sort.Strings(ids)
				for _, id := range ids {
					fmt.Fprintf(cmd.ErrOrStderr(), "FAIL %s: %v\n", id, errs[id])
				}
				return fmt.Errorf("%d rule(s) failed to compile", len(errs))
			}
			counts := set.Count()
			fmt.Fprintf(out,
				"OK: %d rules compiled (%d fingerprint, %d vuln, %d sensitive)\n",
				len(set.Rules),
				counts[rules.KindFingerprint],
				counts[rules.KindVuln],
				counts[rules.KindSensitive],
			)
			return nil
		},
	}
	return cmd
}

// truncatePattern shortens s to at most n runes followed by "..." when it
// exceeds the limit. Operates on bytes since rule patterns are ASCII regex.
func truncatePattern(s string, n int) string {
	if len(s) <= n {
		return s
	}
	if n <= 3 {
		return s[:n]
	}
	return s[:n-3] + "..."
}

// newRulesPathCmd prints the layered rules-source resolution so users can
// see at a glance which YAML "scan" would actually load right now.
func newRulesPathCmd() *cobra.Command {
	var flagPath string
	cmd := &cobra.Command{
		Use:   "path",
		Short: "Show which rules.yaml file the scanner would load",
		Long: `Print each layer of the rules-source precedence (flag, env, user
config, embedded) along with its status, then print the file that would
actually be used. Exit 0 always.

Precedence (highest first):
  1. --rules <path>           (CLI flag)
  2. $JSSCANGO_RULES_PATH     (environment variable)
  3. $USER_CONFIG_DIR/jsscango/rules.yaml  (lazily auto-created)
  4. embedded defaults        (compiled into the binary)`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			out := cmd.OutOrStdout()

			// Layer 1: --rules flag passed to this command (if any).
			flagDisplay := "(not set)"
			if flagPath != "" {
				flagDisplay = flagPath
				if _, err := os.Stat(flagPath); err != nil {
					flagDisplay = flagPath + " (MISSING)"
				}
			}
			fmt.Fprintf(out, "flag:     %s\n", flagDisplay)

			// Layer 2: env var.
			envVal := os.Getenv(rules.EnvRulesPath)
			envDisplay := "$" + rules.EnvRulesPath + " not set"
			if envVal != "" {
				envDisplay = envVal
				if _, err := os.Stat(envVal); err != nil {
					envDisplay = envVal + " (MISSING)"
				}
			}
			fmt.Fprintf(out, "env:      %s\n", envDisplay)

			// Layer 3: user config path. Don't auto-create here; "path" should
			// be read-only. Report (exists) / (not yet) honestly.
			userPath := rules.UserRulesPath()
			userDisplay := "(unavailable on this platform)"
			if userPath != "" {
				if _, err := os.Stat(userPath); err == nil {
					userDisplay = userPath + " (exists)"
				} else {
					userDisplay = userPath + " (not yet; created on next scan)"
				}
			}
			fmt.Fprintf(out, "user:     %s\n", userDisplay)

			// Layer 4: embedded fallback - always present.
			fmt.Fprintf(out, "embedded: (fallback, compiled in)\n")
			fmt.Fprintln(out)

			// Resolved: simulate the same precedence Load() uses, without
			// triggering materialization.
			resolved := "embedded"
			switch {
			case flagPath != "":
				resolved = "flag:" + flagPath
			case envVal != "":
				resolved = "env:" + envVal
			case userPath != "":
				if _, err := os.Stat(userPath); err == nil {
					resolved = "user:" + userPath
				}
			}
			fmt.Fprintf(out, "resolved: %s\n", resolved)
			return nil
		},
	}
	cmd.Flags().StringVar(&flagPath, "rules", "", "simulate the --rules flag from `scan`")
	return cmd
}

// newRulesResetCmd overwrites the user-config rules.yaml with the embedded
// default. Refuses to clobber a locally-edited file unless --force is set.
func newRulesResetCmd() *cobra.Command {
	var force bool
	cmd := &cobra.Command{
		Use:   "reset",
		Short: "Overwrite the user rules.yaml with the embedded defaults",
		Long: `Re-write the per-user rules.yaml from the embedded defaults. Useful
when you've edited the file into a non-working state.

Refuses to overwrite a locally-modified file unless --force is set; "local
modification" is detected by SHA-256 comparison against the embedded
baseline.`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			userPath := rules.UserRulesPath()
			if userPath == "" {
				return fmt.Errorf("os.UserConfigDir unavailable on this platform; cannot reset")
			}
			out := cmd.OutOrStdout()

			embedded := rules.EmbeddedRulesYAML()
			if len(embedded) == 0 {
				return fmt.Errorf("embedded rules.yaml is empty (build problem)")
			}

			existing, err := os.ReadFile(userPath)
			switch {
			case err == nil:
				// File exists - compare to embedded baseline.
				if !bytes.Equal(sha256sum(existing), sha256sum(embedded)) && !force {
					fmt.Fprintf(cmd.ErrOrStderr(),
						"user rules at %s differ from embedded baseline; pass --force to overwrite\n",
						userPath)
					// Exit 2 per the contract in the task description; cobra
					// will translate the SilenceUsage on RunE error to a plain
					// non-zero exit, but we want a SPECIFIC code. Use os.Exit
					// after a clean error message.
					os.Exit(2)
				}
			case os.IsNotExist(err):
				// No prior file - we're effectively doing first-run materialization.
			default:
				return fmt.Errorf("stat %s: %w", userPath, err)
			}

			if mkErr := os.MkdirAll(filepath.Dir(userPath), 0o755); mkErr != nil {
				return fmt.Errorf("mkdir %s: %w", filepath.Dir(userPath), mkErr)
			}
			if wErr := os.WriteFile(userPath, embedded, 0o644); wErr != nil {
				return fmt.Errorf("write %s: %w", userPath, wErr)
			}
			fmt.Fprintf(out, "overwrote %s with embedded defaults (%d bytes)\n", userPath, len(embedded))
			return nil
		},
	}
	cmd.Flags().BoolVar(&force, "force", false, "overwrite even if the user file has local edits vs. the embedded baseline")
	return cmd
}

// sha256sum is a tiny helper so the reset diff-check stays one line.
func sha256sum(b []byte) []byte {
	h := sha256.Sum256(b)
	return h[:]
}
