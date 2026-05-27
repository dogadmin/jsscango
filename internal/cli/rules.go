package cli

import (
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
