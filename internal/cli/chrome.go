package cli

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/dogadmin/jsscango/internal/fetcher"
	"github.com/dogadmin/jsscango/internal/util"
)

// newChromeCmd builds the `chrome` subcommand tree for managing the bundled
// Chromium browser used by --chrome=on / --chrome=auto.
func newChromeCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "chrome",
		Short: "Manage the bundled Chromium browser used by --chrome=on",
		Long: `Manage the Chromium build used by chromedp homepage discovery.

System Chrome on PATH is always preferred. If none is installed (typical on
headless Linux servers), run "jsscango chrome download" once to fetch an
official Chromium snapshot into the local cache, then "jsscango scan
--chrome=on" will pick it up automatically.

Cache location:
  Linux:   $XDG_CACHE_HOME/rod/browser/  (default $HOME/.cache/rod/browser/)
  macOS:   $HOME/Library/Caches/rod/browser/
  Windows: %LOCALAPPDATA%\rod\browser\`,
	}
	cmd.AddCommand(newChromeDownloadCmd())
	cmd.AddCommand(newChromePathCmd())
	return cmd
}

func newChromeDownloadCmd() *cobra.Command {
	var logLevel string
	cmd := &cobra.Command{
		Use:   "download",
		Short: "Download the pinned Chromium snapshot into the local cache",
		Long: `Fetch an official Chromium build into the go-rod launcher cache. The
download is ~150 MiB and may take several minutes on a slow link. Reuses
an existing cache on subsequent runs.`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			logger, err := util.NewLogger(logLevel, "")
			if err != nil {
				return fmt.Errorf("logger: %w", err)
			}
			path, err := fetcher.DownloadChrome(logger)
			if err != nil {
				return err
			}
			fmt.Fprintln(cmd.OutOrStdout(), path)
			return nil
		},
	}
	cmd.Flags().StringVar(&logLevel, "log-level", "info", "debug|info|warn|error")
	return cmd
}

func newChromePathCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "path",
		Short: "Print the path to a usable Chrome binary, if any",
		Long: `Print the path the scanner would use for chromedp homepage discovery.
Order:
  1. system Chrome/Chromium on PATH
  2. standard install locations on Windows
  3. go-rod launcher cache (populated by "jsscango chrome download")

Exits 0 with the path on stdout when found, 1 with an empty stdout otherwise.`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if !fetcher.HeadlessAvailable() {
				return fmt.Errorf("no Chrome binary found; run `jsscango chrome download` to fetch one")
			}
			// Reach into the same lookup logic the scanner uses.
			path := fetcher.LookupChromePath()
			fmt.Fprintln(cmd.OutOrStdout(), path)
			return nil
		},
	}
}
