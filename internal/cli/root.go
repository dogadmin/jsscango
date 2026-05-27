package cli

import (
	"github.com/spf13/cobra"
)

// NewRoot builds the cobra command tree.
func NewRoot(version string) *cobra.Command {
	root := &cobra.Command{
		Use:           "getjsurlscan",
		Short:         "JS / static URL / API path scanner (Go port)",
		SilenceErrors: true,
		SilenceUsage:  true,
	}
	root.AddCommand(newScanCmd())
	root.AddCommand(newChromeCmd())
	root.AddCommand(newVersionCmd(version))
	return root
}

func newVersionCmd(version string) *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print build version",
		RunE: func(cmd *cobra.Command, _ []string) error {
			_, err := cmd.OutOrStdout().Write([]byte(version + "\n"))
			return err
		},
	}
}
