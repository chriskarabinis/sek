package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var uninstallCmd = &cobra.Command{
	Use:   "uninstall",
	Short: "Remove sek from your system",
	Long:  `Delete the sek binary from /usr/local/bin.`,
	Run: func(cmd *cobra.Command, args []string) {
		execPath, err := os.Executable()
		if err != nil {
			WriteLine(fmt.Sprintf("[!] Could not locate binary: %s", err))
			os.Exit(1)
		}

		WriteLine(fmt.Sprintf("[*] Removing: %s", execPath))

		if err := os.Remove(execPath); err != nil {
			WriteLine("[!] Permission denied — try: sudo sek uninstall")
			os.Exit(1)
		}

		WriteLine("[*] sek has been removed.")
	},
}

func init() {
	rootCmd.AddCommand(uninstallCmd)
}
