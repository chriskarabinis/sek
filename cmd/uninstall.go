package cmd

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"
)

var uninstallYes bool

var uninstallCmd = &cobra.Command{
	Use:   "uninstall",
	Short: "Remove sek from your system",
	Long:  `Delete the sek binary from disk.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		w, err := newWriter()
		if err != nil {
			return err
		}
		defer w.Close()

		execPath, err := currentBinaryPath()
		if err != nil {
			return fmt.Errorf("could not locate binary: %w", err)
		}

		// This deletes whatever binary is running, which is not always the
		// installed one — a ./sek built in a working copy is a real
		// possibility. Show the path and confirm before removing it.
		w.Highlightf("[*] This will delete: %s", execPath)

		if !uninstallYes {
			fmt.Print("[?] Continue? [y/N]: ")
			answer, _ := bufio.NewReader(os.Stdin).ReadString('\n')
			if !strings.EqualFold(strings.TrimSpace(answer), "y") {
				w.Section("Aborted.")
				return nil
			}
		}

		if err := os.Remove(execPath); err != nil {
			if os.IsPermission(err) {
				return fmt.Errorf("permission denied — try: sudo sek uninstall")
			}
			return err
		}

		w.Section("sek has been removed.")
		return nil
	},
}

func init() {
	uninstallCmd.Flags().BoolVarP(&uninstallYes, "yes", "y", false, "Skip the confirmation prompt")
	rootCmd.AddCommand(uninstallCmd)
}
