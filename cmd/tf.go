package cmd

import (
	"github.com/spf13/cobra"

	"github.com/chriskarabinis/sek/internal/output"
	"github.com/chriskarabinis/sek/internal/webx"
)

var (
	tfTarget string
	tfHTTP   bool
	tfPort   string
)

var tfCmd = &cobra.Command{
	Use:   "tf",
	Short: "Technology fingerprinting",
	Long:  `Detect technologies used by a website — web server, CMS, frameworks, analytics, and more.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		w, err := newWriter()
		if err != nil {
			return err
		}
		defer w.Close()

		ctx, stop := commandContext()
		defer stop()

		res, err := webx.Fingerprint(ctx, tfTarget, webx.Options{UseHTTP: tfHTTP, Port: tfPort})
		if err != nil {
			return err
		}

		if w.IsJSON() {
			return w.JSON(res)
		}
		renderTech(w, res)
		return nil
	},
}

func renderTech(w *output.Writer, res *webx.TechResult) {
	w.Header("Technology Fingerprint for: %s", res.Target)

	if len(res.Technologies) == 0 {
		w.Note("No technologies detected.")
		w.Blank()
		return
	}

	byCategory := res.ByCategory()
	for _, category := range webx.Categories {
		techs, ok := byCategory[category]
		if !ok {
			continue
		}
		w.Highlightf("[*] %s", category)
		for _, t := range techs {
			if t.Version != "" {
				w.Highlightf("  %s %s", t.Name, t.Version)
			} else {
				w.Highlightf("  %s", t.Name)
			}
		}
		w.Blank()
	}
}

func init() {
	tfCmd.Flags().StringVarP(&tfTarget, "domain", "d", "", "Target domain (e.g. example.com)")
	tfCmd.Flags().BoolVar(&tfHTTP, "http", false, "Use HTTP instead of HTTPS")
	tfCmd.Flags().StringVarP(&tfPort, "port", "p", "", "Custom port")
	tfCmd.MarkFlagRequired("domain")
	rootCmd.AddCommand(tfCmd)
}
