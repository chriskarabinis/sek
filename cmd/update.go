package cmd

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"runtime"

	"github.com/spf13/cobra"
)

const repoAPI = "https://api.github.com/repos/chriskarabinis/sek/releases/latest"
const repoDownload = "https://github.com/chriskarabinis/sek/releases/download"

type githubRelease struct {
	TagName string `json:"tag_name"`
}

// isNewer returns true if b is strictly newer than a (semver: "0.1.2" > "0.1.1")
func isNewer(current, latest string) bool {
	parse := func(v string) [3]int {
		var major, minor, patch int
		fmt.Sscanf(v, "%d.%d.%d", &major, &minor, &patch)
		return [3]int{major, minor, patch}
	}
	a := parse(current)
	b := parse(latest)
	for i := range a {
		if b[i] > a[i] {
			return true
		}
		if b[i] < a[i] {
			return false
		}
	}
	return false
}

func fetchLatestVersion() (string, error) {
	resp, err := http.Get(repoAPI)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	var release githubRelease
	if err := json.NewDecoder(resp.Body).Decode(&release); err != nil {
		return "", err
	}
	if release.TagName == "" {
		return "", fmt.Errorf("no releases found")
	}
	// Strip leading "v"
	v := release.TagName
	if len(v) > 0 && v[0] == 'v' {
		v = v[1:]
	}
	return v, nil
}

var updateCmd = &cobra.Command{
	Use:   "update",
	Short: "Update sek to the latest version",
	Long:  `Check for a newer version and replace the current binary if one is available.`,
	Run: func(cmd *cobra.Command, args []string) {
		plain := fmt.Sprintf("[*] Current version: v%s", version)
		WriteLineColored(yellow+plain+reset, plain)

		WriteLine("[*] Checking for updates...")

		latest, err := fetchLatestVersion()
		if err != nil {
			WriteLine(fmt.Sprintf("[!] Could not check for updates: %s", err))
			os.Exit(1)
		}

		if !isNewer(version, latest) {
			plain := fmt.Sprintf("[*] Already up to date (v%s)", version)
			WriteLineColored(yellow+plain+reset, plain)
			return
		}

		plain = fmt.Sprintf("[*] New version available: v%s — downloading...", latest)
		WriteLineColored(yellow+plain+reset, plain)

		// Build download URL for the current platform
		goos := runtime.GOOS
		goarch := runtime.GOARCH
		binaryName := fmt.Sprintf("sek_%s_%s", goos, goarch)
		url := fmt.Sprintf("%s/v%s/%s", repoDownload, latest, binaryName)

		// Download binary
		dlResp, err := http.Get(url)
		if err != nil {
			WriteLine(fmt.Sprintf("[!] Download failed: %s", err))
			os.Exit(1)
		}
		defer dlResp.Body.Close()

		if dlResp.StatusCode != 200 {
			WriteLine(fmt.Sprintf("[!] Download failed: HTTP %d", dlResp.StatusCode))
			os.Exit(1)
		}

		// Write to temp file
		tmp, err := os.CreateTemp("", "sek-update-*")
		if err != nil {
			WriteLine(fmt.Sprintf("[!] %s", err))
			os.Exit(1)
		}
		tmpName := tmp.Name()
		defer os.Remove(tmpName)

		if _, err := io.Copy(tmp, dlResp.Body); err != nil {
			tmp.Close()
			WriteLine(fmt.Sprintf("[!] %s", err))
			os.Exit(1)
		}
		tmp.Close()

		if err := os.Chmod(tmpName, 0755); err != nil {
			WriteLine(fmt.Sprintf("[!] %s", err))
			os.Exit(1)
		}

		// Find current binary path
		execPath, err := os.Executable()
		if err != nil {
			WriteLine(fmt.Sprintf("[!] Could not locate current binary: %s", err))
			os.Exit(1)
		}

		// Replace current binary (read + write to handle cross-device moves)
		src, err := os.Open(tmpName)
		if err != nil {
			WriteLine(fmt.Sprintf("[!] %s", err))
			os.Exit(1)
		}
		defer src.Close()

		dst, err := os.OpenFile(execPath, os.O_WRONLY|os.O_TRUNC, 0755)
		if err != nil {
			WriteLine(fmt.Sprintf("[!] Permission denied — try: sudo sek update"))
			os.Exit(1)
		}
		defer dst.Close()

		if _, err := io.Copy(dst, src); err != nil {
			WriteLine(fmt.Sprintf("[!] %s", err))
			os.Exit(1)
		}

		plain = fmt.Sprintf("[*] Updated to v%s", latest)
		WriteLineColored(yellow+plain+reset, plain)
	},
}

func init() {
	rootCmd.AddCommand(updateCmd)
}
