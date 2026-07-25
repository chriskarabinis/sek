package cmd

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/spf13/cobra"
)

const repoAPI = "https://api.github.com/repos/chriskarabinis/sek/releases/latest"
const repoDownload = "https://github.com/chriskarabinis/sek/releases/download"

// checksumsName is the file published alongside the binaries by the release
// workflow, in `sha256sum` format.
const checksumsName = "checksums.txt"

type githubRelease struct {
	TagName string `json:"tag_name"`
}

func httpClient() *http.Client {
	return &http.Client{Timeout: 60 * time.Second}
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
	resp, err := httpClient().Get(repoAPI)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("GitHub API returned HTTP %d", resp.StatusCode)
	}

	var release githubRelease
	if err := json.NewDecoder(resp.Body).Decode(&release); err != nil {
		return "", err
	}
	if release.TagName == "" {
		return "", fmt.Errorf("no releases found")
	}
	return strings.TrimPrefix(release.TagName, "v"), nil
}

// fetchExpectedChecksum returns the published SHA-256 for one release asset.
// Format is `sha256sum` output: "<hex>  <filename>" per line.
func fetchExpectedChecksum(version, assetName string) (string, error) {
	url := fmt.Sprintf("%s/v%s/%s", repoDownload, version, checksumsName)
	resp, err := httpClient().Get(url)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("no %s published for v%s (HTTP %d)", checksumsName, version, resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if err != nil {
		return "", err
	}

	for _, line := range strings.Split(string(body), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 2 && strings.TrimPrefix(fields[1], "*") == assetName {
			return strings.ToLower(fields[0]), nil
		}
	}
	return "", fmt.Errorf("%s has no entry for %s", checksumsName, assetName)
}

// downloadVerified writes the asset to a temp file next to dstDir and returns
// its path. The file is kept only if its SHA-256 matches wantSum. Staging in
// the destination directory keeps the later rename on one filesystem, so the
// swap is atomic.
func downloadVerified(url, dstDir, wantSum string) (string, error) {
	resp, err := httpClient().Get(url)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("download failed: HTTP %d", resp.StatusCode)
	}

	tmp, err := os.CreateTemp(dstDir, ".sek-update-*")
	if err != nil {
		return "", fmt.Errorf("cannot stage update in %s: %w", dstDir, err)
	}
	tmpName := tmp.Name()

	sum := sha256.New()
	if _, err := io.Copy(io.MultiWriter(tmp, sum), resp.Body); err != nil {
		tmp.Close()
		os.Remove(tmpName)
		return "", err
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmpName)
		return "", err
	}

	if got := hex.EncodeToString(sum.Sum(nil)); got != wantSum {
		os.Remove(tmpName)
		return "", fmt.Errorf("checksum mismatch\n    expected %s\n    got      %s", wantSum, got)
	}

	if err := os.Chmod(tmpName, 0o755); err != nil {
		os.Remove(tmpName)
		return "", err
	}
	return tmpName, nil
}

// currentBinaryPath resolves the running executable, following symlinks so the
// update replaces the real file rather than the link pointing at it.
func currentBinaryPath() (string, error) {
	execPath, err := os.Executable()
	if err != nil {
		return "", err
	}
	if resolved, err := filepath.EvalSymlinks(execPath); err == nil {
		return resolved, nil
	}
	return execPath, nil
}

var updateCmd = &cobra.Command{
	Use:   "update",
	Short: "Update sek to the latest version",
	Long:  `Check for a newer version and replace the current binary if one is available.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		w, err := newWriter()
		if err != nil {
			return err
		}
		defer w.Close()

		w.Highlightf("[*] Current version: v%s", version)
		w.Section("Checking for updates...")

		latest, err := fetchLatestVersion()
		if err != nil {
			return fmt.Errorf("could not check for updates: %w", err)
		}

		if !isNewer(version, latest) {
			w.Highlightf("[*] Already up to date (v%s)", version)
			return nil
		}

		w.Highlightf("[*] New version available: v%s — downloading...", latest)

		execPath, err := currentBinaryPath()
		if err != nil {
			return fmt.Errorf("could not locate current binary: %w", err)
		}

		assetName := fmt.Sprintf("sek_%s_%s", runtime.GOOS, runtime.GOARCH)

		wantSum, err := fetchExpectedChecksum(latest, assetName)
		if err != nil {
			return fmt.Errorf("cannot verify download: %w", err)
		}

		url := fmt.Sprintf("%s/v%s/%s", repoDownload, latest, assetName)
		tmpName, err := downloadVerified(url, filepath.Dir(execPath), wantSum)
		if err != nil {
			if os.IsPermission(err) {
				return fmt.Errorf("permission denied — try: sudo sek update")
			}
			return err
		}

		w.Section("Checksum verified.")

		// Replace in one step. Writing over the running binary in place would
		// leave it truncated and unrunnable if the copy died halfway through.
		if err := os.Rename(tmpName, execPath); err != nil {
			os.Remove(tmpName)
			if os.IsPermission(err) {
				return fmt.Errorf("permission denied — try: sudo sek update")
			}
			return fmt.Errorf("could not replace %s: %w", execPath, err)
		}

		w.Highlightf("[*] Updated to v%s", latest)
		return nil
	},
}

func init() {
	rootCmd.AddCommand(updateCmd)
}
