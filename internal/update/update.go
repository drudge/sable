// Package update replaces an installed Sable executable with a published
// GitHub release build for the running platform.
package update

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/drudge/sable/internal/version"
)

const (
	defaultRepository    = "drudge/sable"
	defaultAPIBaseURL    = "https://api.github.com"
	checksumsAssetName   = "checksums.txt"
	maximumMetadataBytes = 8 << 20
	maximumArchiveBytes  = 512 << 20
	downloadTimeout      = 10 * time.Minute
)

var errMissingExecutable = errors.New("release archive does not contain the Sable executable")

type Options struct {
	// Repository is the GitHub owner/name pair that publishes Sable releases.
	Repository string
	// APIBaseURL is the GitHub API root. Tests override it.
	APIBaseURL string
	// Version pins a specific release tag instead of the newest one.
	Version string
	// PreRelease allows pre-release builds to be selected.
	PreRelease bool
	// CheckOnly reports the available release without installing it.
	CheckOnly bool
	// Restart restarts the systemd service after a successful replacement.
	Restart bool
	// BinaryPath overrides the executable that is replaced.
	BinaryPath string
	Client     *http.Client
	Output     io.Writer
}

type Result struct {
	CurrentVersion string
	LatestVersion  string
	Tag            string
	ReleaseURL     string
	AssetName      string
	BinaryPath     string
	PreRelease     bool
	UpToDate       bool
	Applied        bool
	Restarted      bool
	ServiceManaged bool
}

func (options Options) withDefaults() Options {
	if strings.TrimSpace(options.Repository) == "" {
		options.Repository = defaultRepository
	}
	if strings.TrimSpace(options.APIBaseURL) == "" {
		options.APIBaseURL = defaultAPIBaseURL
	}
	if options.Client == nil {
		options.Client = &http.Client{Timeout: downloadTimeout}
	}
	if options.Output == nil {
		options.Output = io.Discard
	}
	return options
}

// Apply downloads the selected release for the running platform, verifies it
// against the published checksums, and replaces the installed executable.
func Apply(ctx context.Context, options Options) (Result, error) {
	options = options.withDefaults()
	current := version.Current().Release
	selected, err := resolveRelease(ctx, options)
	if err != nil {
		return Result{}, err
	}
	releaseVersion := strings.TrimPrefix(selected.TagName, "v")
	result := Result{
		CurrentVersion: current,
		LatestVersion:  releaseVersion,
		Tag:            selected.TagName,
		ReleaseURL:     selected.HTMLURL,
		PreRelease:     selected.PreRelease,
	}
	if strings.TrimSpace(options.Version) == "" && !isNewer(releaseVersion, current) {
		result.UpToDate = true
		return result, nil
	}
	if options.CheckOnly {
		return result, nil
	}
	binaryPath, err := targetBinaryPath(options.BinaryPath)
	if err != nil {
		return result, err
	}
	result.BinaryPath = binaryPath
	asset, err := selectAsset(selected, releaseVersion)
	if err != nil {
		return result, err
	}
	result.AssetName = asset.Name
	checksums, found := findAsset(selected, checksumsAssetName)
	if !found {
		return result, fmt.Errorf("release %s does not publish %s", selected.TagName, checksumsAssetName)
	}
	fmt.Fprintf(options.Output, "Downloading %s...\n", asset.Name)
	archive, err := download(ctx, options, asset.DownloadURL)
	if err != nil {
		return result, err
	}
	publishedChecksums, err := download(ctx, options, checksums.DownloadURL)
	if err != nil {
		return result, err
	}
	expected, err := expectedChecksum(publishedChecksums, asset.Name)
	if err != nil {
		return result, err
	}
	if err := verifyChecksum(archive, expected); err != nil {
		return result, fmt.Errorf("%s: %w", asset.Name, err)
	}
	executable, err := extractExecutable(asset.Name, archive)
	if err != nil {
		return result, err
	}
	if err := replaceExecutable(ctx, binaryPath, executable); err != nil {
		return result, err
	}
	result.Applied = true
	if !options.Restart {
		return result, nil
	}
	restarted, managed, err := restartService(ctx, options.Output)
	if err != nil {
		return result, err
	}
	result.Restarted = restarted
	result.ServiceManaged = managed
	return result, nil
}

func download(ctx context.Context, options Options, downloadURL string) ([]byte, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, downloadURL, nil)
	if err != nil {
		return nil, fmt.Errorf("build download request: %w", err)
	}
	request.Header.Set("Accept", "application/octet-stream")
	request.Header.Set("User-Agent", "sable/"+version.Current().Release)
	response, err := options.Client.Do(request)
	if err != nil {
		return nil, fmt.Errorf("download %s: %w", downloadURL, err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("download %s: %s", downloadURL, response.Status)
	}
	contents, err := io.ReadAll(io.LimitReader(response.Body, maximumArchiveBytes))
	if err != nil {
		return nil, fmt.Errorf("download %s: %w", downloadURL, err)
	}
	return contents, nil
}

// targetBinaryPath resolves the executable that the update replaces.
func targetBinaryPath(override string) (string, error) {
	if trimmed := strings.TrimSpace(override); trimmed != "" {
		return trimmed, nil
	}
	executable, err := os.Executable()
	if err != nil {
		return "", fmt.Errorf("locate running Sable executable: %w", err)
	}
	if resolved, err := filepath.EvalSymlinks(executable); err == nil {
		executable = resolved
	}
	if isTemporaryBuild(executable) {
		return "", fmt.Errorf("the running executable %s is a temporary build; run update from an installed Sable executable", executable)
	}
	return executable, nil
}

func isTemporaryBuild(executable string) bool {
	temporaryRoot := os.TempDir()
	if resolved, err := filepath.EvalSymlinks(temporaryRoot); err == nil {
		temporaryRoot = resolved
	}
	return strings.HasPrefix(executable, strings.TrimSuffix(temporaryRoot, string(os.PathSeparator))+string(os.PathSeparator))
}

// replaceExecutable installs the downloaded build in place, keeping the old
// executable until the replacement is known to run.
func replaceExecutable(ctx context.Context, path string, contents []byte) error {
	directory := filepath.Dir(path)
	mode := os.FileMode(0o755)
	if info, err := os.Stat(path); err == nil {
		mode = info.Mode().Perm()
	}
	temporary, err := os.CreateTemp(directory, ".sable-update-*"+filepath.Ext(path))
	if err != nil {
		if errors.Is(err, os.ErrPermission) {
			return fmt.Errorf("cannot write to %s; run sable update as root: %w", directory, err)
		}
		return fmt.Errorf("stage the downloaded Sable executable: %w", err)
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if _, err := temporary.Write(contents); err != nil {
		temporary.Close()
		return fmt.Errorf("write the downloaded Sable executable: %w", err)
	}
	if err := temporary.Chmod(mode); err != nil {
		temporary.Close()
		return fmt.Errorf("set Sable executable permissions: %w", err)
	}
	if err := temporary.Sync(); err != nil {
		temporary.Close()
		return fmt.Errorf("sync the downloaded Sable executable: %w", err)
	}
	if err := temporary.Close(); err != nil {
		return fmt.Errorf("close the downloaded Sable executable: %w", err)
	}
	if err := exec.CommandContext(ctx, temporaryPath, "version").Run(); err != nil {
		return fmt.Errorf("the downloaded Sable executable did not run: %w", err)
	}
	previousPath := temporaryPath + ".previous"
	renamedPrevious := true
	if err := os.Rename(path, previousPath); err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("move the current Sable executable aside: %w", err)
		}
		renamedPrevious = false
	}
	if err := os.Rename(temporaryPath, path); err != nil {
		if renamedPrevious {
			os.Rename(previousPath, path)
		}
		return fmt.Errorf("replace %s: %w", path, err)
	}
	if renamedPrevious {
		os.Remove(previousPath)
	}
	return nil
}
