package update

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"runtime"
	"sort"
	"strings"

	"github.com/drudge/sable/internal/version"
	"golang.org/x/mod/semver"
)

const releasePageSize = 30

type releaseAsset struct {
	Name        string `json:"name"`
	DownloadURL string `json:"browser_download_url"`
	Size        int64  `json:"size"`
}

type release struct {
	TagName    string         `json:"tag_name"`
	Draft      bool           `json:"draft"`
	PreRelease bool           `json:"prerelease"`
	HTMLURL    string         `json:"html_url"`
	Assets     []releaseAsset `json:"assets"`
}

func resolveRelease(ctx context.Context, options Options) (release, error) {
	if requested := strings.TrimSpace(options.Version); requested != "" {
		return fetchRelease(ctx, options, "/releases/tags/"+normalizeTag(requested))
	}
	if !options.PreRelease {
		selected, err := fetchRelease(ctx, options, "/releases/latest")
		if errors.Is(err, errReleaseNotFound) {
			return release{}, errors.New("no published release was found; include pre-release builds to see the newest one")
		}
		return selected, err
	}
	candidates, err := fetchReleases(ctx, options)
	if err != nil {
		return release{}, err
	}
	return newestRelease(candidates)
}

var errReleaseNotFound = errors.New("release not found")

func fetchRelease(ctx context.Context, options Options, path string) (release, error) {
	body, err := requestAPI(ctx, options, path)
	if err != nil {
		return release{}, err
	}
	var selected release
	if err := json.Unmarshal(body, &selected); err != nil {
		return release{}, fmt.Errorf("decode release metadata: %w", err)
	}
	if strings.TrimSpace(selected.TagName) == "" {
		return release{}, errors.New("release metadata does not contain a tag")
	}
	return selected, nil
}

func fetchReleases(ctx context.Context, options Options) ([]release, error) {
	body, err := requestAPI(ctx, options, fmt.Sprintf("/releases?per_page=%d", releasePageSize))
	if err != nil {
		return nil, err
	}
	var releases []release
	if err := json.Unmarshal(body, &releases); err != nil {
		return nil, fmt.Errorf("decode release metadata: %w", err)
	}
	return releases, nil
}

func requestAPI(ctx context.Context, options Options, path string) ([]byte, error) {
	endpoint := fmt.Sprintf("%s/repos/%s%s", strings.TrimSuffix(options.APIBaseURL, "/"), options.Repository, path)
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("build release request: %w", err)
	}
	request.Header.Set("Accept", "application/vnd.github+json")
	request.Header.Set("User-Agent", "sable/"+version.Current().Release)
	if token := githubToken(); token != "" {
		request.Header.Set("Authorization", "Bearer "+token)
	}
	response, err := options.Client.Do(request)
	if err != nil {
		return nil, fmt.Errorf("contact %s: %w", endpoint, err)
	}
	defer response.Body.Close()
	switch {
	case response.StatusCode == http.StatusNotFound:
		return nil, errReleaseNotFound
	case response.StatusCode == http.StatusForbidden || response.StatusCode == http.StatusTooManyRequests:
		return nil, errors.New("GitHub rejected the release request; the API rate limit is likely exhausted, retry later or set SABLE_GITHUB_TOKEN")
	case response.StatusCode != http.StatusOK:
		return nil, fmt.Errorf("release request failed: %s", response.Status)
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, maximumMetadataBytes))
	if err != nil {
		return nil, fmt.Errorf("read release metadata: %w", err)
	}
	return body, nil
}

func githubToken() string {
	for _, name := range []string{"SABLE_GITHUB_TOKEN", "GITHUB_TOKEN"} {
		if token := strings.TrimSpace(os.Getenv(name)); token != "" {
			return token
		}
	}
	return ""
}

func newestRelease(candidates []release) (release, error) {
	usable := make([]release, 0, len(candidates))
	for _, candidate := range candidates {
		if !candidate.Draft && comparableVersion(candidate.TagName) != "" {
			usable = append(usable, candidate)
		}
	}
	if len(usable) == 0 {
		return release{}, errors.New("no published release was found")
	}
	sort.SliceStable(usable, func(first, second int) bool {
		return semver.Compare(comparableVersion(usable[first].TagName), comparableVersion(usable[second].TagName)) > 0
	})
	return usable[0], nil
}

func selectAsset(selected release, releaseVersion string) (releaseAsset, error) {
	preferred := assetName(releaseVersion, runtime.GOOS, runtime.GOARCH)
	if asset, found := findAsset(selected, preferred); found {
		return asset, nil
	}
	suffix := fmt.Sprintf("_%s_%s%s", runtime.GOOS, runtime.GOARCH, archiveExtension(runtime.GOOS))
	for _, asset := range selected.Assets {
		if strings.HasSuffix(asset.Name, suffix) {
			return asset, nil
		}
	}
	return releaseAsset{}, fmt.Errorf("release %s does not publish a build for %s/%s", selected.TagName, runtime.GOOS, runtime.GOARCH)
}

func findAsset(selected release, name string) (releaseAsset, bool) {
	for _, asset := range selected.Assets {
		if asset.Name == name {
			return asset, true
		}
	}
	return releaseAsset{}, false
}

func assetName(releaseVersion, operatingSystem, architecture string) string {
	return fmt.Sprintf("sable_%s_%s_%s%s", releaseVersion, operatingSystem, architecture, archiveExtension(operatingSystem))
}

func archiveExtension(operatingSystem string) string {
	if operatingSystem == "windows" {
		return ".zip"
	}
	return ".tar.gz"
}

func normalizeTag(tag string) string {
	tag = strings.TrimSpace(tag)
	if tag == "" || strings.HasPrefix(tag, "v") {
		return tag
	}
	return "v" + tag
}

// comparableVersion returns a semver-comparable form of a release tag, or an
// empty string when the tag is not a version Sable can reason about.
func comparableVersion(tag string) string {
	candidate := normalizeTag(tag)
	if !semver.IsValid(candidate) {
		return ""
	}
	return candidate
}

// isNewer reports whether the candidate release supersedes the running build.
// An unrecognizable running version is always treated as outdated so that
// development builds still pick up published releases.
func isNewer(candidate, current string) bool {
	comparableCandidate := comparableVersion(candidate)
	if comparableCandidate == "" {
		return false
	}
	comparableCurrent := comparableVersion(current)
	if comparableCurrent == "" {
		return true
	}
	return semver.Compare(comparableCandidate, comparableCurrent) > 0
}
