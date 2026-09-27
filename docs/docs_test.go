package docs

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"testing"
)

// The docs name the release they describe in a few places, and the pull request
// that adds a stable section to CHANGELOG.md has to move every one of them.
// Screenshot captions ("captured from Sable X") trail on purpose: they change
// when the screenshots are retaken after the release, and sabledns.io checks
// them then.
func TestDocsNameTheLatestStableRelease(t *testing.T) {
	var navigation struct {
		Version      string `json:"version"`
		VersionLabel string `json:"versionLabel"`
		Groups       []struct {
			Pages []struct {
				File string `json:"file"`
			} `json:"pages"`
		} `json:"groups"`
	}
	manifest, err := os.ReadFile("navigation.json")
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(manifest, &navigation); err != nil {
		t.Fatalf("navigation.json: %v", err)
	}
	changelog, err := os.ReadFile(filepath.Join("..", "CHANGELOG.md"))
	if err != nil {
		t.Fatal(err)
	}
	latest := regexp.MustCompile(`(?m)^## \[(\d+\.\d+\.\d+)\]`).FindSubmatch(changelog)
	if latest == nil {
		t.Fatal("CHANGELOG.md has no stable release section")
	}
	release := string(latest[1])
	if navigation.Version != release || navigation.VersionLabel != release {
		t.Errorf("navigation.json names %s (label %s), but the newest stable release in CHANGELOG.md is %s; update version and versionLabel", navigation.Version, navigation.VersionLabel, release)
	}

	const version = `(\d+\.\d+\.\d+(?:-[0-9A-Za-z.]+)?)`
	claims := regexp.MustCompile(`\bcovers? Sable ` + version)
	links := regexp.MustCompile(`releases/tag/v` + version)
	for _, group := range navigation.Groups {
		for _, page := range group.Pages {
			// The changelog is history, so it names every release.
			if page.File == "CHANGELOG.md" {
				continue
			}
			text, err := os.ReadFile(filepath.Join("..", page.File))
			if err != nil {
				t.Fatal(err)
			}
			patterns := []*regexp.Regexp{claims}
			if page.File == "docs/index.md" {
				patterns = append(patterns, links)
			}
			for _, pattern := range patterns {
				for _, match := range pattern.FindAllStringSubmatch(string(text), -1) {
					if match[1] != release {
						t.Errorf("%s: %q should name %s", page.File, match[0], release)
					}
				}
			}
		}
	}
}
