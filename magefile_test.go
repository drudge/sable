//go:build mage

package main

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestParseReleaseVersion(t *testing.T) {
	t.Parallel()
	for input, expected := range map[string]string{
		"1.2.3":       "1.2.3",
		"v1.2.3":      "1.2.3",
		"1.2.3-rc.2":  "1.2.3-rc.2",
		"v2.0.0-beta": "2.0.0-beta",
	} {
		actual, err := parseReleaseVersion(input)
		if err != nil {
			t.Errorf("parseReleaseVersion(%q) error = %v", input, err)
			continue
		}
		if actual != expected {
			t.Errorf("parseReleaseVersion(%q) = %q, want %q", input, actual, expected)
		}
	}
}

func TestParseReleaseVersionRejectsNonCanonicalOrContainerUnsafeVersions(t *testing.T) {
	t.Parallel()
	for _, input := range []string{
		"", "dev", "1.2", "01.2.3", "1.2.3+build", "v1.2.3+build",
		" v1.2.3", "v1.2.3 ", "1.2.3-" + strings.Repeat("a", 129),
	} {
		if _, err := parseReleaseVersion(input); err == nil {
			t.Errorf("parseReleaseVersion(%q) accepted an invalid release", input)
		}
	}
}

func TestPublishRequiresGitHubActions(t *testing.T) {
	t.Setenv(githubActionsEnvironment, "")
	err := Publish(context.Background())
	if err == nil || !strings.Contains(err.Error(), "GitHub Actions release workflow") {
		t.Fatalf("Publish() error = %v, want the GitHub Actions guard", err)
	}
}

func TestReleaseConfigurationUsesReplaceableDrafts(t *testing.T) {
	t.Parallel()
	for _, expected := range []string{"draft: true", "replace_existing_draft: true", "prerelease: auto"} {
		if !strings.Contains(goReleaserConfig, expected) {
			t.Errorf("GoReleaser configuration does not contain %q", expected)
		}
	}
}

func TestCurrentReleaseTagRequiresAnAnnotatedSemanticTagAtHead(t *testing.T) {
	directory := t.TempDir()
	runMageGit(t, directory, "init")
	runMageGit(t, directory, "config", "user.name", "Sable Test")
	runMageGit(t, directory, "config", "user.email", "sable@example.test")
	if err := os.WriteFile(filepath.Join(directory, "README.md"), []byte("release test\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	runMageGit(t, directory, "add", "README.md")
	runMageGit(t, directory, "commit", "-m", "initial")

	workingDirectory, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(directory); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(workingDirectory) })

	if err := requireCurrentReleaseTag(context.Background(), "v1.2.3"); err == nil {
		t.Fatal("requireCurrentReleaseTag accepted a missing release tag")
	}
	runMageGit(t, directory, "tag", "v1.2.3")
	if err := requireCurrentReleaseTag(context.Background(), "v1.2.3"); err == nil || !strings.Contains(err.Error(), "must be annotated") {
		t.Fatalf("requireCurrentReleaseTag lightweight-tag error = %v", err)
	}
	runMageGit(t, directory, "tag", "--delete", "v1.2.3")
	runMageGit(t, directory, "tag", "--annotate", "v1.2.3", "--message", "Sable v1.2.3")
	if err := requireCurrentReleaseTag(context.Background(), "v1.2.3"); err != nil {
		t.Fatalf("requireCurrentReleaseTag() error = %v", err)
	}
	if err := os.WriteFile(filepath.Join(directory, "README.md"), []byte("new commit\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	runMageGit(t, directory, "commit", "--all", "-m", "advance")
	if err := requireCurrentReleaseTag(context.Background(), "v1.2.3"); err == nil || !strings.Contains(err.Error(), "not current commit") {
		t.Fatalf("requireCurrentReleaseTag stale-tag error = %v", err)
	}
}

func runMageGit(t *testing.T, directory string, arguments ...string) {
	t.Helper()
	command := exec.Command("git", arguments...)
	command.Dir = directory
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("git %s: %v: %s", strings.Join(arguments, " "), err, output)
	}
}

func TestReleaseNotesRequireAnExactNonemptyCuratedSection(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "CHANGELOG.md")
	contents := "# Changelog\n\n## [1.2.0] - Unreleased\n\n- A useful improvement.\n\n## [1.2.0-rc.1]\n\n- Candidate notes.\n\n## [1.3.0]\n\n## [1.4.0]\n\n- Later notes.\n"
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, release := range []string{"1.2.0", "v1.2.0", "1.2.0-rc.1", "1.3.0", "1.2", "2.0.0"} {
		output, err := exec.Command("bash", "scripts/release-notes.sh", release, path).Output()
		valid := release == "1.2.0" || release == "v1.2.0" || release == "1.2.0-rc.1"
		if (err == nil) != valid {
			t.Errorf("%s notes = %q, %v", release, output, err)
		}
		if valid && (strings.Contains(string(output), "Later notes") || strings.Contains(string(output), "## [")) {
			t.Errorf("notes included another release: %s", output)
		}
	}
	if !strings.Contains(goReleaserConfig, "changelog:\n  disable: true") {
		t.Fatal("release builds still generate commit lists")
	}
}

// A script's policy hash matches the one the Content Security Policy spec
// gives for its own example, which is what a browser checks the script
// against.
func TestScriptHashMatchesTheSpecExample(t *testing.T) {
	if got := scriptHash([]byte("alert('Hello, world.');")); got != "sha256-qznLcsROx4GACP2dm0UCKCzCG+HiZ1guq6ZZDob/Tng=" {
		t.Fatalf("scriptHash = %s", got)
	}
}

// The hash dev and devDemo hand the console is of the script the pinned Air
// really injects: its runner/proxy.js, embedded unchanged and wrapped in a bare
// script tag. A newer Air that injects it differently fails here rather than
// quietly stopping the page from reloading.
func TestAirReloadScriptHashFollowsThePinnedAir(t *testing.T) {
	ctx := context.Background()
	hash, err := airReloadScriptHash(ctx)
	if err != nil {
		t.Skipf("Air %s is not available here: %v", airVersion, err)
	}
	output, err := exec.CommandContext(ctx, "go", "mod", "download", "-json", "github.com/air-verse/air@"+airVersion).Output()
	if err != nil {
		t.Fatal(err)
	}
	var module struct{ Dir string }
	if err := json.Unmarshal(output, &module); err != nil {
		t.Fatal(err)
	}
	proxy, err := os.ReadFile(filepath.Join(module.Dir, "runner", "proxy.go"))
	if err != nil {
		t.Fatal(err)
	}
	for _, expected := range []string{"//go:embed proxy.js", `"<script>" + ProxyScript + "</script>"`} {
		if !strings.Contains(string(proxy), expected) {
			t.Fatalf("Air %s no longer injects its reload script the same way: runner/proxy.go lacks %s", airVersion, expected)
		}
	}
	script, err := os.ReadFile(filepath.Join(module.Dir, "runner", "proxy.js"))
	if err != nil {
		t.Fatal(err)
	}
	if hash != scriptHash(script) {
		t.Fatalf("hash = %s, want %s", hash, scriptHash(script))
	}
}
