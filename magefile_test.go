//go:build mage

package main

import (
	"context"
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
