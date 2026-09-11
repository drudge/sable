package main

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/drudge/sable/internal/update"
)

func TestContainerWebUpdatesAreExplicitlyEnabled(t *testing.T) {
	for _, test := range []struct {
		value string
		want  bool
	}{
		{value: "", want: false},
		{value: "false", want: false},
		{value: "true", want: true},
		{value: "1", want: true},
		{value: " TRUE ", want: true},
	} {
		t.Setenv(update.ContainerWebUpdatesEnvironment, test.value)
		got, err := update.ContainerWebUpdatesEnabled()
		if err != nil {
			t.Fatalf("ContainerWebUpdatesEnabled(%q): %v", test.value, err)
		}
		if got != test.want {
			t.Fatalf("ContainerWebUpdatesEnabled(%q) = %t, want %t", test.value, got, test.want)
		}
	}
	t.Setenv(update.ContainerWebUpdatesEnvironment, "sometimes")
	if _, err := update.ContainerWebUpdatesEnabled(); err == nil {
		t.Fatal("an invalid web-update switch was accepted")
	}
}

func TestContainerPrefersOnlyANewerPersistentRelease(t *testing.T) {
	for _, test := range []struct {
		image, mutable string
		want           bool
	}{
		{image: "1.2.0", mutable: "1.3.0", want: true},
		{image: "1.2.0", mutable: "1.3.0-rc.1", want: true},
		{image: "1.2.0", mutable: "1.2.0", want: false},
		{image: "1.2.0", mutable: "1.1.9", want: false},
		{image: "dev", mutable: "1.2.0", want: false},
		{image: "1.2.0-snapshot", mutable: "1.3.0", want: false},
		{image: "1.2.0-rc.1", mutable: "1.2.0", want: true},
		{image: "1.2.0", mutable: "broken", want: false},
	} {
		if got := preferMutableRelease(test.image, test.mutable); got != test.want {
			t.Fatalf("preferMutableRelease(%q, %q) = %t, want %t", test.image, test.mutable, got, test.want)
		}
	}
}

func TestExecutableReleaseReadsTheMachineVersion(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the fixture is a shell script")
	}
	path := filepath.Join(t.TempDir(), "sable")
	if err := os.WriteFile(path, []byte("#!/bin/sh\nprintf '2.4.0-rc.2\\n'\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	release, err := executableRelease(path)
	if err != nil {
		t.Fatal(err)
	}
	if release != "2.4.0-rc.2" {
		t.Fatalf("release = %q", release)
	}
}
