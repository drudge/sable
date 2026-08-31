package main

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
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
	} {
		got, err := containerWebUpdatesEnabled(test.value)
		if err != nil {
			t.Fatalf("containerWebUpdatesEnabled(%q): %v", test.value, err)
		}
		if got != test.want {
			t.Fatalf("containerWebUpdatesEnabled(%q) = %t, want %t", test.value, got, test.want)
		}
	}
	if _, err := containerWebUpdatesEnabled("sometimes"); err == nil {
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
		{image: "dev", mutable: "1.2.0", want: true},
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
