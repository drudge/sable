package update

import (
	"bytes"
	"context"
	"errors"
	"os"
	"strings"
	"testing"
	"time"
)

func TestManagerCheckReportsAnAvailableReleaseWithoutInstallingIt(t *testing.T) {
	binaryPath := installedExecutable(t, "#!/bin/sh\necho old\n")
	server := releaseServer(t, "v9.9.9", false, nil)
	manager := NewManager(Options{APIBaseURL: server.URL, BinaryPath: binaryPath})
	status, err := manager.Check(context.Background(), false)
	if err != nil {
		t.Fatal(err)
	}
	if !status.Available || status.Installed || status.LatestVersion != "9.9.9" {
		t.Fatalf("status = %+v", status)
	}
	if !status.Checked() || status.Busy() || status.UpToDate() {
		t.Fatalf("status = %+v", status)
	}
	installed, err := os.ReadFile(binaryPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(installed), "echo old") {
		t.Fatalf("a check replaced the executable: %q", installed)
	}
}

func TestManagerCheckRecordsAFailedRelease(t *testing.T) {
	server := releaseServer(t, "v9.9.9-rc.1", true, nil)
	manager := NewManager(Options{APIBaseURL: server.URL})
	if _, err := manager.Check(context.Background(), false); err == nil {
		t.Fatal("a pre-release-only repository should report no stable release")
	}
	status := manager.Status()
	if status.Phase != PhaseFailed || status.Error == "" || status.Available {
		t.Fatalf("status = %+v", status)
	}
	if _, err := manager.Check(context.Background(), true); err != nil {
		t.Fatal(err)
	}
	if status := manager.Status(); status.Phase != PhaseIdle || !status.Available || status.Error != "" {
		t.Fatalf("status after including pre-releases = %+v", status)
	}
}

func TestManagerInstallReplacesTheExecutableInTheBackground(t *testing.T) {
	requireExecutableScripts(t)
	binaryPath := installedExecutable(t, "#!/bin/sh\necho old\n")
	server := releaseServer(t, "v9.9.9", false, nil)
	manager := NewManager(Options{APIBaseURL: server.URL, BinaryPath: binaryPath})
	if err := manager.Install(false); err != nil {
		t.Fatal(err)
	}
	status := awaitInstall(t, manager)
	if status.Phase != PhaseInstalled || !status.Installed || status.LatestVersion != "9.9.9" {
		t.Fatalf("status = %+v", status)
	}
	if status.BinaryPath != binaryPath {
		t.Fatalf("status binary path = %q", status.BinaryPath)
	}
	installed, err := os.ReadFile(binaryPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(installed), "echo 9.9.9") {
		t.Fatalf("installed executable = %q", installed)
	}
}

func TestManagerInstallRecordsAFailedDownload(t *testing.T) {
	requireExecutableScripts(t)
	binaryPath := installedExecutable(t, "#!/bin/sh\necho old\n")
	server := releaseServer(t, "v9.9.9", false, func(checksums []byte) []byte {
		return bytes.Replace(checksums, checksums[:8], []byte("00000000"), 1)
	})
	manager := NewManager(Options{APIBaseURL: server.URL, BinaryPath: binaryPath})
	if err := manager.Install(false); err != nil {
		t.Fatal(err)
	}
	status := awaitInstall(t, manager)
	if status.Phase != PhaseFailed || status.Installed {
		t.Fatalf("status = %+v", status)
	}
	if !strings.Contains(status.Error, "checksum verification failed") {
		t.Fatalf("status error = %q", status.Error)
	}
	installed, err := os.ReadFile(binaryPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(installed), "echo old") {
		t.Fatalf("a failed installation replaced the executable: %q", installed)
	}
}

func TestManagerRunsOneOperationAtATime(t *testing.T) {
	manager := NewManager(Options{})
	if err := manager.begin(PhaseInstalling, false); err != nil {
		t.Fatal(err)
	}
	if err := manager.Install(false); !errors.Is(err, ErrUpdateInProgress) {
		t.Fatalf("second installation error = %v", err)
	}
	if _, err := manager.Check(context.Background(), false); !errors.Is(err, ErrUpdateInProgress) {
		t.Fatalf("check during an installation error = %v", err)
	}
	manager.finish(Result{CurrentVersion: "0.7.0", LatestVersion: "0.7.0", UpToDate: true}, nil)
	if status := manager.Status(); status.Busy() || !status.UpToDate() {
		t.Fatalf("status = %+v", status)
	}
}

// awaitInstall waits for the background installation to settle.
func awaitInstall(t *testing.T, manager *Manager) Status {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		if status := manager.Status(); !status.Busy() {
			return status
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("the installation did not finish")
	return Status{}
}
