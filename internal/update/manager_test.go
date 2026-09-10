package update

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestManagerCheckReportsAnAvailableReleaseWithoutInstallingIt(t *testing.T) {
	setTestRelease(t, "0.7.0")
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
	setTestRelease(t, "0.7.0-rc.1")
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
	setTestRelease(t, "0.7.0")
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
	setTestRelease(t, "0.7.0")
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
	setTestRelease(t, "0.7.0")
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

func TestManagerRefusesToInstallWhereItCannotWrite(t *testing.T) {
	setTestRelease(t, "0.7.0")
	binaryPath := installedExecutable(t, "#!/bin/sh\necho old\n")
	if err := os.Chmod(filepath.Dir(binaryPath), 0o555); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chmod(filepath.Dir(binaryPath), 0o755) })
	if os.Geteuid() == 0 {
		t.Skip("root writes through a read-only directory")
	}
	server := releaseServer(t, "v9.9.9", false, nil)
	manager := NewManager(Options{APIBaseURL: server.URL, BinaryPath: binaryPath})
	status, err := manager.Check(context.Background(), false)
	if err != nil {
		t.Fatal(err)
	}
	if !status.Available || status.Blocked == "" {
		t.Fatalf("a check should report the release and why it cannot be installed: %+v", status)
	}
	if err := manager.Install(false); err == nil {
		t.Fatal("an installation should be refused where the executable cannot be replaced")
	}
	if status := manager.Status(); status.Phase != PhaseFailed || status.Error == "" {
		t.Fatalf("status = %+v", status)
	}
	installed, err := os.ReadFile(binaryPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(installed), "echo old") {
		t.Fatalf("a refused installation replaced the executable: %q", installed)
	}
}

type countingReleaseTransport struct{ calls atomic.Int32 }

func (transport *countingReleaseTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	transport.calls.Add(1)
	return http.DefaultTransport.RoundTrip(request)
}

func TestAutomaticChecksCacheAcrossSessionsAndPreserveReleaseNotes(t *testing.T) {
	setTestRelease(t, "1.0.0")
	source := releaseServer(t, "v1.1.0", false, nil)
	transport := &countingReleaseTransport{}
	manager := NewManager(Options{APIBaseURL: source.URL, BinaryPath: installedExecutable(t, "old"), Client: &http.Client{Transport: transport}})
	var checks sync.WaitGroup
	for range 20 {
		checks.Go(func() { _, _ = manager.CheckAutomatically(context.Background(), false) })
	}
	checks.Wait()
	if transport.calls.Load() != 1 {
		t.Fatalf("concurrent metadata requests = %d", transport.calls.Load())
	}
	for range 3 {
		if _, err := manager.CheckAutomatically(context.Background(), false); err != nil {
			t.Fatal(err)
		}
	}
	if transport.calls.Load() != 1 {
		t.Fatal("cached check contacted GitHub")
	}
	if status := manager.Status(); !status.Available || status.ReleaseNotes != "### Improvements\n\n- More reliable updates." {
		t.Fatalf("status = %+v", status)
	}
	manager.mutex.Lock()
	manager.status.CheckedAt = time.Now().Add(-automaticCheckInterval)
	manager.mutex.Unlock()
	if _, err := manager.CheckAutomatically(context.Background(), false); err != nil {
		t.Fatal(err)
	}
	if transport.calls.Load() != 2 {
		t.Fatal("expired result was not refreshed")
	}
	if _, err := manager.Check(context.Background(), false); err != nil {
		t.Fatal(err)
	}
	if transport.calls.Load() != 3 {
		t.Fatal("manual check did not bypass cache")
	}
}

func TestAutomaticChecksCacheFailuresAndRespectChannelChanges(t *testing.T) {
	setTestRelease(t, "1.0.0")
	source := releaseServer(t, "v1.1.0-rc.1", true, nil)
	transport := &countingReleaseTransport{}
	manager := NewManager(Options{APIBaseURL: source.URL, BinaryPath: installedExecutable(t, "old"), Client: &http.Client{Transport: transport}})
	if _, err := manager.CheckAutomatically(context.Background(), false); err == nil {
		t.Fatal("missing stable release succeeded")
	}
	_, _ = manager.CheckAutomatically(context.Background(), false)
	if transport.calls.Load() != 1 {
		t.Fatal("failed lookup was not cached")
	}
	status, err := manager.CheckAutomatically(context.Background(), true)
	if err != nil || !status.Available || !status.PreRelease || transport.calls.Load() != 2 {
		t.Fatalf("changed channel = %+v, %v", status, err)
	}
}

func TestReservedUpdatePinsVersionAndBlocksOtherOperations(t *testing.T) {
	setTestRelease(t, "1.0.0")
	requireExecutableScripts(t)
	source := releaseServer(t, "v1.1.0", false, nil)
	manager := NewManager(Options{APIBaseURL: source.URL, BinaryPath: installedExecutable(t, "#!/bin/sh\necho old\n")})
	if err := manager.Reserve("rollout-1"); err != nil {
		t.Fatal(err)
	}
	if !manager.Status().ClusterUpdate {
		t.Fatal("reservation is not visible")
	}
	if _, err := manager.Check(context.Background(), false); !errors.Is(err, ErrUpdateInProgress) {
		t.Fatalf("reserved check = %v", err)
	}
	if err := manager.Install(false); !errors.Is(err, ErrUpdateInProgress) {
		t.Fatalf("reserved install = %v", err)
	}
	if err := manager.InstallVersion("other-rollout", "v1.1.0"); err == nil {
		t.Fatal("wrong reservation accepted")
	}
	if err := manager.InstallVersion("rollout-1", "v0.9.0"); err == nil {
		t.Fatal("downgrade accepted")
	}
	if err := manager.InstallVersion("rollout-1", "v1.1.0"); err != nil {
		t.Fatal(err)
	}
	if status := awaitInstall(t, manager); !status.Installed || status.LatestVersion != "1.1.0" {
		t.Fatalf("install = %+v", status)
	}
	manager.Release("rollout-1")
	if _, err := manager.Check(context.Background(), false); !errors.Is(err, ErrUpdateInProgress) {
		t.Fatalf("check erased pending restart: %v", err)
	}
	if !manager.Status().Installed {
		t.Fatal("pending installation was lost")
	}
}
