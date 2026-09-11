package update

import (
	"context"
	"errors"
	"testing"
	"time"
)

type testReleaseStore struct {
	release ReleaseInfo
	err     error
}

func (store *testReleaseStore) LoadUpdateRelease(context.Context) (ReleaseInfo, error) {
	return store.release, store.err
}

func (store *testReleaseStore) SaveUpdateRelease(_ context.Context, release ReleaseInfo) error {
	if store.err != nil {
		return store.err
	}
	store.release = release
	return nil
}

func TestReleaseNotesSurviveClusterInstallAndRestartOffline(t *testing.T) {
	setTestRelease(t, "1.0.0")
	requireExecutableScripts(t)
	source := releaseServer(t, "v1.1.0", false, nil)
	cache := &testReleaseStore{}
	options := Options{APIBaseURL: source.URL, BinaryPath: installedExecutable(t, "#!/bin/sh\necho old\n"), ReleaseStore: cache}
	manager := NewManager(options)
	if err := manager.Reserve("rollout"); err != nil {
		t.Fatal(err)
	}
	if err := manager.InstallVersion("rollout", "v1.1.0"); err != nil {
		t.Fatal(err)
	}
	installed := awaitInstall(t, manager)
	if !installed.Installed || installed.ReleaseNotes == "" {
		t.Fatalf("installation = %+v", installed)
	}
	source.Close()
	setTestRelease(t, "1.1.0")
	restarted := NewManager(options)
	status := restarted.Status()
	if status.ReleaseNotes != installed.ReleaseNotes || status.ReleaseURL != installed.ReleaseURL || status.LatestVersion != "1.1.0" {
		t.Fatalf("release details lost after restart: %+v", status)
	}
	if !status.UpToDate() || status.Available || status.Installed || status.ClusterUpdate || status.Phase != PhaseIdle || status.CurrentVersion != "1.1.0" {
		t.Fatalf("restart restored obsolete installation state: %+v", status)
	}
	if _, err := restarted.CheckAutomatically(context.Background(), false); err != nil {
		t.Fatalf("fresh cache contacted unavailable release feed: %v", err)
	}
}

func TestRestoredReleaseCacheExpiresAndRetainsNotesOnFailedCheck(t *testing.T) {
	setTestRelease(t, "1.0.0")
	source := releaseServer(t, "v1.1.0", false, nil)
	cache := &testReleaseStore{}
	options := Options{APIBaseURL: source.URL, BinaryPath: installedExecutable(t, "old"), ReleaseStore: cache}
	manager := NewManager(options)
	if _, err := manager.Check(context.Background(), false); err != nil {
		t.Fatal(err)
	}
	cache.release.CheckedAt = time.Now().Add(-automaticCheckInterval)
	restarted := NewManager(options)
	if !restarted.Status().Available {
		t.Fatal("restart must recompute availability for a node still on the older version")
	}
	source.Close()
	status, err := restarted.CheckAutomatically(context.Background(), false)
	if err == nil || status.ReleaseNotes == "" {
		t.Fatalf("expired cache should refresh and preserve notes on failure: %+v, %v", status, err)
	}
	if restored := NewManager(options).Status(); restored.ReleaseNotes != status.ReleaseNotes || restored.Error != "" {
		t.Fatalf("failed check replaced the last successful release: %+v", restored)
	}
}

func TestReleaseCacheRespectsSourceAndChannelAndToleratesStorageFailure(t *testing.T) {
	setTestRelease(t, "1.0.0")
	for _, scenario := range []string{"repository", "endpoint", "channel", "storage failure"} {
		t.Run(scenario, func(t *testing.T) {
			cache := &testReleaseStore{release: ReleaseInfo{Repository: defaultRepository, APIBaseURL: defaultAPIBaseURL, Version: "1.1.0", Notes: "Saved notes", CheckedAt: time.Now()}}
			options := Options{ReleaseStore: cache}
			switch scenario {
			case "repository":
				options.Repository = "another/project"
			case "endpoint":
				options.APIBaseURL = "https://another.example.test"
			case "channel":
				options.PreRelease = true
			case "storage failure":
				cache.err = errors.New("database unavailable")
			}
			manager := NewManager(options)
			if status := manager.Status(); status.Checked() || status.ReleaseNotes != "" || status.Error != "" {
				t.Fatalf("invalid cache must leave normal unchecked state: %+v", status)
			}
			if scenario == "storage failure" {
				status := manager.finish(Result{CurrentVersion: "1.0.0", LatestVersion: "1.1.0", ReleaseNotes: "Fresh notes", Applied: true}, nil)
				if !status.Installed || status.Error != "" || status.ReleaseNotes != "Fresh notes" {
					t.Fatalf("cache failure broke installation: %+v", status)
				}
			}
		})
	}
}
