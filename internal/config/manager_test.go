package config

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestManagerReloadCommitsValidConfiguration(t *testing.T) {
	t.Parallel()

	path := writeConfiguration(t, "[blocking]\nenabled = false\n")
	initial, err := Load(path)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	manager := NewManager(path, initial, func(_ context.Context, _, _ Config) error { return nil })

	if err := os.WriteFile(path, []byte("[blocking]\nenabled = true\n"), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	if err := manager.Reload(context.Background()); err != nil {
		t.Fatalf("Reload() error = %v", err)
	}

	snapshot := manager.Current()
	if snapshot.Revision != 2 {
		t.Fatalf("Revision = %d, want 2", snapshot.Revision)
	}
	if !snapshot.Config.Blocking.Enabled {
		t.Fatal("Blocking.Enabled = false, want true")
	}
}

func TestManagerReloadPreservesSnapshotWhenApplyRejectsCandidate(t *testing.T) {
	t.Parallel()

	path := writeConfiguration(t, "[blocking]\nenabled = false\n")
	initial, err := Load(path)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	manager := NewManager(path, initial, func(_ context.Context, _, _ Config) error {
		return errors.New("replacement listener unavailable")
	})

	if err := os.WriteFile(path, []byte("[blocking]\nenabled = true\n"), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	if err := manager.Reload(context.Background()); err == nil {
		t.Fatal("Reload() error = nil, want rejection")
	}

	snapshot := manager.Current()
	if snapshot.Revision != 1 {
		t.Fatalf("Revision = %d, want 1", snapshot.Revision)
	}
	if snapshot.Config.Blocking.Enabled {
		t.Fatal("Blocking.Enabled = true, want last-known-good false")
	}
}

func TestManagerUpdateBlockingPersistsAndAppliesPolicy(t *testing.T) {
	t.Parallel()

	path := writeConfiguration(t, "[blocking]\nenabled = true\ndomains = []\n")
	initial, err := Load(path)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	manager := NewManager(path, initial, func(_ context.Context, _, _ Config) error { return nil })
	if err := manager.UpdateBlocking(context.Background(), func(policy *Blocking) error {
		policy.Domains = append(policy.Domains, "Ads.Example.")
		return nil
	}); err != nil {
		t.Fatalf("UpdateBlocking() error = %v", err)
	}
	loaded, err := Load(path)
	if err != nil {
		t.Fatalf("Load(updated) error = %v", err)
	}
	if len(loaded.Blocking.Domains) != 1 || loaded.Blocking.Domains[0] != "ads.example" {
		t.Fatalf("updated domains = %v", loaded.Blocking.Domains)
	}
	if manager.Current().Revision != 2 {
		t.Fatalf("Revision = %d, want 2", manager.Current().Revision)
	}
}

func TestManagerUpdateBlockingRestoresFileWhenApplyFails(t *testing.T) {
	t.Parallel()

	path := writeConfiguration(t, "[blocking]\nenabled = false\n")
	initial, err := Load(path)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	manager := NewManager(path, initial, func(_ context.Context, _, _ Config) error {
		return errors.New("activation failed")
	})
	if err := manager.UpdateBlocking(context.Background(), func(policy *Blocking) error {
		policy.Enabled = true
		return nil
	}); err == nil {
		t.Fatal("UpdateBlocking() error = nil")
	}
	loaded, err := Load(path)
	if err != nil {
		t.Fatalf("Load(restored) error = %v", err)
	}
	if loaded.Blocking.Enabled || manager.Current().Revision != 1 {
		t.Fatalf("restored policy = %+v revision=%d", loaded.Blocking, manager.Current().Revision)
	}
}

func TestManagerUpdatePersistsRevisionedRuntimeConfiguration(t *testing.T) {
	t.Parallel()
	path := writeConfiguration(t, "[server]\ndns_listen = [\"127.0.0.1:5353\"]\n[resolver]\nforwarders = [\"1.1.1.1:53\"]\n")
	initial, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	manager := NewManager(path, initial, func(_ context.Context, active, candidate Config) error {
		if active.Resolver.CacheSize == candidate.Resolver.CacheSize {
			return errors.New("candidate cache size was not updated")
		}
		return nil
	})
	if err := manager.Update(context.Background(), func(candidate *Config) error {
		candidate.Resolver.CacheSize = 4096
		candidate.Resolver.Forwarders = []string{"9.9.9.9:53"}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	loaded, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if manager.Current().Revision != 2 || loaded.Resolver.CacheSize != 4096 || len(loaded.Resolver.Forwarders) != 1 || loaded.Resolver.Forwarders[0] != "9.9.9.9:53" {
		t.Fatalf("snapshot=%+v loaded=%+v", manager.Current(), loaded.Resolver)
	}
}

func writeConfiguration(t *testing.T, contents string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "sable.toml")
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	return path
}
