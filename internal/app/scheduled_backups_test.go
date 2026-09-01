package app

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/drudge/sable/internal/auth"
	"github.com/drudge/sable/internal/backup"
	"github.com/drudge/sable/internal/config"
)

type memoryBackupVault struct {
	values map[string][]byte
}

func (vault *memoryBackupVault) Put(_ context.Context, name string, value []byte) error {
	if vault.values == nil {
		vault.values = map[string][]byte{}
	}
	vault.values[name] = append([]byte(nil), value...)
	return nil
}

func (vault *memoryBackupVault) Get(_ context.Context, name string) ([]byte, error) {
	value, ok := vault.values[name]
	if !ok {
		return nil, auth.ErrNotFound
	}
	return append([]byte(nil), value...), nil
}

func (vault *memoryBackupVault) Delete(_ context.Context, name string) error {
	delete(vault.values, name)
	return nil
}

func newScheduledBackupTestService(t *testing.T, retention int) (*scheduledBackupService, config.Backup) {
	t.Helper()
	directory := t.TempDir()
	policy := config.Backup{
		Enabled: true, Directory: "backups", Interval: config.Duration{Duration: 24 * time.Hour}, RunAt: "02:00", RetentionCount: retention,
	}
	manager := config.NewManager(filepath.Join(directory, "sable.toml"), config.Defaults(), func(context.Context, config.Config, config.Config) error { return nil })
	service, err := newScheduledBackupService(
		filepath.Join(directory, "sable.toml"), manager, &memoryBackupVault{},
		slog.New(slog.NewTextHandler(io.Discard, nil)), policy,
	)
	if err != nil {
		t.Fatalf("newScheduledBackupService() error = %v", err)
	}
	return service, policy
}

func TestNextAnchoredBackupRunUsesTheSelectedLocalTime(t *testing.T) {
	previous := time.Date(2026, time.September, 1, 17, 50, 0, 0, time.Local)
	if got, want := nextAnchoredBackupRun(previous, 24*time.Hour, "02:00"), time.Date(2026, time.September, 2, 2, 0, 0, 0, time.Local); !got.Equal(want) {
		t.Fatalf("daily next run = %s, want %s", got, want)
	}
	if got, want := nextAnchoredBackupRun(previous, 6*time.Hour, "02:00"), time.Date(2026, time.September, 1, 20, 0, 0, 0, time.Local); !got.Equal(want) {
		t.Fatalf("six-hour next run = %s, want %s", got, want)
	}
	beforeAnchor := time.Date(2026, time.September, 1, 1, 30, 0, 0, time.Local)
	if got, want := nextAnchoredBackupRun(beforeAnchor, 24*time.Hour, "02:00"), time.Date(2026, time.September, 1, 2, 0, 0, 0, time.Local); !got.Equal(want) {
		t.Fatalf("same-day next run = %s, want %s", got, want)
	}
}

func writeScheduledTestArchive(t *testing.T, service *scheduledBackupService, policy config.Backup, created time.Time, suffix string) string {
	t.Helper()
	contents, err := backup.Encode(backup.Archive{Manifest: backup.Manifest{
		CreatedAt: created, SableVersion: "test", Hostname: "test-node", Sections: []string{backup.SectionZones},
	}}, "a long enough passphrase")
	if err != nil {
		t.Fatalf("backup.Encode() error = %v", err)
	}
	name := service.scheduledPrefix() + suffix + ".sablebackup"
	if err := writeLocalBackup(filepath.Join(service.resolveDirectory(policy.Directory), name), contents); err != nil {
		t.Fatalf("writeLocalBackup() error = %v", err)
	}
	return name
}

func TestScheduledBackupInventoryAndRotation(t *testing.T) {
	service, policy := newScheduledBackupTestService(t, 2)
	now := time.Now().UTC().Truncate(time.Second)
	oldest := writeScheduledTestArchive(t, service, policy, now.Add(-48*time.Hour), "oldest")
	writeScheduledTestArchive(t, service, policy, now.Add(-24*time.Hour), "middle")
	writeScheduledTestArchive(t, service, policy, now, "newest")
	if err := os.WriteFile(filepath.Join(service.resolveDirectory(policy.Directory), "foreign.sablebackup"), []byte("not a backup"), 0o600); err != nil {
		t.Fatal(err)
	}

	archives, err := service.LocalBackups(context.Background())
	if err != nil {
		t.Fatalf("LocalBackups() error = %v", err)
	}
	if len(archives) != 3 || archives[0].CreatedAt != now {
		t.Fatalf("archives = %+v", archives)
	}
	if err := service.pruneScheduled(context.Background(), policy); err != nil {
		t.Fatalf("pruneScheduled() error = %v", err)
	}
	if _, err := os.Stat(filepath.Join(service.resolveDirectory(policy.Directory), oldest)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("oldest archive stat error = %v, want not exist", err)
	}
	archives, err = service.LocalBackups(context.Background())
	if err != nil || len(archives) != 2 {
		t.Fatalf("archives after prune = %+v, error = %v", archives, err)
	}
}

func TestLocalBackupRestoreRejectsTraversalAndSymlinks(t *testing.T) {
	service, policy := newScheduledBackupTestService(t, 2)
	if _, _, err := service.LocalBackupForRestore(context.Background(), "../outside.sablebackup", "passphrase"); err == nil {
		t.Fatal("LocalBackupForRestore() accepted traversal")
	}
	target := filepath.Join(service.resolveDirectory(policy.Directory), "target.sablebackup")
	if err := os.WriteFile(target, []byte("backup"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(service.resolveDirectory(policy.Directory), "link.sablebackup")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if _, _, err := service.LocalBackupForRestore(context.Background(), "link.sablebackup", "passphrase"); err == nil {
		t.Fatal("LocalBackupForRestore() accepted a symlink")
	}
}

func TestDeleteLocalBackupRemovesOnlyAValidArchive(t *testing.T) {
	service, policy := newScheduledBackupTestService(t, 2)
	name := writeScheduledTestArchive(t, service, policy, time.Now().UTC(), "delete-me")
	path := filepath.Join(service.resolveDirectory(policy.Directory), name)
	if err := service.DeleteLocalBackup(context.Background(), name); err != nil {
		t.Fatalf("DeleteLocalBackup() error = %v", err)
	}
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("deleted archive stat error = %v, want not exist", err)
	}
	if err := service.DeleteLocalBackup(context.Background(), "../outside.sablebackup"); err == nil {
		t.Fatal("DeleteLocalBackup() accepted traversal")
	}
	foreign := filepath.Join(service.resolveDirectory(policy.Directory), "foreign.sablebackup")
	if err := os.WriteFile(foreign, []byte("not a backup"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := service.DeleteLocalBackup(context.Background(), filepath.Base(foreign)); err == nil {
		t.Fatal("DeleteLocalBackup() accepted a foreign file")
	}
	if _, err := os.Stat(foreign); err != nil {
		t.Fatalf("foreign file was removed: %v", err)
	}
}

func TestLocalBackupPassphraseUsesVaultUnlessOverridden(t *testing.T) {
	service, _ := newScheduledBackupTestService(t, 2)
	if err := service.vault.Put(context.Background(), scheduledBackupPassphraseSecret, []byte("the vaulted backup passphrase")); err != nil {
		t.Fatal(err)
	}
	passphrase, err := service.localBackupPassphrase(context.Background(), "")
	if err != nil || passphrase != "the vaulted backup passphrase" {
		t.Fatalf("localBackupPassphrase(vault) = %q, %v", passphrase, err)
	}
	passphrase, err = service.localBackupPassphrase(context.Background(), "a different one-off passphrase")
	if err != nil || passphrase != "a different one-off passphrase" {
		t.Fatalf("localBackupPassphrase(override) = %q, %v", passphrase, err)
	}
}

func TestLocalBackupPassphraseRequiresAVaultValueWithoutOverride(t *testing.T) {
	service, _ := newScheduledBackupTestService(t, 2)
	if _, err := service.localBackupPassphrase(context.Background(), ""); err == nil {
		t.Fatal("localBackupPassphrase() accepted a missing vault value")
	}
}
