package app

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/drudge/sable/internal/backup"
	"github.com/drudge/sable/internal/config"
	"github.com/drudge/sable/internal/store"
)

func TestStageRestoreDefersEveryMutationUntilStartup(t *testing.T) {
	ctx := context.Background()
	sourcePath := newBackupDeployment(t)
	sealed, err := CreateBackup(ctx, BackupOptions{ConfigurationPath: sourcePath, Passphrase: backupTestPassphrase})
	if err != nil {
		t.Fatalf("CreateBackup() error = %v", err)
	}
	sealed = backupWithZoneName(t, sealed, "restored.test")
	targetPath := newBackupDeployment(t)

	result, err := StageRestore(RestoreOptions{
		ConfigurationPath: targetPath,
		Contents:          sealed,
		Passphrase:        backupTestPassphrase,
		KeepConfiguration: true,
	})
	if err != nil {
		t.Fatalf("StageRestore() error = %v", err)
	}
	if result.Zones != 1 {
		t.Fatalf("StageRestore() result = %+v", result)
	}
	assertOnlyZone(t, targetPath, "example.test")
	if _, err := os.Stat(targetPath + pendingRestoreMarkerSuffix); err != nil {
		t.Fatalf("pending marker: %v", err)
	}

	applied, err := applyStagedRestore(ctx, targetPath)
	if err != nil {
		t.Fatalf("applyStagedRestore() error = %v", err)
	}
	if !applied {
		t.Fatal("applyStagedRestore() did not find the staged archive")
	}
	assertOnlyZone(t, targetPath, "restored.test")
	for _, suffix := range []string{pendingRestoreMarkerSuffix, applyingRestoreMarkerSuffix, pendingRestoreArchiveSuffix, rollbackKeySuffix, rollbackArchiveSuffix} {
		if _, err := os.Stat(targetPath + suffix); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("restore artifact %s remains: %v", suffix, err)
		}
	}
}

func TestStageRestoreRejectsReplacementUntilThePendingRestoreIsApplied(t *testing.T) {
	ctx := context.Background()
	sourcePath := newBackupDeployment(t)
	sealed, err := CreateBackup(ctx, BackupOptions{ConfigurationPath: sourcePath, Passphrase: backupTestPassphrase})
	if err != nil {
		t.Fatalf("CreateBackup() error = %v", err)
	}
	targetPath := newBackupDeployment(t)
	options := RestoreOptions{
		ConfigurationPath: targetPath,
		Contents:          sealed,
		Passphrase:        backupTestPassphrase,
		KeepConfiguration: true,
	}
	if _, err := StageRestore(options); err != nil {
		t.Fatalf("first StageRestore() error = %v", err)
	}
	if _, err := StageRestore(options); err == nil {
		t.Fatal("second StageRestore() replaced the pending restore")
	}
}

func TestApplyStagedRestoreResumesAnAlreadyClaimedRestore(t *testing.T) {
	ctx := context.Background()
	sourcePath := newBackupDeployment(t)
	sealed, err := CreateBackup(ctx, BackupOptions{ConfigurationPath: sourcePath, Passphrase: backupTestPassphrase})
	if err != nil {
		t.Fatalf("CreateBackup() error = %v", err)
	}
	sealed = backupWithZoneName(t, sealed, "resumed.test")
	targetPath := newBackupDeployment(t)
	if _, err := StageRestore(RestoreOptions{
		ConfigurationPath: targetPath,
		Contents:          sealed,
		Passphrase:        backupTestPassphrase,
		KeepConfiguration: true,
	}); err != nil {
		t.Fatalf("StageRestore() error = %v", err)
	}
	if err := os.Rename(targetPath+pendingRestoreMarkerSuffix, targetPath+applyingRestoreMarkerSuffix); err != nil {
		t.Fatal(err)
	}
	if applied, err := applyStagedRestore(ctx, targetPath); err != nil || !applied {
		t.Fatalf("applyStagedRestore() = %t, %v", applied, err)
	}
	assertOnlyZone(t, targetPath, "resumed.test")
}

func TestRestoreRollsBackSectionsAppliedBeforeALateFailure(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	sourcePath := newBackupDeployment(t)
	sealed, err := CreateBackup(ctx, BackupOptions{ConfigurationPath: sourcePath, Passphrase: backupTestPassphrase})
	if err != nil {
		t.Fatalf("CreateBackup() error = %v", err)
	}
	sealed = backupWithZoneName(t, sealed, "restored.test")
	targetPath := newBackupDeployment(t)
	originalConfiguration, err := os.ReadFile(targetPath)
	if err != nil {
		t.Fatal(err)
	}

	_, err = RestoreBackup(ctx, RestoreOptions{
		ConfigurationPath: targetPath,
		Contents:          sealed,
		Passphrase:        backupTestPassphrase,
		KeepConfiguration: true,
		Progress: func(progress Progress) {
			if progress.Stage == "Restoring users, roles, and tokens" {
				cancel()
			}
		},
	})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("RestoreBackup() error = %v, want context cancellation", err)
	}
	assertOnlyZone(t, targetPath, "example.test")
	restoredConfiguration, err := os.ReadFile(targetPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(restoredConfiguration) != string(originalConfiguration) {
		t.Fatal("failed restore did not put the original configuration back")
	}
	if _, err := os.Stat(targetPath + rollbackKeySuffix); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("rollback marker remains: %v", err)
	}
}

func backupWithZoneName(t *testing.T, sealed []byte, name string) []byte {
	t.Helper()
	archive, err := backup.Decode(sealed, backupTestPassphrase)
	if err != nil {
		t.Fatalf("backup.Decode() error = %v", err)
	}
	archive.Zones[0].ID = "restored-zone"
	archive.Zones[0].Name = name
	for index := range archive.Zones[0].Records {
		archive.Zones[0].Records[index].Name = name
	}
	sealed, err = backup.Encode(archive, backupTestPassphrase)
	if err != nil {
		t.Fatalf("backup.Encode() error = %v", err)
	}
	return sealed
}

func assertOnlyZone(t *testing.T, configurationPath, name string) {
	t.Helper()
	configuration, err := config.Load(configurationPath)
	if err != nil {
		t.Fatalf("config.Load() error = %v", err)
	}
	database, err := store.Open(context.Background(), configuration.Database.Driver, configuration.Database.DSN)
	if err != nil {
		t.Fatalf("store.Open() error = %v", err)
	}
	defer database.Close()
	zones, err := database.ListZones(context.Background())
	if err != nil {
		t.Fatalf("ListZones() error = %v", err)
	}
	if len(zones) != 1 || zones[0].Name != name {
		t.Fatalf("zones = %+v, want only %q", zones, name)
	}
}

func TestRecoverInterruptedRestoreUsesTheDurableJournal(t *testing.T) {
	ctx := context.Background()
	configurationPath := newBackupDeployment(t)
	original, err := os.ReadFile(configurationPath)
	if err != nil {
		t.Fatal(err)
	}
	rollback, err := beginRestoreRollback(ctx, configurationPath, false)
	if err != nil {
		t.Fatalf("beginRestoreRollback() error = %v", err)
	}
	if rollback == nil {
		t.Fatal("beginRestoreRollback() returned no journal")
	}
	if err := os.WriteFile(configurationPath, []byte("not valid TOML"), 0o600); err != nil {
		t.Fatal(err)
	}
	recovered, err := recoverInterruptedRestore(ctx, configurationPath)
	if err != nil {
		t.Fatalf("recoverInterruptedRestore() error = %v", err)
	}
	if !recovered {
		t.Fatal("recoverInterruptedRestore() did not find the journal")
	}
	contents, err := os.ReadFile(configurationPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(contents) != string(original) {
		t.Fatalf("recovered configuration differs from %s", filepath.Base(configurationPath))
	}
}
