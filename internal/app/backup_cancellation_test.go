package app

import (
	"context"
	"errors"
	"os"
	"testing"

	"github.com/drudge/sable/internal/backup"
)

func TestCreateBackupStopsBeforeSealingWhenCancelled(t *testing.T) {
	path := newBackupDeployment(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	contents, err := CreateBackup(ctx, BackupOptions{
		ConfigurationPath: path, Passphrase: backupTestPassphrase,
		Progress: func(progress backup.Progress) {
			if progress.Stage == "Sealing the archive" {
				cancel()
			}
		},
	})
	if !errors.Is(err, context.Canceled) || len(contents) != 0 {
		t.Fatalf("CreateBackup = %d bytes, %v; want cancelled with no archive", len(contents), err)
	}
}

func TestStageRestoreCancellationDoesNotPublishMarker(t *testing.T) {
	sourcePath := newBackupDeployment(t)
	sealed, err := CreateBackup(context.Background(), BackupOptions{ConfigurationPath: sourcePath, Passphrase: backupTestPassphrase})
	if err != nil {
		t.Fatal(err)
	}
	for _, stage := range []string{"before start", "Opening the archive", "Staging the restore"} {
		t.Run(stage, func(t *testing.T) {
			path := newBackupDeployment(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if stage == "before start" {
				cancel()
			}
			_, err := StageRestore(ctx, RestoreOptions{
				ConfigurationPath: path, Contents: sealed, Passphrase: backupTestPassphrase, KeepConfiguration: true,
				Progress: func(progress backup.Progress) {
					if progress.Stage == stage {
						cancel()
					}
				},
			})
			if !errors.Is(err, context.Canceled) {
				t.Fatalf("StageRestore error=%v; want cancellation", err)
			}
			for _, suffix := range []string{pendingRestoreMarkerSuffix, applyingRestoreMarkerSuffix, pendingRestoreArchiveSuffix} {
				if _, err := os.Stat(path + suffix); !errors.Is(err, os.ErrNotExist) {
					t.Fatalf("cancelled restore left %s: %v", suffix, err)
				}
			}
			assertOnlyZone(t, path, "example.test")
		})
	}
}

func TestRestoreControllersPropagateCancellation(t *testing.T) {
	path := newBackupDeployment(t)
	scheduled, _ := newScheduledBackupTestService(t, 2)
	controllers := map[string]interface {
		StageRestore(context.Context, []byte, string, bool, func(backup.Progress)) (backup.RestoreSummary, error)
	}{
		"console": &consoleBackups{configurationPath: path}, "scheduled": scheduled,
	}
	for name, controller := range controllers {
		t.Run(name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			cancel()
			_, err := controller.StageRestore(ctx, []byte("not an archive"), backupTestPassphrase, true, nil)
			if !errors.Is(err, context.Canceled) {
				t.Fatalf("cancelled controller returned %v", err)
			}
		})
	}
}
