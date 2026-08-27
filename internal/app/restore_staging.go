package app

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/drudge/sable/internal/backup"
	"github.com/drudge/sable/internal/config"
)

const (
	pendingRestoreArchiveSuffix = ".restore-pending.sablebackup"
	pendingRestoreMarkerSuffix  = ".restore-pending.json"
	applyingRestoreMarkerSuffix = ".restore-applying.json"
	rollbackArchiveSuffix       = ".restore-rollback.sablebackup"
	rollbackKeySuffix           = ".restore-rollback.key"
)

type stagedRestore struct {
	Passphrase        string `json:"passphrase"`
	KeepConfiguration bool   `json:"keep_configuration"`
}

type restoreRollback struct {
	configurationPath string
	archivePath       string
	keyPath           string
	passphrase        string
}

// StageRestore validates and durably stages an encrypted archive. The running
// node never mutates its own configuration, database, or keys; app startup
// consumes the marker before opening any of those resources.
func StageRestore(options RestoreOptions) (RestoreResult, error) {
	progress := newReporter(options.Progress, 1)
	progress.stage("Opening the archive")
	archive, err := backup.Decode(options.Contents, options.Passphrase)
	if err != nil {
		return RestoreResult{}, err
	}
	sections, err := restoreSections(archive, options.Sections)
	if err != nil {
		return RestoreResult{}, err
	}
	absolutePath, err := config.AbsolutePath(options.ConfigurationPath)
	if err != nil {
		return RestoreResult{}, err
	}
	if _, _, err := effectiveConfiguration(archive, options, absolutePath, sections); err != nil {
		return RestoreResult{}, err
	}
	for _, suffix := range []string{pendingRestoreMarkerSuffix, applyingRestoreMarkerSuffix} {
		if _, err := os.Stat(absolutePath + suffix); err == nil {
			return RestoreResult{}, errors.New("a deployment restore is already staged")
		} else if !errors.Is(err, fs.ErrNotExist) {
			return RestoreResult{}, fmt.Errorf("inspect staged restore: %w", err)
		}
	}
	marker, err := json.Marshal(stagedRestore{
		Passphrase: options.Passphrase, KeepConfiguration: options.KeepConfiguration,
	})
	if err != nil {
		return RestoreResult{}, fmt.Errorf("encode staged restore: %w", err)
	}
	if err := atomicWriteFile(absolutePath+pendingRestoreArchiveSuffix, 0o600, options.Contents); err != nil {
		return RestoreResult{}, fmt.Errorf("stage restore archive: %w", err)
	}
	// The marker lands last. Its presence is the commit record that startup uses,
	// so a crash while writing the larger archive never schedules partial bytes.
	if err := atomicWriteFile(absolutePath+pendingRestoreMarkerSuffix, 0o600, marker); err != nil {
		return RestoreResult{}, fmt.Errorf("stage restore marker: %w", err)
	}
	progress.done("Restore staged")
	return restoreResultFromArchive(archive, sections, absolutePath), nil
}

func applyStagedRestore(ctx context.Context, configurationPath string) (bool, error) {
	pendingMarker := configurationPath + pendingRestoreMarkerSuffix
	applyingMarker := configurationPath + applyingRestoreMarkerSuffix
	archivePath := configurationPath + pendingRestoreArchiveSuffix

	_, applyingErr := os.Stat(applyingMarker)
	if applyingErr != nil && !errors.Is(applyingErr, fs.ErrNotExist) {
		return false, fmt.Errorf("inspect applying restore marker: %w", applyingErr)
	}
	if errors.Is(applyingErr, fs.ErrNotExist) {
		if _, err := os.Stat(pendingMarker); errors.Is(err, fs.ErrNotExist) {
			return false, nil
		} else if err != nil {
			return false, fmt.Errorf("inspect pending restore marker: %w", err)
		}
		if err := os.Rename(pendingMarker, applyingMarker); err != nil {
			return false, fmt.Errorf("claim pending restore: %w", err)
		}
	}
	cleanup := func() {
		_ = os.Remove(applyingMarker)
		_ = os.Remove(archivePath)
	}
	marker, err := os.ReadFile(applyingMarker)
	if err != nil {
		cleanup()
		return false, fmt.Errorf("read staged restore marker: %w", err)
	}
	var staged stagedRestore
	if err := json.Unmarshal(marker, &staged); err != nil {
		cleanup()
		return false, fmt.Errorf("decode staged restore marker: %w", err)
	}
	contents, err := os.ReadFile(archivePath)
	if err != nil {
		cleanup()
		return false, fmt.Errorf("read staged restore archive: %w", err)
	}
	_, err = RestoreBackup(ctx, RestoreOptions{
		ConfigurationPath: configurationPath,
		Contents:          contents,
		Passphrase:        staged.Passphrase,
		KeepConfiguration: staged.KeepConfiguration,
	})
	cleanup()
	if err != nil {
		return false, err
	}
	return true, nil
}

func beginRestoreRollback(ctx context.Context, configurationPath string, skip bool) (*restoreRollback, error) {
	if skip {
		return nil, nil
	}
	if _, err := os.Stat(configurationPath); errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	} else if err != nil {
		return nil, err
	}
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		return nil, fmt.Errorf("generate rollback passphrase: %w", err)
	}
	passphrase := base64.RawURLEncoding.EncodeToString(secret)
	contents, err := CreateBackup(ctx, BackupOptions{
		ConfigurationPath: configurationPath,
		Passphrase:        passphrase,
	})
	if err != nil {
		return nil, err
	}
	rollback := &restoreRollback{
		configurationPath: configurationPath,
		archivePath:       configurationPath + rollbackArchiveSuffix,
		keyPath:           configurationPath + rollbackKeySuffix,
		passphrase:        passphrase,
	}
	if err := atomicWriteFile(rollback.archivePath, 0o600, contents); err != nil {
		return nil, err
	}
	// The key is the recovery marker and therefore lands last.
	if err := atomicWriteFile(rollback.keyPath, 0o600, []byte(passphrase)); err != nil {
		return nil, err
	}
	return rollback, nil
}

func recoverInterruptedRestore(ctx context.Context, configurationPath string) (bool, error) {
	keyPath := configurationPath + rollbackKeySuffix
	passphrase, err := os.ReadFile(keyPath)
	if errors.Is(err, fs.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	rollback := &restoreRollback{
		configurationPath: configurationPath,
		archivePath:       configurationPath + rollbackArchiveSuffix,
		keyPath:           keyPath,
		passphrase:        string(passphrase),
	}
	if err := rollback.restore(ctx); err != nil {
		return false, err
	}
	return true, nil
}

func (rollback *restoreRollback) restore(ctx context.Context) error {
	contents, err := os.ReadFile(rollback.archivePath)
	if err != nil {
		return fmt.Errorf("read rollback archive: %w", err)
	}
	if _, err := RestoreBackup(ctx, RestoreOptions{
		ConfigurationPath: rollback.configurationPath,
		Contents:          contents,
		Passphrase:        rollback.passphrase,
		skipRollback:      true,
	}); err != nil {
		return err
	}
	return rollback.commit()
}

func (rollback *restoreRollback) commit() error {
	// Removing the key commits the new state: startup only rolls back when this
	// marker exists. A leftover archive without its key is inert and can be
	// replaced by the next restore.
	if err := os.Remove(rollback.keyPath); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	_ = os.Remove(rollback.archivePath)
	return nil
}

func restoreResultFromArchive(archive backup.Archive, sections []string, configurationPath string) RestoreResult {
	result := RestoreResult{Manifest: archive.Manifest, Sections: sections, ConfigurationPath: configurationPath}
	if containsSection(sections, backup.SectionZones) {
		result.Zones = len(archive.Zones)
	}
	if containsSection(sections, backup.SectionAuthorization) {
		result.Users = len(archive.Authorization.Users)
		result.Roles = len(archive.Authorization.Roles)
		result.Tokens = len(archive.Authorization.Tokens)
	}
	if containsSection(sections, backup.SectionSecrets) {
		result.Secrets = len(archive.Secrets)
	}
	if containsSection(sections, backup.SectionTrustAnchors) {
		result.TrustAnchors = len(archive.TrustAnchors)
	}
	for _, file := range archive.Files {
		if containsSection(sections, file.Section) {
			result.Files++
		}
	}
	return result
}

func containsSection(sections []string, section string) bool {
	for _, candidate := range sections {
		if candidate == section {
			return true
		}
	}
	return false
}

func atomicWriteFile(destination string, mode fs.FileMode, contents []byte) error {
	directory := filepath.Dir(destination)
	if err := os.MkdirAll(directory, 0o750); err != nil {
		return fmt.Errorf("create %s: %w", directory, err)
	}
	temporary, err := os.CreateTemp(directory, ".sable-restore-*")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if err := temporary.Chmod(mode.Perm()); err != nil {
		temporary.Close()
		return err
	}
	if _, err := temporary.Write(contents); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Sync(); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	if err := os.Rename(temporaryPath, destination); err != nil {
		return err
	}
	if opened, err := os.Open(directory); err == nil {
		defer opened.Close()
		if err := opened.Sync(); err != nil {
			return err
		}
	}
	return nil
}
