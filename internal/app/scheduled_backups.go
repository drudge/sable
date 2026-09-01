package app

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode"

	"github.com/drudge/sable/internal/auth"
	"github.com/drudge/sable/internal/backup"
	"github.com/drudge/sable/internal/config"
	"github.com/drudge/sable/internal/web"
)

const (
	scheduledBackupPassphraseSecret = "backup/scheduled/passphrase"
	maximumLocalBackupBytes         = 64 << 20
	backupHeaderReadBytes           = 64<<10 + 14
	scheduledBackupRetryDelay       = 5 * time.Minute
)

type backupSecretVault interface {
	Put(context.Context, string, []byte) error
	Get(context.Context, string) ([]byte, error)
	Delete(context.Context, string) error
}

// scheduledBackupService owns both browser backup operations and the local
// scheduler so a scheduled capture cannot race a manual capture or restore.
type scheduledBackupService struct {
	configurationPath string
	configuration     *config.Manager
	vault             backupSecretVault
	logger            *slog.Logger

	operationMu sync.Mutex
	policyMu    sync.RWMutex
	policy      config.Backup
	nextRun     time.Time
	lastSuccess time.Time
	lastError   string
	wake        chan struct{}
}

func newScheduledBackupService(configurationPath string, manager *config.Manager, vault backupSecretVault, logger *slog.Logger, policy config.Backup) (*scheduledBackupService, error) {
	service := &scheduledBackupService{
		configurationPath: configurationPath,
		configuration:     manager,
		vault:             vault,
		logger:            logger,
		policy:            policy,
		wake:              make(chan struct{}, 1),
	}
	if err := service.Prepare(policy); err != nil {
		return nil, err
	}
	return service, nil
}

// Prepare checks filesystem work that can fail before the rest of a hot reload
// mutates the live runtime.
func (service *scheduledBackupService) Prepare(policy config.Backup) error {
	if !policy.Enabled {
		return nil
	}
	directory := service.resolveDirectory(policy.Directory)
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return fmt.Errorf("create backup directory %s: %w", directory, err)
	}
	info, err := os.Stat(directory)
	if err != nil {
		return fmt.Errorf("inspect backup directory %s: %w", directory, err)
	}
	if !info.IsDir() {
		return fmt.Errorf("backup directory %s is not a directory", directory)
	}
	return nil
}

// Apply publishes a validated policy and wakes the scheduler. It cannot fail
// because Prepare has already completed any filesystem work.
func (service *scheduledBackupService) Apply(policy config.Backup) {
	service.policyMu.Lock()
	service.policy = policy
	service.nextRun = time.Time{}
	service.policyMu.Unlock()
	service.notify()
}

func (service *scheduledBackupService) CreateBackup(ctx context.Context, passphrase string, progress func(web.BackupProgress)) ([]byte, error) {
	service.operationMu.Lock()
	defer service.operationMu.Unlock()
	return CreateBackup(ctx, BackupOptions{
		ConfigurationPath: service.configurationPath,
		Passphrase:        passphrase,
		Progress:          consoleProgress(progress),
	})
}

func (service *scheduledBackupService) StageRestore(_ context.Context, contents []byte, passphrase string, keepConfiguration bool, progress func(web.BackupProgress)) (web.BackupSummary, error) {
	service.operationMu.Lock()
	defer service.operationMu.Unlock()
	result, err := StageRestore(RestoreOptions{
		ConfigurationPath: service.configurationPath,
		Contents:          contents,
		Passphrase:        passphrase,
		KeepConfiguration: keepConfiguration,
		Progress:          consoleProgress(progress),
	})
	if err != nil {
		return web.BackupSummary{}, err
	}
	return web.BackupSummary{
		Sections: result.Sections, Zones: result.Zones, Users: result.Users, Roles: result.Roles,
		Tokens: result.Tokens, Secrets: result.Secrets, TrustAnchors: result.TrustAnchors,
		Files: result.Files, ConfigurationBackedUp: result.ConfigurationBackedUp,
	}, nil
}

func (service *scheduledBackupService) BackupSchedule(ctx context.Context) (web.BackupSchedule, error) {
	policy, nextRun, lastSuccess, lastError := service.snapshot()
	_, stored, err := service.passphrase(ctx)
	if err != nil {
		return web.BackupSchedule{}, err
	}
	return web.BackupSchedule{
		Enabled: policy.Enabled, Directory: policy.Directory,
		ResolvedDirectory: service.resolveDirectory(policy.Directory),
		Interval:          policy.Interval.Duration, RunAt: policy.RunAt, RetentionCount: policy.RetentionCount,
		PassphraseStored: stored, NextRun: nextRun, LastSuccess: lastSuccess, LastError: lastError,
	}, nil
}

func (service *scheduledBackupService) UpdateBackupSchedule(ctx context.Context, update web.BackupScheduleUpdate) error {
	oldSecret, hadOldSecret, err := service.passphrase(ctx)
	if err != nil {
		return err
	}
	if update.Enabled && strings.TrimSpace(update.Passphrase) == "" && !hadOldSecret {
		return errors.New("enter a passphrase before enabling scheduled backups")
	}
	secretChanged := update.Passphrase != ""
	if secretChanged {
		if err := service.vault.Put(ctx, scheduledBackupPassphraseSecret, []byte(update.Passphrase)); err != nil {
			return fmt.Errorf("store backup passphrase: %w", err)
		}
	}
	err = service.configuration.Update(ctx, func(candidate *config.Config) error {
		candidate.Backup = config.Backup{
			Enabled: update.Enabled, Directory: update.Directory,
			Interval: config.Duration{Duration: update.Interval}, RunAt: update.RunAt, RetentionCount: update.RetentionCount,
		}
		return nil
	})
	if err == nil || !secretChanged {
		return err
	}
	// Configuration failed, so restore the vault to the state the active
	// policy had rather than silently rotating a passphrase nobody requested.
	if hadOldSecret {
		if rollbackErr := service.vault.Put(ctx, scheduledBackupPassphraseSecret, oldSecret); rollbackErr != nil {
			return fmt.Errorf("%w (restore backup passphrase: %v)", err, rollbackErr)
		}
	} else if rollbackErr := service.vault.Delete(ctx, scheduledBackupPassphraseSecret); rollbackErr != nil {
		return fmt.Errorf("%w (remove unused backup passphrase: %v)", err, rollbackErr)
	}
	return err
}

func (service *scheduledBackupService) LocalBackups(ctx context.Context) ([]web.LocalBackup, error) {
	policy, _, _, _ := service.snapshot()
	return service.localBackups(ctx, policy)
}

func (service *scheduledBackupService) CreateLocalBackup(ctx context.Context, passphrase string, progress func(web.BackupProgress)) (web.LocalBackup, error) {
	service.operationMu.Lock()
	defer service.operationMu.Unlock()
	passphrase, err := service.localBackupPassphrase(ctx, passphrase)
	if err != nil {
		return web.LocalBackup{}, err
	}
	contents, err := CreateBackup(ctx, BackupOptions{
		ConfigurationPath: service.configurationPath,
		Passphrase:        passphrase,
		Progress:          consoleProgress(progress),
	})
	if err != nil {
		return web.LocalBackup{}, err
	}
	summary, err := backup.Inspect(contents)
	if err != nil {
		return web.LocalBackup{}, err
	}
	policy, _, _, _ := service.snapshot()
	directory := service.resolveDirectory(policy.Directory)
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return web.LocalBackup{}, fmt.Errorf("create backup directory: %w", err)
	}
	name := strings.Replace(service.scheduledPrefix(), "sable-scheduled-", "sable-backup-", 1) + summary.CreatedAt.UTC().Format("20060102-150405.000") + ".sablebackup"
	if err := writeLocalBackup(filepath.Join(directory, name), contents); err != nil {
		return web.LocalBackup{}, err
	}
	return web.LocalBackup{
		Name: name, CreatedAt: summary.CreatedAt, Hostname: summary.Hostname,
		SableVersion: summary.SableVersion, Size: int64(len(contents)), Scheduled: false,
	}, nil
}

// localBackupPassphrase keeps run-now consistent with the scheduler: an
// omitted override uses the encrypted vault credential, while a supplied value
// deliberately creates a one-off archive with its own key.
func (service *scheduledBackupService) localBackupPassphrase(ctx context.Context, override string) (string, error) {
	if override != "" {
		return override, nil
	}
	secret, stored, err := service.passphrase(ctx)
	if err != nil {
		return "", err
	}
	if !stored || strings.TrimSpace(string(secret)) == "" {
		return "", errors.New("the local backup passphrase is not stored on this node")
	}
	return string(secret), nil
}

func (service *scheduledBackupService) localBackups(ctx context.Context, policy config.Backup) ([]web.LocalBackup, error) {
	directory := service.resolveDirectory(policy.Directory)
	entries, err := os.ReadDir(directory)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read backup directory %s: %w", directory, err)
	}
	prefix := service.scheduledPrefix()
	archives := make([]web.LocalBackup, 0, len(entries))
	for _, entry := range entries {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if entry.IsDir() || strings.ToLower(filepath.Ext(entry.Name())) != ".sablebackup" {
			continue
		}
		info, err := entry.Info()
		if err != nil || !info.Mode().IsRegular() {
			continue
		}
		file, err := os.Open(filepath.Join(directory, entry.Name()))
		if err != nil {
			continue
		}
		head, readErr := io.ReadAll(io.LimitReader(file, backupHeaderReadBytes))
		closeErr := file.Close()
		if readErr != nil || closeErr != nil {
			continue
		}
		summary, err := backup.Inspect(head)
		if err != nil {
			continue
		}
		archives = append(archives, web.LocalBackup{
			Name: entry.Name(), CreatedAt: summary.CreatedAt, Hostname: summary.Hostname,
			SableVersion: summary.SableVersion, Size: info.Size(), Scheduled: strings.HasPrefix(entry.Name(), prefix),
		})
	}
	sort.Slice(archives, func(left, right int) bool {
		return archives[left].CreatedAt.After(archives[right].CreatedAt)
	})
	return archives, nil
}

func (service *scheduledBackupService) LocalBackupForRestore(ctx context.Context, name, suppliedPassphrase string) ([]byte, string, error) {
	contents, err := service.LocalBackupContents(ctx, name)
	if err != nil {
		return nil, "", err
	}
	passphrase := suppliedPassphrase
	if strings.TrimSpace(passphrase) == "" {
		if !strings.HasPrefix(name, service.scheduledPrefix()) {
			return nil, "", errors.New("enter this archive's passphrase")
		}
		stored, ok, err := service.passphrase(ctx)
		if err != nil {
			return nil, "", err
		}
		if !ok {
			return nil, "", errors.New("the scheduled backup passphrase is not stored on this node")
		}
		passphrase = string(stored)
	}
	return contents, passphrase, nil
}

func (service *scheduledBackupService) LocalBackupContents(ctx context.Context, name string) ([]byte, error) {
	if name == "" || filepath.Base(name) != name || strings.ToLower(filepath.Ext(name)) != ".sablebackup" {
		return nil, errors.New("invalid local backup name")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	policy, _, _, _ := service.snapshot()
	path := filepath.Join(service.resolveDirectory(policy.Directory), name)
	info, err := os.Lstat(path)
	if err != nil {
		return nil, fmt.Errorf("inspect %s: %w", name, err)
	}
	if !info.Mode().IsRegular() {
		return nil, errors.New("local backup must be a regular file")
	}
	if info.Size() > maximumLocalBackupBytes {
		return nil, errors.New("local backup is too large for the console")
	}
	contents, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", name, err)
	}
	return contents, nil
}

func (service *scheduledBackupService) DeleteLocalBackup(ctx context.Context, name string) error {
	service.operationMu.Lock()
	defer service.operationMu.Unlock()
	contents, err := service.LocalBackupContents(ctx, name)
	if err != nil {
		return err
	}
	if _, err := backup.Inspect(contents); err != nil {
		return errors.New("the selected file is not a valid Sable backup")
	}
	policy, _, _, _ := service.snapshot()
	path := filepath.Join(service.resolveDirectory(policy.Directory), name)
	if err := os.Remove(path); err != nil {
		return fmt.Errorf("delete %s: %w", name, err)
	}
	return nil
}

// Run creates due archives until the application context closes. A failed run
// retries after a bounded delay instead of spinning, and a policy update wakes
// the loop immediately.
func (service *scheduledBackupService) Run(ctx context.Context) {
	for {
		policy, _, _, _ := service.snapshot()
		if !policy.Enabled {
			service.setNextRun(time.Time{})
			if !service.wait(ctx, 0) {
				return
			}
			continue
		}
		passphrase, stored, err := service.passphrase(ctx)
		if err != nil || !stored {
			if err == nil {
				err = errors.New("scheduled backup passphrase is missing")
			}
			service.recordScheduledFailure(err)
			service.setNextRun(time.Now().Add(scheduledBackupRetryDelay))
			if !service.wait(ctx, scheduledBackupRetryDelay) {
				return
			}
			continue
		}
		archives, err := service.localBackups(ctx, policy)
		if err != nil {
			service.recordScheduledFailure(err)
			service.setNextRun(time.Now().Add(scheduledBackupRetryDelay))
			if !service.wait(ctx, scheduledBackupRetryDelay) {
				return
			}
			continue
		}
		next := time.Now()
		for _, archive := range archives {
			if archive.Scheduled {
				next = nextAnchoredBackupRun(archive.CreatedAt, policy.Interval.Duration, policy.RunAt)
				break
			}
		}
		service.setNextRun(next)
		if delay := time.Until(next); delay > 0 {
			if !service.wait(ctx, delay) {
				return
			}
			continue
		}
		if !service.operationMu.TryLock() {
			service.setNextRun(time.Now().Add(time.Minute))
			if !service.wait(ctx, time.Minute) {
				return
			}
			continue
		}
		err = service.createScheduled(ctx, policy, string(passphrase))
		service.operationMu.Unlock()
		if err != nil {
			service.recordScheduledFailure(err)
			service.logger.Error("create scheduled backup", "error", err)
			service.setNextRun(time.Now().Add(scheduledBackupRetryDelay))
			if !service.wait(ctx, scheduledBackupRetryDelay) {
				return
			}
			continue
		}
		service.policyMu.Lock()
		service.lastSuccess = time.Now()
		service.lastError = ""
		service.policyMu.Unlock()
		service.logger.Info("created scheduled backup", "directory", service.resolveDirectory(policy.Directory), "retention_count", policy.RetentionCount)
	}
}

// nextAnchoredBackupRun preserves a predictable wall-clock phase without
// limiting intervals to whole days. For example, 6h anchored at 02:00 runs at
// 02:00, 08:00, 14:00, and 20:00 in the node's local timezone.
func nextAnchoredBackupRun(previous time.Time, interval time.Duration, runAt string) time.Time {
	clock, err := time.Parse("15:04", runAt)
	if err != nil || interval <= 0 {
		return previous.Add(interval)
	}
	local := previous.In(time.Local)
	anchor := time.Date(local.Year(), local.Month(), local.Day(), clock.Hour(), clock.Minute(), 0, 0, time.Local)
	if anchor.After(local) {
		return anchor
	}
	steps := local.Sub(anchor)/interval + 1
	return anchor.Add(steps * interval)
}

func (service *scheduledBackupService) createScheduled(ctx context.Context, policy config.Backup, passphrase string) error {
	contents, err := CreateBackup(ctx, BackupOptions{ConfigurationPath: service.configurationPath, Passphrase: passphrase})
	if err != nil {
		return err
	}
	summary, err := backup.Inspect(contents)
	if err != nil {
		return err
	}
	directory := service.resolveDirectory(policy.Directory)
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return fmt.Errorf("create backup directory: %w", err)
	}
	name := service.scheduledPrefix() + summary.CreatedAt.UTC().Format("20060102-150405") + ".sablebackup"
	if err := writeLocalBackup(filepath.Join(directory, name), contents); err != nil {
		return err
	}
	if err := service.pruneScheduled(ctx, policy); err != nil {
		return fmt.Errorf("prune scheduled backups after creating %s: %w", name, err)
	}
	return nil
}

func writeLocalBackup(path string, contents []byte) error {
	temporary, err := os.CreateTemp(filepath.Dir(path), ".sable-scheduled-*.tmp")
	if err != nil {
		return fmt.Errorf("create temporary backup: %w", err)
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if err := temporary.Chmod(0o600); err != nil {
		temporary.Close()
		return fmt.Errorf("secure temporary backup: %w", err)
	}
	if _, err := temporary.Write(contents); err != nil {
		temporary.Close()
		return fmt.Errorf("write temporary backup: %w", err)
	}
	if err := temporary.Sync(); err != nil {
		temporary.Close()
		return fmt.Errorf("sync temporary backup: %w", err)
	}
	if err := temporary.Close(); err != nil {
		return fmt.Errorf("close temporary backup: %w", err)
	}
	if err := os.Rename(temporaryPath, path); err != nil {
		return fmt.Errorf("publish scheduled backup: %w", err)
	}
	directory, err := os.Open(filepath.Dir(path))
	if err == nil {
		err = directory.Sync()
		_ = directory.Close()
	}
	if err != nil {
		return fmt.Errorf("sync backup directory: %w", err)
	}
	return nil
}

func (service *scheduledBackupService) pruneScheduled(ctx context.Context, policy config.Backup) error {
	archives, err := service.localBackups(ctx, policy)
	if err != nil {
		return err
	}
	kept := 0
	for _, archive := range archives {
		if !archive.Scheduled {
			continue
		}
		kept++
		if kept <= policy.RetentionCount {
			continue
		}
		path := filepath.Join(service.resolveDirectory(policy.Directory), archive.Name)
		if err := os.Remove(path); err != nil {
			return fmt.Errorf("remove %s: %w", archive.Name, err)
		}
		service.logger.Info("purged scheduled backup", "file", archive.Name)
	}
	return nil
}

func (service *scheduledBackupService) passphrase(ctx context.Context) ([]byte, bool, error) {
	secret, err := service.vault.Get(ctx, scheduledBackupPassphraseSecret)
	if errors.Is(err, auth.ErrNotFound) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, fmt.Errorf("read scheduled backup passphrase: %w", err)
	}
	return secret, true, nil
}

func (service *scheduledBackupService) scheduledPrefix() string {
	name := service.configuration.Current().Config.Cluster.NodeName
	if strings.TrimSpace(name) == "" {
		name = hostname()
	}
	var clean strings.Builder
	for _, character := range strings.ToLower(name) {
		if unicode.IsLetter(character) || unicode.IsDigit(character) {
			clean.WriteRune(character)
		} else if clean.Len() > 0 && !strings.HasSuffix(clean.String(), "-") {
			clean.WriteByte('-')
		}
	}
	node := strings.Trim(clean.String(), "-")
	if node == "" {
		node = "node"
	}
	return "sable-scheduled-" + node + "-"
}

func (service *scheduledBackupService) resolveDirectory(directory string) string {
	if filepath.IsAbs(directory) {
		return filepath.Clean(directory)
	}
	return filepath.Clean(filepath.Join(service.configuration.BaseDirectory(), directory))
}

func (service *scheduledBackupService) snapshot() (config.Backup, time.Time, time.Time, string) {
	service.policyMu.RLock()
	defer service.policyMu.RUnlock()
	return service.policy, service.nextRun, service.lastSuccess, service.lastError
}

func (service *scheduledBackupService) setNextRun(next time.Time) {
	service.policyMu.Lock()
	service.nextRun = next
	service.policyMu.Unlock()
}

func (service *scheduledBackupService) recordScheduledFailure(err error) {
	service.policyMu.Lock()
	service.lastError = err.Error()
	service.policyMu.Unlock()
}

func (service *scheduledBackupService) notify() {
	select {
	case service.wake <- struct{}{}:
	default:
	}
}

func (service *scheduledBackupService) wait(ctx context.Context, delay time.Duration) bool {
	if delay <= 0 {
		select {
		case <-ctx.Done():
			return false
		case <-service.wake:
			return true
		}
	}
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-service.wake:
		return true
	case <-timer.C:
		return true
	}
}
