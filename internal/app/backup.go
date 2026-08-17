package app

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/drudge/sable/internal/backup"
	"github.com/drudge/sable/internal/config"
	"github.com/drudge/sable/internal/store"
	"github.com/drudge/sable/internal/trustanchor"
	"github.com/drudge/sable/internal/version"
	"github.com/drudge/sable/internal/web"
	"github.com/drudge/sable/internal/zone"
)

// Backup archives address material by role rather than by the path it happened
// to occupy on the source node. Restore resolves each role through the
// configuration it is restoring, so a deployment that keeps its certificates
// somewhere else still lands them where its own configuration expects them.
const (
	manualCertificateEntry = "manual/certificate.pem"
	manualPrivateKeyEntry  = "manual/private-key.pem"
	acmeEntryPrefix        = "acme/"
	clusterDataPrefix      = "data/"
	clusterTrustEntry      = "trust-anchor.pem"
)

// Progress reports how far a backup or restore has advanced. Step counts
// completed stages, so a caller can show real movement rather than a spinner
// that says nothing about what is happening.
type Progress struct {
	Stage string
	Step  int
	Total int
}

// ProgressFunc receives progress updates. It is called from the goroutine
// running the operation and must not block for long.
type ProgressFunc func(Progress)

// reporter turns a caller's optional callback into something the capture and
// restore paths can call unconditionally.
type reporter struct {
	report ProgressFunc
	total  int
	step   int
}

func newReporter(report ProgressFunc, total int) *reporter {
	return &reporter{report: report, total: total}
}

// stage announces the work about to begin. The step number reported is the
// count already finished, so a bar starts empty and ends full.
func (progress *reporter) stage(name string) {
	if progress == nil || progress.report == nil {
		return
	}
	progress.report(Progress{Stage: name, Step: progress.step, Total: progress.total})
	progress.step++
}

func (progress *reporter) done(name string) {
	if progress == nil || progress.report == nil {
		return
	}
	progress.report(Progress{Stage: name, Step: progress.total, Total: progress.total})
}

// BackupOptions describes a backup to capture.
type BackupOptions struct {
	// ConfigurationPath names the TOML configuration of the deployment to
	// capture. Everything else is resolved through it.
	ConfigurationPath string
	// Passphrase seals the archive. It is mandatory.
	Passphrase string
	// Sections limits the capture. An empty list captures everything.
	Sections []string
	// Progress, when set, receives a report as each stage begins.
	Progress ProgressFunc
}

// RestoreOptions describes a restore to apply.
type RestoreOptions struct {
	// ConfigurationPath names where the restored configuration is written and
	// where relative paths inside it resolve from. The file need not exist.
	ConfigurationPath string
	// Contents is the sealed archive.
	Contents []byte
	// Passphrase opens the archive.
	Passphrase string
	// DatabaseDriver and DatabaseDSN override the backed-up database settings.
	// A node restored onto different hardware often has to point somewhere
	// else, and without the override its configuration would name a database
	// it cannot reach.
	DatabaseDriver string
	DatabaseDSN    string
	// KeepConfiguration leaves the local configuration file untouched and
	// resolves every restored path through it instead. It is how an operator
	// restores data onto a node whose listeners and storage are already right.
	KeepConfiguration bool
	// Sections limits the restore to part of the archive. An empty list
	// restores every section the archive carries.
	Sections []string
	// Progress, when set, receives a report as each stage begins.
	Progress ProgressFunc
}

// RestoreResult reports what a restore touched so the caller can tell an
// operator what changed and what still needs a restart.
type RestoreResult struct {
	Manifest              backup.Manifest
	Sections              []string
	Zones                 int
	Users                 int
	Roles                 int
	Tokens                int
	Secrets               int
	TrustAnchors          int
	Files                 int
	ConfigurationPath     string
	ConfigurationBackedUp string
	DatabaseDriver        string
	DatabaseDSN           string
}

// CreateBackup captures a complete deployment into a sealed archive. It reads
// the configuration and the database directly rather than going through a
// running server, so it works whether or not Sable is up.
func CreateBackup(ctx context.Context, options BackupOptions) ([]byte, error) {
	if strings.TrimSpace(options.Passphrase) == "" {
		return nil, backup.ErrPassphraseRequired
	}
	sections, err := resolveSections(options.Sections)
	if err != nil {
		return nil, err
	}
	absolutePath, err := config.AbsolutePath(options.ConfigurationPath)
	if err != nil {
		return nil, err
	}
	configuration, err := config.Load(absolutePath)
	if err != nil {
		return nil, err
	}
	baseDirectory := filepath.Dir(absolutePath)

	// One stage per captured section, plus the seal at the end. Sealing is its
	// own stage because Argon2id is by design the slowest step of the whole
	// operation and an operator should see why the bar pauses there.
	progress := newReporter(options.Progress, len(sections)+1)

	archive := backup.Archive{Manifest: backup.Manifest{
		CreatedAt:      time.Now().UTC(),
		SableVersion:   version.Current().Release,
		Hostname:       hostname(),
		DatabaseDriver: configuration.Database.Driver,
		Sections:       sections,
	}}

	if slices.Contains(sections, backup.SectionConfiguration) {
		progress.stage("Reading configuration")
		// The configuration travels as the operator wrote it, comments and
		// all, instead of being re-marshalled from the parsed model.
		contents, err := os.ReadFile(absolutePath)
		if err != nil {
			return nil, fmt.Errorf("read configuration: %w", err)
		}
		archive.Configuration = contents
	}

	if needsDatabase(sections) {
		database, err := store.Open(ctx, configuration.Database.Driver, configuration.Database.DSN)
		if err != nil {
			return nil, err
		}
		defer database.Close()
		if err := captureDatabase(ctx, database, sections, &archive, progress); err != nil {
			return nil, err
		}
	}

	if slices.Contains(sections, backup.SectionSecrets) {
		keyPath := configuration.SecuritySecretKeyPath(baseDirectory)
		key, err := readOptionalFile(keyPath)
		if err != nil {
			return nil, fmt.Errorf("read secret vault key: %w", err)
		}
		if len(key) == 0 && len(archive.Secrets) > 0 {
			return nil, fmt.Errorf("secret vault key %s is missing; the stored secrets could never be opened again", keyPath)
		}
		archive.VaultKey = key
	}

	if slices.Contains(sections, backup.SectionCertificates) {
		progress.stage("Collecting TLS material")
		files, err := captureCertificates(configuration, baseDirectory)
		if err != nil {
			return nil, err
		}
		archive.Files = append(archive.Files, files...)
	}

	if slices.Contains(sections, backup.SectionCluster) {
		progress.stage("Collecting cluster state")
		files, clusterID, err := captureCluster(configuration, baseDirectory)
		if err != nil {
			return nil, err
		}
		archive.Files = append(archive.Files, files...)
		archive.Manifest.ClusterID = clusterID
	}

	progress.stage("Sealing the archive")
	sealed, err := backup.Encode(archive, options.Passphrase)
	if err != nil {
		return nil, err
	}
	progress.done("Backup ready")
	return sealed, nil
}

func captureDatabase(ctx context.Context, database *store.Store, sections []string, archive *backup.Archive, progress *reporter) error {
	if slices.Contains(sections, backup.SectionZones) {
		progress.stage("Collecting zones and records")
		zones, err := database.ListZones(ctx)
		if err != nil {
			return err
		}
		archive.Zones = zones
	}
	if slices.Contains(sections, backup.SectionAuthorization) {
		progress.stage("Collecting users, roles, and tokens")
		authorization, err := database.ExportAuthorizationState(ctx)
		if err != nil {
			return err
		}
		archive.Authorization = authorization
	}
	if slices.Contains(sections, backup.SectionSecrets) {
		progress.stage("Collecting secrets")
		secrets, err := database.ExportSecrets(ctx)
		if err != nil {
			return err
		}
		archive.Secrets = make([]backup.Secret, 0, len(secrets))
		for _, secret := range secrets {
			archive.Secrets = append(archive.Secrets, backup.Secret{
				Name: secret.Name, Ciphertext: secret.Ciphertext, UpdatedAt: secret.UpdatedAt,
			})
		}
	}
	if slices.Contains(sections, backup.SectionTrustAnchors) {
		progress.stage("Collecting DNSSEC trust anchors")
		owners, err := database.TrustAnchorOwners(ctx)
		if err != nil {
			return err
		}
		archive.TrustAnchors = make([]trustanchor.Snapshot, 0, len(owners))
		for _, owner := range owners {
			snapshot, err := database.LoadTrustAnchorSnapshot(ctx, owner)
			if err != nil {
				return err
			}
			archive.TrustAnchors = append(archive.TrustAnchors, snapshot)
		}
	}
	return nil
}

func captureCertificates(configuration config.Config, baseDirectory string) ([]backup.File, error) {
	files := []backup.File{}
	certificatePath, privateKeyPath := configuration.EncryptedDNSCertificatePaths(baseDirectory)
	if configuration.EncryptedDNS.CertificateMode != "acme" {
		for entry, source := range map[string]string{
			manualCertificateEntry: certificatePath,
			manualPrivateKeyEntry:  privateKeyPath,
		} {
			contents, err := readOptionalFile(source)
			if err != nil {
				return nil, fmt.Errorf("read %s: %w", source, err)
			}
			if len(contents) == 0 {
				continue
			}
			files = append(files, backup.File{
				Section: backup.SectionCertificates, Path: entry, Mode: 0o600, Contents: contents,
			})
		}
	}
	acmeDirectory := resolveConfigured(baseDirectory, configuration.EncryptedDNS.ACME.StorageDirectory)
	if acmeDirectory != "" {
		captured, err := captureTree(acmeDirectory, backup.SectionCertificates, acmeEntryPrefix)
		if err != nil {
			return nil, err
		}
		files = append(files, captured...)
	}
	slices.SortFunc(files, func(left, right backup.File) int { return strings.Compare(left.Path, right.Path) })
	return files, nil
}

func captureCluster(configuration config.Config, baseDirectory string) ([]backup.File, string, error) {
	files, err := captureTree(configuration.ClusterDataPath(baseDirectory), backup.SectionCluster, clusterDataPrefix)
	if err != nil {
		return nil, "", err
	}
	if trustPath := configuration.ClusterTrustAnchorPath(baseDirectory); trustPath != "" {
		contents, readErr := readOptionalFile(trustPath)
		if readErr != nil {
			return nil, "", fmt.Errorf("read %s: %w", trustPath, readErr)
		}
		if len(contents) > 0 {
			files = append(files, backup.File{
				Section: backup.SectionCluster, Path: clusterTrustEntry, Mode: 0o600, Contents: contents,
			})
		}
	}
	slices.SortFunc(files, func(left, right backup.File) int { return strings.Compare(left.Path, right.Path) })
	return files, clusterIdentity(files), nil
}

// captureTree walks a directory and records every regular file under it.
func captureTree(directory, section, entryPrefix string) ([]backup.File, error) {
	files := []backup.File{}
	if directory == "" {
		return files, nil
	}
	if _, err := os.Stat(directory); errors.Is(err, fs.ErrNotExist) {
		return files, nil
	}
	err := filepath.WalkDir(directory, func(current string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() || !entry.Type().IsRegular() {
			return nil
		}
		relative, err := filepath.Rel(directory, current)
		if err != nil {
			return err
		}
		contents, err := os.ReadFile(current)
		if err != nil {
			return fmt.Errorf("read %s: %w", current, err)
		}
		mode := fs.FileMode(0o600)
		if info, err := entry.Info(); err == nil {
			mode = info.Mode().Perm()
		}
		files = append(files, backup.File{
			Section:  section,
			Path:     entryPrefix + filepath.ToSlash(relative),
			Mode:     mode,
			Contents: contents,
		})
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("capture %s: %w", directory, err)
	}
	return files, nil
}

// RestoreBackup writes a sealed archive over a deployment. It is written for a
// stopped node: a running Sable holds the configuration watcher and its own
// view of zones, so the caller is expected to restart afterwards.
func RestoreBackup(ctx context.Context, options RestoreOptions) (RestoreResult, error) {
	// Opening the archive is one stage because Argon2id makes it the slowest
	// single step; the rest is one stage per section that is actually applied.
	opening := newReporter(options.Progress, 2)
	opening.stage("Opening the archive")
	archive, err := backup.Decode(options.Contents, options.Passphrase)
	if err != nil {
		return RestoreResult{}, err
	}
	requested, err := restoreSections(archive, options.Sections)
	if err != nil {
		return RestoreResult{}, err
	}
	absolutePath, err := config.AbsolutePath(options.ConfigurationPath)
	if err != nil {
		return RestoreResult{}, err
	}
	baseDirectory := filepath.Dir(absolutePath)

	configurationContents, configuration, err := effectiveConfiguration(archive, options, absolutePath, requested)
	if err != nil {
		return RestoreResult{}, err
	}
	result := RestoreResult{
		Manifest: archive.Manifest, Sections: requested, ConfigurationPath: absolutePath,
		DatabaseDriver: configuration.Database.Driver, DatabaseDSN: configuration.Database.DSN,
	}
	// Now that the archive is open the real section count is known, so the bar
	// switches to a schedule it can actually finish on.
	progress := newReporter(options.Progress, len(requested)+2)
	progress.step = 1

	// Open the database before anything is written. A restore that cannot
	// reach its database should fail while the node is still untouched.
	var database *store.Store
	if needsDatabase(requested) {
		progress.stage("Checking the database")
		database, err = store.Open(ctx, configuration.Database.Driver, configuration.Database.DSN)
		if err != nil {
			return RestoreResult{}, err
		}
		defer database.Close()
	}

	if len(configurationContents) > 0 {
		progress.stage("Writing configuration")
		previousPath, err := replaceConfiguration(absolutePath, configurationContents)
		if err != nil {
			return RestoreResult{}, err
		}
		result.ConfigurationBackedUp = previousPath
	}

	// The vault key lands before the secrets it opens, so a restore that fails
	// midway never leaves ciphertext behind that nothing can decrypt.
	if slices.Contains(requested, backup.SectionSecrets) {
		progress.stage("Restoring secrets and the vault key")
		if len(archive.VaultKey) > 0 {
			keyPath := configuration.SecuritySecretKeyPath(baseDirectory)
			if keyPath == "" {
				return result, errors.New("restored configuration names no security.secret_key_file")
			}
			if err := writeRestoredFile(keyPath, 0o600, archive.VaultKey); err != nil {
				return result, fmt.Errorf("restore secret vault key: %w", err)
			}
		}
		secrets := make([]store.EncryptedSecret, 0, len(archive.Secrets))
		for _, secret := range archive.Secrets {
			secrets = append(secrets, store.EncryptedSecret{
				Name: secret.Name, Ciphertext: secret.Ciphertext, UpdatedAt: secret.UpdatedAt,
			})
		}
		if err := database.ReplaceSecrets(ctx, secrets); err != nil {
			return result, err
		}
		result.Secrets = len(secrets)
	}

	if slices.Contains(requested, backup.SectionZones) {
		progress.stage("Restoring zones and records")
		current, err := database.ListZones(ctx)
		if err != nil {
			return result, err
		}
		if _, err := database.ReplaceZones(ctx, current, zone.Clone(archive.Zones)); err != nil {
			return result, fmt.Errorf("restore zones: %w", err)
		}
		result.Zones = len(archive.Zones)
	}

	if slices.Contains(requested, backup.SectionAuthorization) {
		progress.stage("Restoring users, roles, and tokens")
		if err := database.ReplaceAuthorizationState(ctx, archive.Authorization); err != nil {
			return result, fmt.Errorf("restore authorization: %w", err)
		}
		result.Users = len(archive.Authorization.Users)
		result.Roles = len(archive.Authorization.Roles)
		result.Tokens = len(archive.Authorization.Tokens)
	}

	if slices.Contains(requested, backup.SectionTrustAnchors) {
		progress.stage("Restoring DNSSEC trust anchors")
		for _, snapshot := range archive.TrustAnchors {
			if err := database.SaveTrustAnchorSnapshot(ctx, snapshot); err != nil {
				return result, fmt.Errorf("restore trust anchors: %w", err)
			}
		}
		result.TrustAnchors = len(archive.TrustAnchors)
	}

	if slices.Contains(requested, backup.SectionCertificates) {
		progress.stage("Restoring TLS material")
		written, err := restoreCertificates(archive, configuration, baseDirectory)
		if err != nil {
			return result, err
		}
		result.Files += written
	}

	if slices.Contains(requested, backup.SectionCluster) {
		progress.stage("Restoring cluster state")
		written, err := restoreCluster(archive, configuration, baseDirectory)
		if err != nil {
			return result, err
		}
		result.Files += written
	}
	progress.done("Restore complete")
	return result, nil
}

// effectiveConfiguration decides which configuration governs the restore and
// returns the bytes to write, or nil when the local file stays as it is.
func effectiveConfiguration(archive backup.Archive, options RestoreOptions, absolutePath string, sections []string) ([]byte, config.Config, error) {
	if options.KeepConfiguration || !slices.Contains(sections, backup.SectionConfiguration) {
		configuration, err := config.Load(absolutePath)
		if err != nil {
			return nil, config.Config{}, fmt.Errorf("this restore needs the existing configuration: %w", err)
		}
		return nil, applyDatabaseOverride(configuration, options), nil
	}
	if len(archive.Configuration) == 0 {
		return nil, config.Config{}, errors.New("backup carries no configuration")
	}
	configuration, err := config.Decode(strings.NewReader(string(archive.Configuration)))
	if err != nil {
		return nil, config.Config{}, fmt.Errorf("decode backed-up configuration: %w", err)
	}
	contents := archive.Configuration
	overridden := applyDatabaseOverride(configuration, options)
	if overridden.Database != configuration.Database {
		// Re-marshal so the written configuration names the database the
		// operator asked for rather than the one the source node used.
		rewritten, err := rewriteDatabaseSection(contents, overridden.Database)
		if err != nil {
			return nil, config.Config{}, err
		}
		contents = rewritten
		configuration = overridden
	}
	return contents, configuration, nil
}

func applyDatabaseOverride(configuration config.Config, options RestoreOptions) config.Config {
	if driver := strings.TrimSpace(options.DatabaseDriver); driver != "" {
		configuration.Database.Driver = driver
	}
	if dsn := strings.TrimSpace(options.DatabaseDSN); dsn != "" {
		configuration.Database.DSN = dsn
	}
	return configuration
}

func rewriteDatabaseSection(contents []byte, database config.Database) ([]byte, error) {
	configuration, err := config.Decode(strings.NewReader(string(contents)))
	if err != nil {
		return nil, fmt.Errorf("decode backed-up configuration: %w", err)
	}
	configuration.Database = database
	if err := configuration.Validate(); err != nil {
		return nil, fmt.Errorf("database override is not valid: %w", err)
	}
	encoded, err := config.Marshal(configuration)
	if err != nil {
		return nil, err
	}
	return encoded, nil
}

func restoreCertificates(archive backup.Archive, configuration config.Config, baseDirectory string) (int, error) {
	certificatePath, privateKeyPath := configuration.EncryptedDNSCertificatePaths(baseDirectory)
	acmeDirectory := resolveConfigured(baseDirectory, configuration.EncryptedDNS.ACME.StorageDirectory)
	written := 0
	for _, file := range archive.SectionFiles(backup.SectionCertificates) {
		var destination string
		switch {
		case file.Path == manualCertificateEntry:
			destination = certificatePath
		case file.Path == manualPrivateKeyEntry:
			destination = privateKeyPath
		case strings.HasPrefix(file.Path, acmeEntryPrefix):
			if acmeDirectory == "" {
				continue
			}
			relative, err := safeJoin(acmeDirectory, strings.TrimPrefix(file.Path, acmeEntryPrefix))
			if err != nil {
				return written, err
			}
			destination = relative
		default:
			continue
		}
		if destination == "" {
			continue
		}
		if err := writeRestoredFile(destination, file.Mode, file.Contents); err != nil {
			return written, fmt.Errorf("restore %s: %w", file.Path, err)
		}
		written++
	}
	return written, nil
}

func restoreCluster(archive backup.Archive, configuration config.Config, baseDirectory string) (int, error) {
	dataDirectory := configuration.ClusterDataPath(baseDirectory)
	trustPath := configuration.ClusterTrustAnchorPath(baseDirectory)
	written := 0
	for _, file := range archive.SectionFiles(backup.SectionCluster) {
		var destination string
		switch {
		case file.Path == clusterTrustEntry:
			destination = trustPath
		case strings.HasPrefix(file.Path, clusterDataPrefix):
			if dataDirectory == "" {
				continue
			}
			joined, err := safeJoin(dataDirectory, strings.TrimPrefix(file.Path, clusterDataPrefix))
			if err != nil {
				return written, err
			}
			destination = joined
		default:
			continue
		}
		if destination == "" {
			continue
		}
		if err := writeRestoredFile(destination, file.Mode, file.Contents); err != nil {
			return written, fmt.Errorf("restore %s: %w", file.Path, err)
		}
		written++
	}
	return written, nil
}

// replaceConfiguration writes the restored configuration and keeps the file it
// displaced next to it, so an operator can always get back to the state the
// node booted with.
func replaceConfiguration(absolutePath string, contents []byte) (string, error) {
	if err := os.MkdirAll(filepath.Dir(absolutePath), 0o750); err != nil {
		return "", fmt.Errorf("create configuration directory: %w", err)
	}
	previousPath := ""
	if existing, err := os.ReadFile(absolutePath); err == nil {
		previousPath = absolutePath + ".pre-restore"
		if err := os.WriteFile(previousPath, existing, 0o600); err != nil {
			return "", fmt.Errorf("save displaced configuration: %w", err)
		}
	} else if !errors.Is(err, fs.ErrNotExist) {
		return "", fmt.Errorf("read current configuration: %w", err)
	}
	if err := os.WriteFile(absolutePath, contents, 0o600); err != nil {
		return "", fmt.Errorf("write restored configuration: %w", err)
	}
	return previousPath, nil
}

func writeRestoredFile(destination string, mode fs.FileMode, contents []byte) error {
	if mode.Perm() == 0 {
		mode = 0o600
	}
	if err := os.MkdirAll(filepath.Dir(destination), 0o750); err != nil {
		return fmt.Errorf("create %s: %w", filepath.Dir(destination), err)
	}
	return os.WriteFile(destination, contents, mode.Perm())
}

// safeJoin keeps a restored archive member inside its destination directory.
func safeJoin(directory, relative string) (string, error) {
	cleaned := path.Clean("/" + relative)
	joined := filepath.Join(directory, filepath.FromSlash(strings.TrimPrefix(cleaned, "/")))
	if joined != directory && !strings.HasPrefix(joined, directory+string(os.PathSeparator)) {
		return "", fmt.Errorf("archive member %q escapes %s", relative, directory)
	}
	return joined, nil
}

func resolveSections(requested []string) ([]string, error) {
	if len(requested) == 0 {
		return slices.Clone(backup.AllSections), nil
	}
	sections := make([]string, 0, len(requested))
	for _, section := range requested {
		section = strings.TrimSpace(section)
		if !slices.Contains(backup.AllSections, section) {
			return nil, fmt.Errorf("unknown backup section %q", section)
		}
		if !slices.Contains(sections, section) {
			sections = append(sections, section)
		}
	}
	// Keep the canonical order so restore always applies configuration first.
	ordered := make([]string, 0, len(sections))
	for _, section := range backup.AllSections {
		if slices.Contains(sections, section) {
			ordered = append(ordered, section)
		}
	}
	return ordered, nil
}

func restoreSections(archive backup.Archive, requested []string) ([]string, error) {
	sections, err := resolveSections(requested)
	if err != nil {
		return nil, err
	}
	available := make([]string, 0, len(sections))
	for _, section := range sections {
		if archive.HasSection(section) {
			available = append(available, section)
		} else if len(requested) > 0 {
			return nil, fmt.Errorf("this backup does not carry the %s section", section)
		}
	}
	if len(available) == 0 {
		return nil, errors.New("this backup carries nothing to restore")
	}
	return available, nil
}

func needsDatabase(sections []string) bool {
	for _, section := range []string{
		backup.SectionZones, backup.SectionAuthorization,
		backup.SectionSecrets, backup.SectionTrustAnchors,
	} {
		if slices.Contains(sections, section) {
			return true
		}
	}
	return false
}

func readOptionalFile(path string) ([]byte, error) {
	if path == "" {
		return nil, nil
	}
	contents, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return contents, nil
}

func resolveConfigured(baseDirectory, configured string) string {
	if strings.TrimSpace(configured) == "" {
		return ""
	}
	if filepath.IsAbs(configured) {
		return filepath.Clean(configured)
	}
	return filepath.Clean(filepath.Join(baseDirectory, configured))
}

// clusterIdentity reads the cluster identifier out of the captured manifest so
// the backup can name the cluster it came from without decoding the archive.
func clusterIdentity(files []backup.File) string {
	for _, file := range files {
		if file.Path != clusterDataPrefix+"cluster.json" {
			continue
		}
		return clusterIDFromManifest(file.Contents)
	}
	return ""
}

// consoleBackups adapts the file-driven backup routines to the console. The
// console never chooses sections: an operator downloading a backup from the
// browser is asking for the whole deployment.
type consoleBackups struct {
	configurationPath string
}

func (backups *consoleBackups) CreateBackup(ctx context.Context, passphrase string, progress func(web.BackupProgress)) ([]byte, error) {
	return CreateBackup(ctx, BackupOptions{
		ConfigurationPath: backups.configurationPath,
		Passphrase:        passphrase,
		Progress:          consoleProgress(progress),
	})
}

func (backups *consoleBackups) RestoreBackup(ctx context.Context, contents []byte, passphrase string, keepConfiguration bool, progress func(web.BackupProgress)) (web.BackupSummary, error) {
	result, err := RestoreBackup(ctx, RestoreOptions{
		ConfigurationPath: backups.configurationPath,
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

func consoleProgress(report func(web.BackupProgress)) ProgressFunc {
	if report == nil {
		return nil
	}
	return func(progress Progress) {
		report(web.BackupProgress{Stage: progress.Stage, Step: progress.Step, Total: progress.Total})
	}
}

func clusterIDFromManifest(contents []byte) string {
	var manifest struct {
		ClusterID string `json:"cluster_id"`
	}
	if err := json.Unmarshal(contents, &manifest); err != nil {
		return ""
	}
	return manifest.ClusterID
}

func hostname() string {
	name, err := os.Hostname()
	if err != nil {
		return ""
	}
	return name
}
