package app

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/drudge/sable/internal/backup"
	"github.com/drudge/sable/internal/config"
	"github.com/drudge/sable/internal/secrets"
	"github.com/drudge/sable/internal/store"
	"github.com/drudge/sable/internal/trustanchor"
	"github.com/drudge/sable/internal/zone"
)

const backupTestPassphrase = "a passphrase worth keeping"

// newBackupDeployment lays down a node with every kind of state a backup has
// to carry, then returns the path of its configuration.
func newBackupDeployment(t *testing.T) string {
	t.Helper()
	ctx := context.Background()
	directory := t.TempDir()
	configurationPath := filepath.Join(directory, "sable.toml")

	configuration := config.Defaults()
	configuration.Database.DSN = filepath.Join(directory, "data", "sable.db")
	configuration.Security.SecretKeyFile = filepath.Join(directory, "data", "sable.key")
	configuration.Cluster.DataDirectory = filepath.Join(directory, "data", "cluster")
	configuration.EncryptedDNS.CertificateMode = "manual"
	configuration.EncryptedDNS.CertificateFile = filepath.Join(directory, "tls", "certificate.pem")
	configuration.EncryptedDNS.PrivateKeyFile = filepath.Join(directory, "tls", "private-key.pem")
	configuration.EncryptedDNS.ACME.StorageDirectory = filepath.Join(directory, "data", "tls", "acme")
	writeBackupConfiguration(t, configurationPath, configuration)

	database, err := store.Open(ctx, configuration.Database.Driver, configuration.Database.DSN)
	if err != nil {
		t.Fatalf("store.Open() error = %v", err)
	}
	defer database.Close()

	if _, err := database.ReplaceZones(ctx, nil, []zone.Zone{{
		ID: "zone-1", Name: "example.test", Type: "primary", DefaultTTL: 300,
		Records: []zone.Record{{Name: "example.test", Type: "A", Value: "192.0.2.10", TTL: 300}},
	}}); err != nil {
		t.Fatalf("ReplaceZones() error = %v", err)
	}
	if _, err := database.CreateUser(ctx, "admin", "Administrator", "admin@example.test", "hashed", []string{"Administrator"}, time.Now()); err != nil {
		t.Fatalf("CreateUser() error = %v", err)
	}
	vault, err := secrets.Open(configuration.SecuritySecretKeyPath(directory), database)
	if err != nil {
		t.Fatalf("secrets.Open() error = %v", err)
	}
	if err := vault.Put(ctx, "dnssec/example.test", []byte("private key material")); err != nil {
		t.Fatalf("vault.Put() error = %v", err)
	}
	if err := database.SaveTrustAnchorSnapshot(ctx, trustanchor.Snapshot{
		Status:  trustanchor.Status{Owner: ".", Initialized: true, OriginalTTLSeconds: 172800},
		Anchors: []trustanchor.Anchor{{Owner: ".", KeyID: "20326", DNSKEY: "example", State: "valid"}},
	}); err != nil {
		t.Fatalf("SaveTrustAnchorSnapshot() error = %v", err)
	}

	writeBackupFile(t, configuration.EncryptedDNS.CertificateFile, "certificate contents")
	writeBackupFile(t, configuration.EncryptedDNS.PrivateKeyFile, "private key contents")
	writeBackupFile(t, filepath.Join(configuration.EncryptedDNS.ACME.StorageDirectory, "account.key"), "acme account key")
	writeBackupFile(t, filepath.Join(configuration.Cluster.DataDirectory, "cluster.json"), `{"cluster_id":"cluster-abc"}`)
	return configurationPath
}

func writeBackupConfiguration(t *testing.T, path string, configuration config.Config) {
	t.Helper()
	encoded, err := config.Marshal(configuration)
	if err != nil {
		t.Fatalf("config.Marshal() error = %v", err)
	}
	if err := os.WriteFile(path, encoded, 0o600); err != nil {
		t.Fatalf("write configuration: %v", err)
	}
}

func writeBackupFile(t *testing.T, path, contents string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		t.Fatalf("create %s: %v", filepath.Dir(path), err)
	}
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

// freshConfigurationPath returns a path inside an empty directory, standing in
// for a node that has never run Sable.
func freshConfigurationPath(t *testing.T) string {
	t.Helper()
	return filepath.Join(t.TempDir(), "sable.toml")
}

func TestBackupRestoresOntoAFreshInstance(t *testing.T) {
	ctx := context.Background()
	sourcePath := newBackupDeployment(t)

	sealed, err := CreateBackup(ctx, BackupOptions{ConfigurationPath: sourcePath, Passphrase: backupTestPassphrase})
	if err != nil {
		t.Fatalf("CreateBackup() error = %v", err)
	}

	targetPath := freshConfigurationPath(t)
	targetDirectory := filepath.Dir(targetPath)
	result, err := RestoreBackup(ctx, RestoreOptions{
		ConfigurationPath: targetPath,
		Contents:          sealed,
		Passphrase:        backupTestPassphrase,
		// A fresh node keeps its own database file rather than reaching for
		// the path the source node used.
		DatabaseDSN: filepath.Join(targetDirectory, "data", "sable.db"),
	})
	if err != nil {
		t.Fatalf("RestoreBackup() error = %v", err)
	}
	if result.Zones != 1 || result.Users != 1 || result.Secrets != 1 || result.TrustAnchors != 1 {
		t.Fatalf("restore result = %+v", result)
	}
	if result.ConfigurationBackedUp != "" {
		t.Fatalf("displaced configuration = %q, want none on a fresh node", result.ConfigurationBackedUp)
	}

	restored, err := config.Load(targetPath)
	if err != nil {
		t.Fatalf("config.Load() error = %v", err)
	}
	if restored.Database.DSN != filepath.Join(targetDirectory, "data", "sable.db") {
		t.Fatalf("restored DSN = %q, want the override", restored.Database.DSN)
	}

	database, err := store.Open(ctx, restored.Database.Driver, restored.Database.DSN)
	if err != nil {
		t.Fatalf("store.Open() error = %v", err)
	}
	defer database.Close()

	zones, err := database.ListZones(ctx)
	if err != nil {
		t.Fatalf("ListZones() error = %v", err)
	}
	if len(zones) != 1 || zones[0].Name != "example.test" || len(zones[0].Records) != 1 {
		t.Fatalf("restored zones = %+v", zones)
	}
	users, err := database.ListUsers(ctx)
	if err != nil {
		t.Fatalf("ListUsers() error = %v", err)
	}
	if len(users) != 1 || users[0].Username != "admin" {
		t.Fatalf("restored users = %+v", users)
	}

	// The whole point of carrying the vault key: a secret sealed on the source
	// node has to open on the restored one.
	vault, err := secrets.Open(restored.SecuritySecretKeyPath(targetDirectory), database)
	if err != nil {
		t.Fatalf("secrets.Open() error = %v", err)
	}
	plaintext, err := vault.Get(ctx, "dnssec/example.test")
	if err != nil {
		t.Fatalf("vault.Get() error = %v", err)
	}
	if string(plaintext) != "private key material" {
		t.Fatalf("restored secret = %q", plaintext)
	}

	snapshot, err := database.LoadTrustAnchorSnapshot(ctx, ".")
	if err != nil {
		t.Fatalf("LoadTrustAnchorSnapshot() error = %v", err)
	}
	if !snapshot.Status.Initialized || len(snapshot.Anchors) != 1 {
		t.Fatalf("restored trust anchors = %+v", snapshot)
	}

	certificate, err := os.ReadFile(restored.EncryptedDNS.CertificateFile)
	if err != nil {
		t.Fatalf("read restored certificate: %v", err)
	}
	if string(certificate) != "certificate contents" {
		t.Fatalf("restored certificate = %q", certificate)
	}
	acmeAccount, err := os.ReadFile(filepath.Join(restored.EncryptedDNS.ACME.StorageDirectory, "account.key"))
	if err != nil {
		t.Fatalf("read restored ACME account key: %v", err)
	}
	if string(acmeAccount) != "acme account key" {
		t.Fatalf("restored ACME account key = %q", acmeAccount)
	}
	manifest, err := os.ReadFile(filepath.Join(restored.Cluster.DataDirectory, "cluster.json"))
	if err != nil {
		t.Fatalf("read restored cluster manifest: %v", err)
	}
	if !strings.Contains(string(manifest), "cluster-abc") {
		t.Fatalf("restored cluster manifest = %q", manifest)
	}
}

func TestBackupManifestNamesTheSourceCluster(t *testing.T) {
	ctx := context.Background()
	sealed, err := CreateBackup(ctx, BackupOptions{
		ConfigurationPath: newBackupDeployment(t), Passphrase: backupTestPassphrase,
	})
	if err != nil {
		t.Fatalf("CreateBackup() error = %v", err)
	}
	archive, err := backup.Decode(sealed, backupTestPassphrase)
	if err != nil {
		t.Fatalf("backup.Decode() error = %v", err)
	}
	if archive.Manifest.ClusterID != "cluster-abc" {
		t.Fatalf("cluster id = %q, want cluster-abc", archive.Manifest.ClusterID)
	}
	if archive.Manifest.DatabaseDriver != "sqlite" {
		t.Fatalf("database driver = %q", archive.Manifest.DatabaseDriver)
	}
}

func TestRestoreKeepsLocalConfigurationWhenAsked(t *testing.T) {
	ctx := context.Background()
	sealed, err := CreateBackup(ctx, BackupOptions{
		ConfigurationPath: newBackupDeployment(t), Passphrase: backupTestPassphrase,
	})
	if err != nil {
		t.Fatalf("CreateBackup() error = %v", err)
	}

	targetPath := freshConfigurationPath(t)
	targetDirectory := filepath.Dir(targetPath)
	local := config.Defaults()
	local.Server.HTTPListen = "127.0.0.1:15380"
	local.Database.DSN = filepath.Join(targetDirectory, "local.db")
	local.Security.SecretKeyFile = filepath.Join(targetDirectory, "local.key")
	local.Cluster.DataDirectory = filepath.Join(targetDirectory, "cluster")
	writeBackupConfiguration(t, targetPath, local)

	result, err := RestoreBackup(ctx, RestoreOptions{
		ConfigurationPath: targetPath, Contents: sealed,
		Passphrase: backupTestPassphrase, KeepConfiguration: true,
	})
	if err != nil {
		t.Fatalf("RestoreBackup() error = %v", err)
	}
	if result.ConfigurationBackedUp != "" {
		t.Fatalf("displaced configuration = %q, want none", result.ConfigurationBackedUp)
	}
	kept, err := config.Load(targetPath)
	if err != nil {
		t.Fatalf("config.Load() error = %v", err)
	}
	if kept.Server.HTTPListen != "127.0.0.1:15380" {
		t.Fatalf("http listen = %q, want the local value", kept.Server.HTTPListen)
	}
	if _, err := os.Stat(filepath.Join(targetDirectory, "local.db")); err != nil {
		t.Fatalf("restore did not use the local database: %v", err)
	}
}

func TestRestoreSavesTheConfigurationItDisplaces(t *testing.T) {
	ctx := context.Background()
	sealed, err := CreateBackup(ctx, BackupOptions{
		ConfigurationPath: newBackupDeployment(t), Passphrase: backupTestPassphrase,
	})
	if err != nil {
		t.Fatalf("CreateBackup() error = %v", err)
	}
	targetPath := freshConfigurationPath(t)
	targetDirectory := filepath.Dir(targetPath)
	local := config.Defaults()
	local.Server.HTTPListen = "127.0.0.1:15380"
	local.Database.DSN = filepath.Join(targetDirectory, "local.db")
	writeBackupConfiguration(t, targetPath, local)

	result, err := RestoreBackup(ctx, RestoreOptions{
		ConfigurationPath: targetPath, Contents: sealed, Passphrase: backupTestPassphrase,
		DatabaseDSN: filepath.Join(targetDirectory, "restored.db"),
	})
	if err != nil {
		t.Fatalf("RestoreBackup() error = %v", err)
	}
	if result.ConfigurationBackedUp == "" {
		t.Fatal("restore discarded the configuration it displaced")
	}
	previous, err := config.Load(result.ConfigurationBackedUp)
	if err != nil {
		t.Fatalf("config.Load() error = %v", err)
	}
	if previous.Server.HTTPListen != "127.0.0.1:15380" {
		t.Fatalf("saved http listen = %q", previous.Server.HTTPListen)
	}
}

func TestRestoreRejectsTheWrongPassphrase(t *testing.T) {
	ctx := context.Background()
	sealed, err := CreateBackup(ctx, BackupOptions{
		ConfigurationPath: newBackupDeployment(t), Passphrase: backupTestPassphrase,
	})
	if err != nil {
		t.Fatalf("CreateBackup() error = %v", err)
	}
	targetPath := freshConfigurationPath(t)
	if _, err := RestoreBackup(ctx, RestoreOptions{
		ConfigurationPath: targetPath, Contents: sealed, Passphrase: "not it",
	}); !errors.Is(err, backup.ErrWrongPassphrase) {
		t.Fatalf("RestoreBackup() error = %v, want ErrWrongPassphrase", err)
	}
	if _, err := os.Stat(targetPath); err == nil {
		t.Fatal("a failed restore wrote a configuration anyway")
	}
}

func TestCreateBackupRequiresAPassphrase(t *testing.T) {
	if _, err := CreateBackup(context.Background(), BackupOptions{
		ConfigurationPath: newBackupDeployment(t),
	}); !errors.Is(err, backup.ErrPassphraseRequired) {
		t.Fatalf("CreateBackup() error = %v, want ErrPassphraseRequired", err)
	}
}

func TestBackupSectionsLimitWhatTravels(t *testing.T) {
	ctx := context.Background()
	sealed, err := CreateBackup(ctx, BackupOptions{
		ConfigurationPath: newBackupDeployment(t), Passphrase: backupTestPassphrase,
		Sections: []string{backup.SectionZones, backup.SectionConfiguration},
	})
	if err != nil {
		t.Fatalf("CreateBackup() error = %v", err)
	}
	archive, err := backup.Decode(sealed, backupTestPassphrase)
	if err != nil {
		t.Fatalf("backup.Decode() error = %v", err)
	}
	if len(archive.Secrets) != 0 || len(archive.VaultKey) != 0 || len(archive.Files) != 0 {
		t.Fatalf("archive carries more than the requested sections: %+v", archive.Manifest.Sections)
	}
	if _, err := RestoreBackup(ctx, RestoreOptions{
		ConfigurationPath: freshConfigurationPath(t), Contents: sealed,
		Passphrase: backupTestPassphrase, Sections: []string{backup.SectionSecrets},
	}); err == nil || !strings.Contains(err.Error(), "does not carry") {
		t.Fatalf("RestoreBackup() error = %v, want a missing section rejection", err)
	}
}

func TestRestoreRefusesToLeaveTheDestinationDirectory(t *testing.T) {
	ctx := context.Background()
	directory := t.TempDir()
	targetPath := filepath.Join(directory, "sable.toml")
	configuration := config.Defaults()
	configuration.Database.DSN = filepath.Join(directory, "sable.db")
	configuration.Cluster.DataDirectory = filepath.Join(directory, "cluster")
	encoded, err := config.Marshal(configuration)
	if err != nil {
		t.Fatalf("config.Marshal() error = %v", err)
	}
	// An archive whose member climbs out of its section is rejected while it is
	// still being written, so a crafted path never reaches a restoring node.
	if _, err := backup.Encode(backup.Archive{
		Manifest: backup.Manifest{
			FormatVersion: backup.FormatVersion,
			Sections:      []string{backup.SectionConfiguration, backup.SectionCluster},
		},
		Configuration: encoded,
		Files: []backup.File{{
			Section: backup.SectionCluster, Path: "data/../../escaped.json",
			Mode: 0o600, Contents: []byte("nope"),
		}},
	}, backupTestPassphrase); err == nil || !strings.Contains(err.Error(), "escapes") {
		t.Fatalf("backup.Encode() error = %v, want an escape rejection", err)
	}

	// A member that only escapes once it is joined to the destination is
	// caught by the restore side instead.
	sealed, err := backup.Encode(backup.Archive{
		Manifest: backup.Manifest{
			FormatVersion: backup.FormatVersion,
			Sections:      []string{backup.SectionConfiguration, backup.SectionCluster},
		},
		Configuration: encoded,
		Files: []backup.File{{
			Section: backup.SectionCluster, Path: "data/nested/manifest.json",
			Mode: 0o600, Contents: []byte(`{"cluster_id":"nested"}`),
		}},
	}, backupTestPassphrase)
	if err != nil {
		t.Fatalf("backup.Encode() error = %v", err)
	}
	if _, err := RestoreBackup(ctx, RestoreOptions{
		ConfigurationPath: targetPath, Contents: sealed, Passphrase: backupTestPassphrase,
	}); err != nil {
		t.Fatalf("RestoreBackup() error = %v", err)
	}
	nested := filepath.Join(directory, "cluster", "nested", "manifest.json")
	if _, err := os.Stat(nested); err != nil {
		t.Fatalf("nested cluster member was not restored: %v", err)
	}
	if _, err := os.Stat(filepath.Join(filepath.Dir(directory), "escaped.json")); err == nil {
		t.Fatal("restore wrote outside the destination directory")
	}
}

func TestBackupReportsEveryStageInOrder(t *testing.T) {
	ctx := context.Background()
	reports := []Progress{}
	sealed, err := CreateBackup(ctx, BackupOptions{
		ConfigurationPath: newBackupDeployment(t), Passphrase: backupTestPassphrase,
		Progress: func(progress Progress) { reports = append(reports, progress) },
	})
	if err != nil {
		t.Fatalf("CreateBackup() error = %v", err)
	}
	if len(reports) < 2 {
		t.Fatalf("progress reports = %+v", reports)
	}
	// Every section plus the seal, and the bar has to start empty and end full.
	if first := reports[0]; first.Step != 0 || first.Total != len(backup.AllSections)+1 {
		t.Fatalf("first report = %+v, want step 0 of %d", first, len(backup.AllSections)+1)
	}
	last := reports[len(reports)-1]
	if last.Step != last.Total {
		t.Fatalf("last report = %+v, want a finished bar", last)
	}
	for index, report := range reports {
		if report.Stage == "" {
			t.Fatalf("report %d names no stage: %+v", index, report)
		}
		if index > 0 && report.Step < reports[index-1].Step {
			t.Fatalf("progress went backwards at %d: %+v then %+v", index, reports[index-1], report)
		}
	}

	restoreReports := []Progress{}
	if _, err := RestoreBackup(ctx, RestoreOptions{
		ConfigurationPath: freshConfigurationPath(t), Contents: sealed, Passphrase: backupTestPassphrase,
		Progress: func(progress Progress) { restoreReports = append(restoreReports, progress) },
	}); err != nil {
		t.Fatalf("RestoreBackup() error = %v", err)
	}
	if len(restoreReports) < 2 {
		t.Fatalf("restore progress reports = %+v", restoreReports)
	}
	if first := restoreReports[0]; first.Step != 0 {
		t.Fatalf("first restore report = %+v, want an empty bar", first)
	}
	if last := restoreReports[len(restoreReports)-1]; last.Step != last.Total {
		t.Fatalf("last restore report = %+v, want a finished bar", last)
	}
}

func TestBackupWithoutAProgressCallbackStillRuns(t *testing.T) {
	if _, err := CreateBackup(context.Background(), BackupOptions{
		ConfigurationPath: newBackupDeployment(t), Passphrase: backupTestPassphrase,
	}); err != nil {
		t.Fatalf("CreateBackup() error = %v", err)
	}
}
