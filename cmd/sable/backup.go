package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/term"

	"github.com/drudge/sable/internal/app"
	"github.com/drudge/sable/internal/backup"
)

const backupUsage = `Usage:
  sable backup create [--config sable.toml] [--out file] [--section name]
  sable backup restore [--config sable.toml] [--keep-config] [--section name]
                       [--database-driver name] [--database-dsn dsn] <file>
  sable backup inspect <file>

A backup carries the configuration, zones, users, roles, API tokens, encrypted
secrets and the key that opens them, DNSSEC trust anchors, TLS material, and
cluster membership. It is always sealed with a passphrase. Query logs and
statistics are operational data and are deliberately left out.

The passphrase is read from --passphrase-file, then SABLE_BACKUP_PASSPHRASE,
and finally from the terminal.
`

// passphraseEnvironmentVariable lets automated backups run unattended without
// putting the passphrase on a command line, where it would be visible to every
// process on the host.
const passphraseEnvironmentVariable = "SABLE_BACKUP_PASSPHRASE"

func backupCommand(arguments []string) error {
	if len(arguments) == 0 {
		fmt.Print(backupUsage)
		return nil
	}
	switch arguments[0] {
	case "create":
		return backupCreateCommand(arguments[1:])
	case "restore":
		return backupRestoreCommand(arguments[1:])
	case "inspect":
		return backupInspectCommand(arguments[1:])
	case "help", "-h", "--help":
		fmt.Print(backupUsage)
		return nil
	default:
		return fmt.Errorf("unknown backup command %q", arguments[0])
	}
}

func backupCreateCommand(arguments []string) error {
	flags := flag.NewFlagSet("backup create", flag.ContinueOnError)
	configurationPath := flags.String("config", "sable.toml", "path to the TOML configuration")
	output := flags.String("out", "", "file to write (default sable-backup-<host>-<timestamp>.sablebackup)")
	passphraseFile := flags.String("passphrase-file", "", "read the backup passphrase from this file")
	var sections stringListFlag
	flags.Var(&sections, "section", "capture only this section (repeatable): "+strings.Join(backup.AllSections, ", "))
	if err := flags.Parse(arguments); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("usage: sable backup create [--config sable.toml] [--out file] [--section name]")
	}

	passphrase, err := readPassphrase(*passphraseFile, true)
	if err != nil {
		return err
	}
	contents, err := app.CreateBackup(context.Background(), app.BackupOptions{
		ConfigurationPath: *configurationPath,
		Passphrase:        passphrase,
		Sections:          sections,
	})
	if err != nil {
		return err
	}
	destination := *output
	if destination == "" {
		destination = defaultBackupName()
	}
	// The archive holds the secret vault key, so it is written where only its
	// owner can read it even before it leaves the machine.
	if err := os.WriteFile(destination, contents, 0o600); err != nil {
		return fmt.Errorf("write backup: %w", err)
	}
	absolute, err := filepath.Abs(destination)
	if err != nil {
		absolute = destination
	}
	fmt.Printf("Backup written: %s (%s)\n", absolute, humanBytes(len(contents)))
	fmt.Println("Keep the passphrase somewhere safe; without it this file cannot be restored.")
	return nil
}

func backupRestoreCommand(arguments []string) error {
	flags := flag.NewFlagSet("backup restore", flag.ContinueOnError)
	configurationPath := flags.String("config", "sable.toml", "path to the TOML configuration to write and resolve paths from")
	passphraseFile := flags.String("passphrase-file", "", "read the backup passphrase from this file")
	keepConfiguration := flags.Bool("keep-config", false, "leave the local configuration in place and restore data through it")
	databaseDriver := flags.String("database-driver", "", "override the backed-up database driver")
	databaseDSN := flags.String("database-dsn", "", "override the backed-up database DSN")
	var sections stringListFlag
	flags.Var(&sections, "section", "restore only this section (repeatable): "+strings.Join(backup.AllSections, ", "))
	if err := flags.Parse(arguments); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	if flags.NArg() != 1 {
		return errors.New("usage: sable backup restore [options] <file>")
	}

	contents, err := os.ReadFile(flags.Arg(0))
	if err != nil {
		return fmt.Errorf("read backup: %w", err)
	}
	summary, err := backup.Inspect(contents)
	if err != nil {
		return err
	}
	fmt.Printf("Restoring the backup taken from %s on %s (Sable %s).\n",
		describeHostname(summary.Hostname), summary.CreatedAt.Local().Format(time.RFC1123), describeVersion(summary.SableVersion))

	passphrase, err := readPassphrase(*passphraseFile, false)
	if err != nil {
		return err
	}
	result, err := app.RestoreBackup(context.Background(), app.RestoreOptions{
		ConfigurationPath: *configurationPath,
		Contents:          contents,
		Passphrase:        passphrase,
		DatabaseDriver:    *databaseDriver,
		DatabaseDSN:       *databaseDSN,
		KeepConfiguration: *keepConfiguration,
		Sections:          sections,
	})
	if err != nil {
		return err
	}
	printRestoreResult(result)
	return nil
}

func backupInspectCommand(arguments []string) error {
	flags := flag.NewFlagSet("backup inspect", flag.ContinueOnError)
	if err := flags.Parse(arguments); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	if flags.NArg() != 1 {
		return errors.New("usage: sable backup inspect <file>")
	}
	contents, err := os.ReadFile(flags.Arg(0))
	if err != nil {
		return fmt.Errorf("read backup: %w", err)
	}
	summary, err := backup.Inspect(contents)
	if err != nil {
		return err
	}
	fmt.Printf("Created:  %s\nHost:     %s\nSable:    %s\nFormat:   %d\nSize:     %s\n",
		summary.CreatedAt.Local().Format(time.RFC1123), describeHostname(summary.Hostname),
		describeVersion(summary.SableVersion), summary.FormatVersion, humanBytes(len(contents)))
	fmt.Println("The section list and contents need the passphrase; restore reports them.")
	return nil
}

func printRestoreResult(result app.RestoreResult) {
	fmt.Printf("Restored: %s\n", strings.Join(result.Sections, ", "))
	if result.Zones > 0 {
		fmt.Printf("  zones:         %d\n", result.Zones)
	}
	if result.Users > 0 || result.Roles > 0 || result.Tokens > 0 {
		fmt.Printf("  authorization: %d users, %d roles, %d API tokens\n", result.Users, result.Roles, result.Tokens)
	}
	if result.Secrets > 0 {
		fmt.Printf("  secrets:       %d\n", result.Secrets)
	}
	if result.TrustAnchors > 0 {
		fmt.Printf("  trust anchors: %d\n", result.TrustAnchors)
	}
	if result.Files > 0 {
		fmt.Printf("  files:         %d\n", result.Files)
	}
	fmt.Printf("Configuration: %s\n", result.ConfigurationPath)
	if result.ConfigurationBackedUp != "" {
		fmt.Printf("Previous configuration kept at: %s\n", result.ConfigurationBackedUp)
	}
	fmt.Printf("Database: %s %s\n", result.DatabaseDriver, result.DatabaseDSN)
	fmt.Println("Start Sable to bring the restored deployment up.")
}

// readPassphrase resolves the passphrase without ever putting it on a command
// line. Creating a backup confirms the passphrase, because a typo there is only
// discovered when the backup is needed.
func readPassphrase(passphraseFile string, confirm bool) (string, error) {
	if passphraseFile != "" {
		contents, err := os.ReadFile(passphraseFile)
		if err != nil {
			return "", fmt.Errorf("read passphrase file: %w", err)
		}
		passphrase := strings.TrimRight(string(contents), "\r\n")
		if passphrase == "" {
			return "", errors.New("passphrase file is empty")
		}
		return passphrase, nil
	}
	if passphrase := os.Getenv(passphraseEnvironmentVariable); passphrase != "" {
		return passphrase, nil
	}
	if !term.IsTerminal(int(os.Stdin.Fd())) {
		return "", fmt.Errorf("no passphrase available; use --passphrase-file or set %s", passphraseEnvironmentVariable)
	}
	passphrase, err := promptPassphrase("Backup passphrase: ")
	if err != nil {
		return "", err
	}
	if passphrase == "" {
		return "", backup.ErrPassphraseRequired
	}
	if confirm {
		again, err := promptPassphrase("Confirm passphrase: ")
		if err != nil {
			return "", err
		}
		if again != passphrase {
			return "", errors.New("the passphrases do not match")
		}
	}
	return passphrase, nil
}

func promptPassphrase(prompt string) (string, error) {
	fmt.Fprint(os.Stderr, prompt)
	entered, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return "", fmt.Errorf("read passphrase: %w", err)
	}
	return strings.TrimSpace(string(entered)), nil
}

func defaultBackupName() string {
	host, err := os.Hostname()
	if err != nil || host == "" {
		host = "sable"
	}
	host = strings.ReplaceAll(strings.Split(host, ".")[0], string(os.PathSeparator), "-")
	return fmt.Sprintf("sable-backup-%s-%s.sablebackup", host, time.Now().Format("20060102-150405"))
}

func describeHostname(hostname string) string {
	if strings.TrimSpace(hostname) == "" {
		return "an unnamed host"
	}
	return hostname
}

func describeVersion(release string) string {
	if strings.TrimSpace(release) == "" {
		return "unknown"
	}
	return release
}

func humanBytes(size int) string {
	switch {
	case size >= 1<<20:
		return fmt.Sprintf("%.1f MiB", float64(size)/(1<<20))
	case size >= 1<<10:
		return fmt.Sprintf("%.1f KiB", float64(size)/(1<<10))
	default:
		return fmt.Sprintf("%d B", size)
	}
}
