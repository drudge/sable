//go:build linux

package install

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"github.com/drudge/sable/internal/certificates"
)

const initialCertificateValidity = 365 * 24 * time.Hour

func SystemService(ctx context.Context, options Options) (Result, error) {
	if os.Geteuid() != 0 {
		return Result{}, errors.New("install must be run as root")
	}
	paths := layoutForOptions(options)
	certificateNames, hostname := initialCertificateNames(options.CertificateNames)
	if err := exec.CommandContext(ctx, "systemctl", "--version").Run(); err != nil {
		return Result{}, errors.New("systemd is required to install the Sable service")
	}
	if err := ensureServiceUser(ctx, paths.dataDirectory); err != nil {
		return Result{}, err
	}
	if err := os.MkdirAll(paths.configurationDir, 0o750); err != nil {
		return Result{}, fmt.Errorf("create configuration directory: %w", err)
	}
	if err := os.MkdirAll(paths.dataDirectory, 0o750); err != nil {
		return Result{}, fmt.Errorf("create data directory: %w", err)
	}
	if err := installExecutable(paths.binaryPath); err != nil {
		return Result{}, err
	}
	if paths.serviceBinaryPath != paths.binaryPath {
		if err := installExecutable(paths.serviceBinaryPath); err != nil {
			return Result{}, fmt.Errorf("install web-updateable service executable: %w", err)
		}
	}
	if err := installInitialConfiguration(ctx, paths, certificateNames); err != nil {
		return Result{}, err
	}
	if err := writeAtomic(paths.servicePath, []byte(systemdUnit(paths)), 0o644); err != nil {
		return Result{}, fmt.Errorf("install systemd service: %w", err)
	}
	if err := run(ctx, "chown", "-R", serviceUser+":"+serviceUser, paths.configurationDir, paths.dataDirectory); err != nil {
		return Result{}, fmt.Errorf("set Sable directory ownership: %w", err)
	}
	if err := run(ctx, "systemctl", "daemon-reload"); err != nil {
		return Result{}, fmt.Errorf("reload systemd: %w", err)
	}
	if err := run(ctx, "systemctl", "enable", ServiceName); err != nil {
		return Result{}, fmt.Errorf("enable Sable service: %w", err)
	}
	if options.Start {
		if err := run(ctx, "systemctl", "restart", ServiceName); err != nil {
			return Result{}, fmt.Errorf("start Sable service: %w", err)
		}
	}
	return Result{
		BinaryPath: paths.binaryPath, ServiceBinaryPath: paths.serviceBinaryPath,
		ConfigurationPath: paths.configurationPath, DataDirectory: paths.dataDirectory,
		ConsoleHost: consoleHost(certificateNames, hostname), Started: options.Start, WebUpdates: options.WebUpdates,
	}, nil
}

func ensureServiceUser(ctx context.Context, homeDirectory string) error {
	if exec.CommandContext(ctx, "id", "-u", serviceUser).Run() == nil {
		return nil
	}
	if err := run(ctx, "useradd", "--system", "--user-group", "--home-dir", homeDirectory,
		"--no-create-home", "--shell", "/usr/sbin/nologin", serviceUser); err != nil {
		return fmt.Errorf("create Sable service user: %w", err)
	}
	return nil
}

func installExecutable(destination string) error {
	source, err := os.Executable()
	if err != nil {
		return fmt.Errorf("locate running Sable executable: %w", err)
	}
	sourceInfo, err := os.Stat(source)
	if err != nil {
		return fmt.Errorf("inspect running Sable executable: %w", err)
	}
	if destinationInfo, destinationErr := os.Stat(destination); destinationErr == nil && os.SameFile(sourceInfo, destinationInfo) {
		return nil
	}
	input, err := os.Open(source)
	if err != nil {
		return fmt.Errorf("open running Sable executable: %w", err)
	}
	defer input.Close()
	if err := os.MkdirAll(filepath.Dir(destination), 0o755); err != nil {
		return fmt.Errorf("create binary directory: %w", err)
	}
	temporary, err := os.CreateTemp(filepath.Dir(destination), ".sable-install-*")
	if err != nil {
		return fmt.Errorf("create temporary executable: %w", err)
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if _, err := io.Copy(temporary, input); err != nil {
		temporary.Close()
		return fmt.Errorf("copy Sable executable: %w", err)
	}
	if err := temporary.Chmod(0o755); err != nil {
		temporary.Close()
		return fmt.Errorf("set Sable executable permissions: %w", err)
	}
	if err := temporary.Sync(); err != nil {
		temporary.Close()
		return fmt.Errorf("sync Sable executable: %w", err)
	}
	if err := temporary.Close(); err != nil {
		return fmt.Errorf("close Sable executable: %w", err)
	}
	if err := os.Rename(temporaryPath, destination); err != nil {
		return fmt.Errorf("replace Sable executable: %w", err)
	}
	return nil
}

func installInitialConfiguration(ctx context.Context, paths layout, certificateNames []string) error {
	if _, err := os.Stat(paths.configurationPath); err == nil {
		return nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("inspect existing configuration: %w", err)
	}
	manager := certificates.New(nil, slog.New(slog.NewTextHandler(io.Discard, nil)), paths.configurationDir)
	if _, err := manager.GenerateSelfSigned(ctx, certificates.ManualCertificateOptions{
		Names: certificateNames, StorageDirectory: filepath.Join("tls", "manual"), ValidFor: initialCertificateValidity,
	}); err != nil {
		return fmt.Errorf("generate initial HTTPS certificate: %w", err)
	}
	if err := writeAtomic(paths.configurationPath, []byte(initialConfiguration(paths)), 0o600); err != nil {
		return fmt.Errorf("install initial configuration: %w", err)
	}
	return nil
}

func writeAtomic(path string, contents []byte, mode os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	temporary, err := os.CreateTemp(filepath.Dir(path), ".sable-install-*")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if err := temporary.Chmod(mode); err != nil {
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
	return os.Rename(temporaryPath, path)
}

func run(ctx context.Context, name string, arguments ...string) error {
	command := exec.CommandContext(ctx, name, arguments...)
	command.Stdout = os.Stdout
	command.Stderr = os.Stderr
	return command.Run()
}
