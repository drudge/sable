package app

import (
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/drudge/sable/internal/config"
)

func TestQueryLogWorkerChangeAllowsEnabledToggle(t *testing.T) {
	t.Parallel()

	active := config.QueryLog{
		Enabled: true, BufferSize: 64, BatchSize: 8,
		FlushInterval: config.Duration{Duration: time.Second},
		Retention:     config.Duration{Duration: 24 * time.Hour},
	}
	candidate := active
	candidate.Enabled = false
	if err := queryLogWorkerChange(active, candidate); err != nil {
		t.Fatalf("queryLogWorkerChange() error = %v, want hot toggle", err)
	}
}

func TestLogWorkerChangesAllowRetentionUpdates(t *testing.T) {
	t.Parallel()

	queryActive := config.Defaults().QueryLog
	queryCandidate := queryActive
	queryCandidate.Retention.Duration = 30 * 24 * time.Hour
	if err := queryLogWorkerChange(queryActive, queryCandidate); err != nil {
		t.Fatalf("queryLogWorkerChange() error = %v, want hot retention change", err)
	}

	serverActive := config.Defaults().ServerLog
	serverCandidate := serverActive
	serverCandidate.Retention.Duration = 90 * 24 * time.Hour
	if err := serverLogWorkerChange(serverActive, serverCandidate); err != nil {
		t.Fatalf("serverLogWorkerChange() error = %v, want hot retention change", err)
	}
}

func TestServerLogLevelMapsValidatedConfiguration(t *testing.T) {
	t.Parallel()

	for name, want := range map[string]slog.Level{
		"debug": slog.LevelDebug,
		"info":  slog.LevelInfo,
		"warn":  slog.LevelWarn,
		"error": slog.LevelError,
	} {
		if got := serverLogLevel(name); got != want {
			t.Errorf("serverLogLevel(%q) = %s, want %s", name, got, want)
		}
	}
}

func TestCheckConfigurationCompilesManagedBlockLists(t *testing.T) {
	t.Parallel()

	directory := t.TempDir()
	configurationPath := filepath.Join(directory, "sable.toml")
	contents := `
[[blocking.lists]]
name = "managed"
path = "managed.txt"
format = "domains"
`
	if err := os.WriteFile(configurationPath, []byte(contents), 0o600); err != nil {
		t.Fatalf("WriteFile(config) error = %v", err)
	}
	if _, err := CheckConfiguration(configurationPath); err == nil {
		t.Fatal("CheckConfiguration() error = nil for missing managed list")
	}
	if err := os.WriteFile(filepath.Join(directory, "managed.txt"), []byte("ads.example\n"), 0o600); err != nil {
		t.Fatalf("WriteFile(list) error = %v", err)
	}
	if _, err := CheckConfiguration(configurationPath); err != nil {
		t.Fatalf("CheckConfiguration() error = %v", err)
	}
}

func TestQueryLogWorkerChangeRequiresRestartForBufferChange(t *testing.T) {
	t.Parallel()

	active := config.Defaults().QueryLog
	candidate := active
	candidate.BufferSize++
	if err := queryLogWorkerChange(active, candidate); err == nil {
		t.Fatal("queryLogWorkerChange() error = nil, want restart requirement")
	}
}

func TestCheckConfigurationValidatesEncryptedDNSCertificate(t *testing.T) {
	t.Parallel()

	directory := t.TempDir()
	configurationPath := filepath.Join(directory, "sable.toml")
	contents := `
[encrypted_dns]
dot_listen = ["127.0.0.1:8853"]
certificate_file = "missing.pem"
private_key_file = "missing-key.pem"
`
	if err := os.WriteFile(configurationPath, []byte(contents), 0o600); err != nil {
		t.Fatalf("WriteFile(config) error = %v", err)
	}
	if _, err := CheckConfiguration(configurationPath); err == nil {
		t.Fatal("CheckConfiguration() error = nil for missing TLS certificate")
	}
}
