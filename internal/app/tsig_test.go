package app

import (
	"context"
	"encoding/base64"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/drudge/sable/internal/config"
)

func TestMigrateTSIGSecretsEmptiesTheConfigurationFile(t *testing.T) {
	ctx := context.Background()
	secret := base64.StdEncoding.EncodeToString(make([]byte, 32))
	configuration := config.Defaults()
	configuration.TSIGKeys = []config.TSIGKey{{
		Name: "transfer-key.", Algorithm: "hmac-sha256.", Secret: secret,
	}}
	manager := newTestConfigurationManager(t, configuration)
	secrets := newTestTSIGStore()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	migrateTSIGSecrets(ctx, manager, secrets, logger)

	contents, err := os.ReadFile(filepath.Join(manager.BaseDirectory(), "sable.toml"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(contents), secret) {
		t.Fatal("sable.toml still contains the TSIG secret after migration")
	}
	if keys := manager.Current().Config.TSIGKeys; len(keys) != 1 || keys[0].Secret != "" {
		t.Fatalf("configured keys after migration = %+v", keys)
	}
	stored, found := secrets.Secret(ctx, "transfer-key.")
	if !found || stored != secret {
		t.Fatalf("vault secret = %q, found = %v", stored, found)
	}

	// The migrated configuration must still hand the DNS runtime a usable key,
	// or transfers would start failing the moment the secret moved.
	hydrated := hydrateTSIGKeys(ctx, secrets, manager.Current().Config, logger)
	runtime := runtimeTSIGKeys(hydrated.TSIGKeys)
	if len(runtime) != 1 || runtime[0].Secret != secret {
		t.Fatalf("runtime TSIG keys = %+v", runtime)
	}
}

func TestMigrateTSIGSecretsLeavesAnAlreadyMigratedFileAlone(t *testing.T) {
	ctx := context.Background()
	configuration := config.Defaults()
	configuration.TSIGKeys = []config.TSIGKey{{Name: "transfer-key.", Algorithm: "hmac-sha256."}}
	manager := newTestConfigurationManager(t, configuration)
	revision := manager.Current().Revision

	migrateTSIGSecrets(ctx, manager, newTestTSIGStore(), slog.New(slog.NewTextHandler(io.Discard, nil)))

	if manager.Current().Revision != revision {
		t.Fatal("an ordinary boot rewrote the configuration file")
	}
}
