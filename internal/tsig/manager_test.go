package tsig

import (
	"context"
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/drudge/sable/internal/config"
	"github.com/pelletier/go-toml/v2"
)

func newTestManager(t *testing.T, initial config.Config) (*Manager, *config.Manager, *memoryVault) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "sable.toml")
	encoded, err := toml.Marshal(initial)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, encoded, 0o600); err != nil {
		t.Fatal(err)
	}
	configuration := config.NewManager(path, initial, func(context.Context, config.Config, config.Config) error { return nil })
	vault := newMemoryVault()
	return NewManager(configuration, NewStore(vault)), configuration, vault
}

func TestSaveGeneratesASecretForANewKey(t *testing.T) {
	t.Parallel()

	manager, configuration, _ := newTestManager(t, config.Defaults())
	result, err := manager.Save(context.Background(), Request{Name: "transfer-key", Algorithm: "hmac-sha512"})
	if err != nil {
		t.Fatalf("Save() error = %v", err)
	}
	if !result.Created || !result.Generated || result.Secret == "" {
		t.Fatalf("Save() = %+v", result)
	}
	if result.Name != "transfer-key." {
		t.Fatalf("Save() name = %q, want the canonical DNS name", result.Name)
	}
	decoded, err := base64.StdEncoding.DecodeString(result.Secret)
	if err != nil || len(decoded) != 64 {
		t.Fatalf("generated secret = %q (%d bytes)", result.Secret, len(decoded))
	}
	keys := configuration.Current().Config.TSIGKeys
	if len(keys) != 1 || keys[0].Name != "transfer-key." || keys[0].Algorithm != "hmac-sha512." {
		t.Fatalf("configured keys = %+v", keys)
	}
	if keys[0].Secret != "" {
		t.Fatal("Save() wrote the secret into the configuration")
	}
}

func TestSaveNeverWritesTheSecretToDisk(t *testing.T) {
	t.Parallel()

	manager, configuration, _ := newTestManager(t, config.Defaults())
	result, err := manager.Save(context.Background(), Request{Name: "transfer-key", Algorithm: "hmac-sha256"})
	if err != nil {
		t.Fatalf("Save() error = %v", err)
	}
	contents, err := os.ReadFile(filepath.Join(configuration.BaseDirectory(), "sable.toml"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(contents), result.Secret) {
		t.Fatal("the configuration file on disk contains the TSIG secret")
	}
}

func TestSaveAcceptsAnOperatorSuppliedSecret(t *testing.T) {
	t.Parallel()

	manager, _, _ := newTestManager(t, config.Defaults())
	supplied := testSecret(32)
	result, err := manager.Save(context.Background(), Request{
		Name: "transfer-key", Algorithm: "hmac-sha256", Secret: supplied,
	})
	if err != nil {
		t.Fatalf("Save() error = %v", err)
	}
	// Only a generated secret is echoed back: one the operator already has does
	// not need showing.
	if result.Generated || result.Secret != "" {
		t.Fatalf("Save() = %+v", result)
	}
	stored, found := manager.secrets.Secret(context.Background(), "transfer-key.")
	if !found || stored != supplied {
		t.Fatalf("stored secret = %q, found = %v", stored, found)
	}
}

func TestSaveKeepsTheSecretUnlessRotationIsAsked(t *testing.T) {
	t.Parallel()

	manager, _, _ := newTestManager(t, config.Defaults())
	if _, err := manager.Save(context.Background(), Request{
		Name: "transfer-key", Algorithm: "hmac-sha256", Secret: testSecret(32),
	}); err != nil {
		t.Fatalf("Save() error = %v", err)
	}
	original, _ := manager.secrets.Secret(context.Background(), "transfer-key.")

	// Changing the algorithm alone must not disturb the shared secret, or the
	// other end of the transfer would stop matching without being told.
	result, err := manager.Save(context.Background(), Request{Name: "transfer-key", Algorithm: "hmac-sha384"})
	if err != nil {
		t.Fatalf("Save() error = %v", err)
	}
	if result.Created || result.Generated {
		t.Fatalf("Save() = %+v", result)
	}
	if kept, _ := manager.secrets.Secret(context.Background(), "transfer-key."); kept != original {
		t.Fatal("Save() replaced the secret when only the algorithm changed")
	}

	rotated, err := manager.Save(context.Background(), Request{
		Name: "transfer-key", Algorithm: "hmac-sha384", Rotate: true,
	})
	if err != nil {
		t.Fatalf("Save() error = %v", err)
	}
	if !rotated.Generated || rotated.Secret == "" || rotated.Secret == original {
		t.Fatalf("rotation = %+v", rotated)
	}
	if stored, _ := manager.secrets.Secret(context.Background(), "transfer-key."); stored != rotated.Secret {
		t.Fatal("rotation did not reach the vault")
	}
}

func TestSaveRejectsBadInput(t *testing.T) {
	t.Parallel()

	manager, _, _ := newTestManager(t, config.Defaults())
	for name, request := range map[string]Request{
		"no name":           {Name: "  ", Algorithm: "hmac-sha256"},
		"unknown algorithm": {Name: "transfer-key", Algorithm: "hmac-md5"},
		"weak secret":       {Name: "transfer-key", Algorithm: "hmac-sha256", Secret: testSecret(8)},
	} {
		if _, err := manager.Save(context.Background(), request); err == nil {
			t.Fatalf("Save() accepted %s", name)
		}
	}
}

func TestDeleteRemovesTheKeyAndItsSecret(t *testing.T) {
	t.Parallel()

	manager, configuration, vault := newTestManager(t, config.Defaults())
	if _, err := manager.Save(context.Background(), Request{Name: "transfer-key", Algorithm: "hmac-sha256"}); err != nil {
		t.Fatalf("Save() error = %v", err)
	}
	if err := manager.Delete(context.Background(), "transfer-key"); err != nil {
		t.Fatalf("Delete() error = %v", err)
	}
	if keys := configuration.Current().Config.TSIGKeys; len(keys) != 0 {
		t.Fatalf("configured keys = %+v", keys)
	}
	if len(vault.values) != 0 {
		t.Fatalf("vault still holds %v", vault.values)
	}
	if err := manager.Delete(context.Background(), "transfer-key"); err == nil {
		t.Fatal("Delete() reported success for a key that is not configured")
	}
}

func TestDeleteKeepsTheSecretWhenTheConfigurationRefuses(t *testing.T) {
	t.Parallel()

	// A zone referencing the key makes the configuration apply fail. The
	// secret has to survive that, because the server still needs it.
	path := filepath.Join(t.TempDir(), "sable.toml")
	initial := config.Defaults()
	encoded, err := toml.Marshal(initial)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, encoded, 0o600); err != nil {
		t.Fatal(err)
	}
	refuse := false
	configuration := config.NewManager(path, initial, func(_ context.Context, _, _ config.Config) error {
		if refuse {
			return errors.New("authoritative zone example.test references unknown TSIG key")
		}
		return nil
	})
	vault := newMemoryVault()
	manager := NewManager(configuration, NewStore(vault))
	if _, err := manager.Save(context.Background(), Request{Name: "transfer-key", Algorithm: "hmac-sha256"}); err != nil {
		t.Fatalf("Save() error = %v", err)
	}

	refuse = true
	if err := manager.Delete(context.Background(), "transfer-key"); err == nil {
		t.Fatal("Delete() succeeded while a zone still referenced the key")
	}
	if _, found := manager.secrets.Secret(context.Background(), "transfer-key."); !found {
		t.Fatal("Delete() destroyed a secret the server still needs")
	}
	if keys := configuration.Current().Config.TSIGKeys; len(keys) != 1 {
		t.Fatalf("configured keys = %+v", keys)
	}
}

func TestKeysReportWhetherASecretIsStored(t *testing.T) {
	t.Parallel()

	initial := config.Defaults()
	initial.TSIGKeys = []config.TSIGKey{{Name: "orphan-key.", Algorithm: "hmac-sha256."}}
	manager, _, _ := newTestManager(t, initial)
	keys := manager.Keys(context.Background())
	if len(keys) != 1 || keys[0].Configured {
		t.Fatalf("Keys() = %+v", keys)
	}
	if _, err := manager.Save(context.Background(), Request{Name: "orphan-key", Algorithm: "hmac-sha256"}); err != nil {
		t.Fatalf("Save() error = %v", err)
	}
	if keys := manager.Keys(context.Background()); len(keys) != 1 || !keys[0].Configured {
		t.Fatalf("Keys() after Save = %+v", keys)
	}
}
