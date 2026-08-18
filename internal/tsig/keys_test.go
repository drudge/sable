package tsig

import (
	"context"
	"encoding/base64"
	"errors"
	"strings"
	"testing"

	"github.com/drudge/sable/internal/config"
)

type memoryVault struct {
	values  map[string][]byte
	putFail bool
}

func newMemoryVault() *memoryVault { return &memoryVault{values: make(map[string][]byte)} }

func (vault *memoryVault) Put(_ context.Context, name string, value []byte) error {
	if vault.putFail {
		return errors.New("vault is unavailable")
	}
	vault.values[name] = append([]byte(nil), value...)
	return nil
}

func (vault *memoryVault) Get(_ context.Context, name string) ([]byte, error) {
	value, found := vault.values[name]
	if !found {
		return nil, errors.New("not found")
	}
	return value, nil
}

func (vault *memoryVault) Delete(_ context.Context, name string) error {
	delete(vault.values, name)
	return nil
}

func testSecret(size int) string {
	material := make([]byte, size)
	for index := range material {
		material[index] = byte(index + 1)
	}
	return base64.StdEncoding.EncodeToString(material)
}

func TestMigrateMovesSecretsOutOfConfiguration(t *testing.T) {
	t.Parallel()

	vault := newMemoryVault()
	store := NewStore(vault)
	secret := testSecret(32)
	configuration := config.Config{TSIGKeys: []config.TSIGKey{
		{Name: "transfer-key.", Algorithm: "hmac-sha256.", Secret: secret},
		{Name: "update-key.", Algorithm: "hmac-sha512."},
	}}
	if !Pending(configuration) {
		t.Fatal("Pending() = false with a secret still in the configuration")
	}
	migrated, err := store.Migrate(context.Background(), &configuration)
	if err != nil {
		t.Fatalf("Migrate() error = %v", err)
	}
	if migrated != 1 {
		t.Fatalf("Migrate() = %d, want 1", migrated)
	}
	if configuration.TSIGKeys[0].Secret != "" {
		t.Fatal("Migrate() left the secret in the configuration")
	}
	if Pending(configuration) {
		t.Fatal("Pending() = true after a complete migration")
	}
	stored, found := store.Secret(context.Background(), "transfer-key")
	if !found || stored != secret {
		t.Fatalf("Secret() = %q, found = %v", stored, found)
	}
	// A second pass has nothing left to do, so an ordinary boot never rewrites
	// the configuration file.
	migrated, err = store.Migrate(context.Background(), &configuration)
	if err != nil || migrated != 0 {
		t.Fatalf("second Migrate() = %d, error = %v", migrated, err)
	}
}

func TestMigrateReportsAVaultFailure(t *testing.T) {
	t.Parallel()

	vault := newMemoryVault()
	vault.putFail = true
	configuration := config.Config{TSIGKeys: []config.TSIGKey{
		{Name: "transfer-key.", Algorithm: "hmac-sha256.", Secret: testSecret(32)},
	}}
	if _, err := NewStore(vault).Migrate(context.Background(), &configuration); err == nil {
		t.Fatal("Migrate() error = nil with an unavailable vault")
	}
	if configuration.TSIGKeys[0].Secret == "" {
		t.Fatal("Migrate() discarded the secret it could not store")
	}
}

func TestHydrateFillsSecretsAndNamesTheGaps(t *testing.T) {
	t.Parallel()

	store := NewStore(newMemoryVault())
	secret := testSecret(32)
	if err := store.PutSecret(context.Background(), "transfer-key.", secret); err != nil {
		t.Fatalf("PutSecret() error = %v", err)
	}
	keys := []config.TSIGKey{
		{Name: "transfer-key.", Algorithm: "hmac-sha256."},
		{Name: "orphan-key.", Algorithm: "hmac-sha256."},
	}
	hydrated, missing := store.Hydrate(context.Background(), keys)
	if hydrated[0].Secret != secret {
		t.Fatalf("hydrated secret = %q", hydrated[0].Secret)
	}
	if hydrated[1].Secret != "" {
		t.Fatal("a key with no vault entry was given a secret")
	}
	if len(missing) != 1 || missing[0] != "orphan-key." {
		t.Fatalf("missing = %v", missing)
	}
	// Hydration must not write back through the caller's slice, or the
	// configuration manager would marshal the secret straight back into TOML.
	if keys[0].Secret != "" {
		t.Fatal("Hydrate() mutated the configured keys")
	}
}

func TestPutSecretRejectsWeakMaterial(t *testing.T) {
	t.Parallel()

	store := NewStore(newMemoryVault())
	if err := store.PutSecret(context.Background(), "weak.", testSecret(8)); err == nil {
		t.Fatal("PutSecret() accepted a secret below 128 bits")
	}
	if err := store.PutSecret(context.Background(), "weak.", "not base64!"); err == nil {
		t.Fatal("PutSecret() accepted a secret that is not base64")
	}
}

func TestGenerateSecretSizesToTheAlgorithm(t *testing.T) {
	t.Parallel()

	for algorithm, want := range map[string]int{
		"":             32,
		"hmac-sha256.": 32,
		"hmac-sha384.": 48,
		"hmac-sha512.": 64,
	} {
		secret, err := GenerateSecret(algorithm)
		if err != nil {
			t.Fatalf("GenerateSecret(%q) error = %v", algorithm, err)
		}
		decoded, err := base64.StdEncoding.DecodeString(secret)
		if err != nil {
			t.Fatalf("GenerateSecret(%q) = %q, which is not base64", algorithm, secret)
		}
		if len(decoded) != want {
			t.Fatalf("GenerateSecret(%q) produced %d bytes, want %d", algorithm, len(decoded), want)
		}
	}
}

func TestForgetSecretRemovesTheVaultEntry(t *testing.T) {
	t.Parallel()

	vault := newMemoryVault()
	store := NewStore(vault)
	if err := store.PutSecret(context.Background(), "retired.", testSecret(32)); err != nil {
		t.Fatalf("PutSecret() error = %v", err)
	}
	if err := store.ForgetSecret(context.Background(), "retired."); err != nil {
		t.Fatalf("ForgetSecret() error = %v", err)
	}
	if _, found := store.Secret(context.Background(), "retired."); found {
		t.Fatal("Secret() still reports a forgotten key")
	}
	for name := range vault.values {
		if strings.Contains(name, "retired") {
			t.Fatalf("vault kept %q after the key was forgotten", name)
		}
	}
}
