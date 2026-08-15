package secrets

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

type memoryStore struct{ values map[string]string }

func (store *memoryStore) PutEncryptedSecret(_ context.Context, name, ciphertext string, _ time.Time) error {
	store.values[name] = ciphertext
	return nil
}

func (store *memoryStore) EncryptedSecret(_ context.Context, name string) (string, error) {
	value, found := store.values[name]
	if !found {
		return "", errors.New("not found")
	}
	return value, nil
}

func TestVaultEncryptsAndAuthenticatesSecrets(t *testing.T) {
	t.Parallel()

	keyPath := filepath.Join(t.TempDir(), "keys", "sable.key")
	store := &memoryStore{values: make(map[string]string)}
	vault, err := Open(keyPath, store)
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	if err := vault.Put(context.Background(), "acme/cloudflare", []byte("provider-token")); err != nil {
		t.Fatalf("Put() error = %v", err)
	}
	if store.values["acme/cloudflare"] == "provider-token" {
		t.Fatal("secret was stored in plaintext")
	}
	plaintext, err := vault.Get(context.Background(), "acme/cloudflare")
	if err != nil {
		t.Fatalf("Get() error = %v", err)
	}
	if string(plaintext) != "provider-token" {
		t.Fatalf("Get() = %q", plaintext)
	}
	info, err := os.Stat(keyPath)
	if err != nil {
		t.Fatalf("Stat(key) error = %v", err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("key permissions = %o, want 600", info.Mode().Perm())
	}
	store.values["acme/cloudflare"] += "A"
	if _, err := vault.Get(context.Background(), "acme/cloudflare"); err == nil {
		t.Fatal("Get() error = nil for tampered ciphertext")
	}
}
