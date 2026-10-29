package app

import (
	"context"
	"errors"
	"fmt"
	"strings"
)

// abuseCHKeyEntry names the vault entry holding the abuse.ch Auth-Key. Block
// list URLs carry a placeholder in its place, so sable.toml, its backups, and
// the console never show the key.
const abuseCHKeyEntry = "blocking:abusech_auth_key"

// abuseCHKeyStore reads and writes the abuse.ch Auth-Key through the encrypted
// vault.
type abuseCHKeyStore struct {
	vault secretVault
}

func newAbuseCHKeyStore(vault secretVault) *abuseCHKeyStore {
	return &abuseCHKeyStore{vault: vault}
}

// Put replaces the stored key.
func (store *abuseCHKeyStore) Put(ctx context.Context, key string) error {
	if store == nil || store.vault == nil {
		return errors.New("secret vault is unavailable")
	}
	key = strings.TrimSpace(key)
	if key == "" {
		return errors.New("an abuse.ch Auth-Key is required")
	}
	if err := store.vault.Put(ctx, abuseCHKeyEntry, []byte(key)); err != nil {
		return fmt.Errorf("store abuse.ch Auth-Key: %w", err)
	}
	return nil
}

// Get returns the stored key, or false when none was ever saved or it was
// cleared.
func (store *abuseCHKeyStore) Get(ctx context.Context) (string, bool) {
	if store == nil || store.vault == nil {
		return "", false
	}
	key, err := store.vault.Get(ctx, abuseCHKeyEntry)
	if err != nil || len(key) == 0 {
		return "", false
	}
	return string(key), true
}

// Clear retires the key. The vault has no delete, so an empty value is written,
// which reads back as not set.
func (store *abuseCHKeyStore) Clear(ctx context.Context) error {
	if store == nil || store.vault == nil {
		return errors.New("secret vault is unavailable")
	}
	if err := store.vault.Put(ctx, abuseCHKeyEntry, nil); err != nil {
		return fmt.Errorf("clear abuse.ch Auth-Key: %w", err)
	}
	return nil
}

// Lookup adapts Get to the block-list updater, which only needs the key.
func (store *abuseCHKeyStore) Lookup(ctx context.Context) string {
	key, _ := store.Get(ctx)
	return key
}
