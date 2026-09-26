package app

import (
	"context"
	"crypto/ecdsa"
	"crypto/x509"
	"errors"
	"fmt"
	"sync"

	"github.com/drudge/sable/internal/auth"
	"github.com/drudge/sable/internal/webpush"
)

// pushKeyEntry names the vault entry holding the key Sable signs browser
// pushes with. Browsers bind each subscription to that key, so it is made
// once and kept, sealed like every other secret.
const pushKeyEntry = "insights:push_key"

// pushKeyStore hands out the push signing key, making it the first time a
// browser asks to subscribe.
type pushKeyStore struct {
	vault secretVault
	mu    sync.Mutex
	key   *ecdsa.PrivateKey
}

func newPushKeyStore(vault secretVault) *pushKeyStore {
	return &pushKeyStore{vault: vault}
}

// PushKey returns the signing key, making and sealing one if there is none.
func (store *pushKeyStore) PushKey(ctx context.Context) (*ecdsa.PrivateKey, error) {
	if store == nil || store.vault == nil {
		return nil, errors.New("secret vault is unavailable")
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.key != nil {
		return store.key, nil
	}
	sealed, err := store.vault.Get(ctx, pushKeyEntry)
	switch {
	case err == nil:
		key, err := x509.ParseECPrivateKey(sealed)
		if err != nil {
			return nil, fmt.Errorf("read push key: %w", err)
		}
		store.key = key
		return key, nil
	case !errors.Is(err, auth.ErrNotFound):
		return nil, fmt.Errorf("read push key: %w", err)
	}
	key, err := webpush.GenerateKey()
	if err != nil {
		return nil, fmt.Errorf("make push key: %w", err)
	}
	encoded, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("encode push key: %w", err)
	}
	if err := store.vault.Put(ctx, pushKeyEntry, encoded); err != nil {
		return nil, fmt.Errorf("store push key: %w", err)
	}
	store.key = key
	return key, nil
}

// Sealed returns the key as the vault keeps it, for the cluster to hand to
// every replica, or nothing when no browser has asked for one yet. Unlike
// PushKey it never makes a key, since the cluster state is read every second.
func (store *pushKeyStore) Sealed(ctx context.Context) ([]byte, error) {
	if store == nil || store.vault == nil {
		return nil, errors.New("secret vault is unavailable")
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.key != nil {
		return x509.MarshalECPrivateKey(store.key)
	}
	sealed, err := store.vault.Get(ctx, pushKeyEntry)
	switch {
	case errors.Is(err, auth.ErrNotFound):
		return nil, nil
	case err != nil:
		return nil, fmt.Errorf("read push key: %w", err)
	}
	key, err := x509.ParseECPrivateKey(sealed)
	if err != nil {
		return nil, fmt.Errorf("read push key: %w", err)
	}
	store.key = key
	return sealed, nil
}

// Replace keeps the key the cluster's primary signs with, in place of any
// this node made. Browsers bind each subscription to the key they subscribed
// with, so a node that takes over sending has to sign with the same one.
func (store *pushKeyStore) Replace(ctx context.Context, sealed []byte) error {
	if store == nil || store.vault == nil {
		return errors.New("secret vault is unavailable")
	}
	key, err := x509.ParseECPrivateKey(sealed)
	if err != nil {
		return fmt.Errorf("read replicated push key: %w", err)
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.key == nil {
		if current, err := store.vault.Get(ctx, pushKeyEntry); err == nil {
			store.key, _ = x509.ParseECPrivateKey(current)
		}
	}
	if store.key != nil && store.key.Equal(key) {
		return nil
	}
	if err := store.vault.Put(ctx, pushKeyEntry, sealed); err != nil {
		return fmt.Errorf("store push key: %w", err)
	}
	store.key = key
	return nil
}
