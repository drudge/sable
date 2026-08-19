package app

import (
	"context"
	"errors"
	"fmt"
	"strings"
)

// oidcClientSecretEntry names the vault entry holding the OpenID Connect client
// secret. Like TSIG secrets and ACME provider credentials it is sealed with the
// node's secret key, so sable.toml, its backups, and every replica's copy of
// the runtime configuration stay free of anything worth stealing.
const oidcClientSecretEntry = "oidc:client_secret"

// oidcSecretStore reads and writes the client secret through the encrypted
// vault.
type oidcSecretStore struct {
	vault secretVault
}

func newOIDCSecretStore(vault secretVault) *oidcSecretStore {
	return &oidcSecretStore{vault: vault}
}

// Put replaces the stored secret. A blank value keeps whatever is already
// there, so the console can re-save the rest of the provider settings without
// asking the operator to paste the secret again.
func (store *oidcSecretStore) Put(ctx context.Context, secret string) error {
	if store == nil || store.vault == nil {
		return errors.New("secret vault is unavailable")
	}
	trimmed := strings.TrimSpace(secret)
	if trimmed == "" {
		if existing, _ := store.Get(ctx); existing != "" {
			return nil
		}
		return errors.New("a client secret is required")
	}
	if err := store.vault.Put(ctx, oidcClientSecretEntry, []byte(trimmed)); err != nil {
		return fmt.Errorf("store OIDC client secret: %w", err)
	}
	return nil
}

// Get returns the stored secret. A vault that has never held one reports an
// empty string rather than an error, because that is the ordinary state of a
// deployment where single sign-on was never configured.
func (store *oidcSecretStore) Get(ctx context.Context) (string, error) {
	if store == nil || store.vault == nil {
		return "", errors.New("secret vault is unavailable")
	}
	secret, err := store.vault.Get(ctx, oidcClientSecretEntry)
	if err != nil || len(secret) == 0 {
		return "", nil
	}
	return string(secret), nil
}

// Forget clears the secret when single sign-on is removed, so a deployment that
// stops using a provider does not keep its credential lying around.
func (store *oidcSecretStore) Forget(ctx context.Context) error {
	if store == nil || store.vault == nil {
		return errors.New("secret vault is unavailable")
	}
	if err := store.vault.Put(ctx, oidcClientSecretEntry, []byte("")); err != nil {
		return fmt.Errorf("clear OIDC client secret: %w", err)
	}
	return nil
}
