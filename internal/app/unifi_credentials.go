package app

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/drudge/sable/internal/unifi"
)

// unifiCredentialSecret names the vault entry holding controller credentials.
// They are sealed with the node's secret key and never written to TOML.
const unifiCredentialSecret = "unifi:credentials"

type secretVault interface {
	Put(context.Context, string, []byte) error
	Get(context.Context, string) ([]byte, error)
}

// unifiCredentialStore reads and writes controller credentials through the
// encrypted secret vault, mirroring how ACME provider credentials are handled.
type unifiCredentialStore struct {
	vault secretVault
}

func newUniFiCredentialStore(vault secretVault) *unifiCredentialStore {
	return &unifiCredentialStore{vault: vault}
}

// Put replaces the stored credentials. Blank fields keep their previous value
// so the console can re-save settings without asking for the secret again.
func (store *unifiCredentialStore) Put(ctx context.Context, credentials unifi.Credentials) error {
	if store == nil || store.vault == nil {
		return errors.New("secret vault is unavailable")
	}
	current, _ := store.Get(ctx)
	merged := unifi.Credentials{
		APIKey:   firstNonBlank(credentials.APIKey, current.APIKey),
		Username: firstNonBlank(credentials.Username, current.Username),
		Password: firstNonBlank(credentials.Password, current.Password),
	}
	if !merged.Configured() {
		return errors.New("an API key or a local account username and password are required")
	}
	encoded, err := json.Marshal(merged)
	if err != nil {
		return fmt.Errorf("encode UniFi credentials: %w", err)
	}
	if err := store.vault.Put(ctx, unifiCredentialSecret, encoded); err != nil {
		return fmt.Errorf("store UniFi credentials: %w", err)
	}
	return nil
}

// Replace stores exactly what it is given, discarding anything held before. The
// wizard uses this when the operator switches authentication modes.
func (store *unifiCredentialStore) Replace(ctx context.Context, credentials unifi.Credentials) error {
	if store == nil || store.vault == nil {
		return errors.New("secret vault is unavailable")
	}
	if !credentials.Configured() {
		return errors.New("an API key or a local account username and password are required")
	}
	encoded, err := json.Marshal(credentials)
	if err != nil {
		return fmt.Errorf("encode UniFi credentials: %w", err)
	}
	if err := store.vault.Put(ctx, unifiCredentialSecret, encoded); err != nil {
		return fmt.Errorf("store UniFi credentials: %w", err)
	}
	return nil
}

// Clear retires the stored credentials. The vault has no delete, so an empty
// payload is written instead: it fails Configured() and therefore reads back as
// "not set up".
func (store *unifiCredentialStore) Clear(ctx context.Context) error {
	if store == nil || store.vault == nil {
		return errors.New("secret vault is unavailable")
	}
	if err := store.vault.Put(ctx, unifiCredentialSecret, []byte("{}")); err != nil {
		return fmt.Errorf("clear UniFi credentials: %w", err)
	}
	return nil
}

// Get returns the stored credentials. A missing or unreadable entry reports
// false rather than an error so callers can present setup guidance.
func (store *unifiCredentialStore) Get(ctx context.Context) (unifi.Credentials, bool) {
	if store == nil || store.vault == nil {
		return unifi.Credentials{}, false
	}
	encoded, err := store.vault.Get(ctx, unifiCredentialSecret)
	if err != nil {
		return unifi.Credentials{}, false
	}
	var credentials unifi.Credentials
	if json.Unmarshal(encoded, &credentials) != nil || !credentials.Configured() {
		return unifi.Credentials{}, false
	}
	return credentials, true
}

func firstNonBlank(candidate, fallback string) string {
	if strings.TrimSpace(candidate) != "" {
		return candidate
	}
	return fallback
}
