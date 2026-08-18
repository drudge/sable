// Package tsig keeps TSIG shared secrets out of the configuration file.
//
// A key has two halves. The name and algorithm are plain identifiers: zones
// reference them, cluster members agree on them, and they belong in TOML. The
// secret is credential material, so it lives in the encrypted vault next to
// DNSSEC private keys and ACME provider credentials. Splitting them this way
// keeps sable.toml, its backups, and every replica's copy of the runtime
// configuration free of anything worth stealing.
package tsig

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/drudge/sable/internal/config"
	"github.com/miekg/dns"
)

// secretPrefix namespaces vault entries, matching the "public-tls/acme/" style
// the certificate manager already uses.
const secretPrefix = "tsig/"

// Vault is the encrypted secret store this package writes through.
type Vault interface {
	Put(context.Context, string, []byte) error
	Get(context.Context, string) ([]byte, error)
	Delete(context.Context, string) error
}

// Store reads and writes the secret half of a TSIG key.
type Store struct {
	vault Vault
}

// NewStore binds a secret store to the node's vault.
func NewStore(vault Vault) *Store { return &Store{vault: vault} }

// Secret returns the stored secret for a key. A key the vault has never held a
// secret for reports false rather than an error, because that is the normal
// state of a key whose secret has not been supplied yet.
func (store *Store) Secret(ctx context.Context, name string) (string, bool) {
	if store == nil || store.vault == nil {
		return "", false
	}
	secret, err := store.vault.Get(ctx, secretEntry(name))
	if err != nil || len(secret) == 0 {
		return "", false
	}
	return string(secret), true
}

// PutSecret stores or replaces the secret for a key.
func (store *Store) PutSecret(ctx context.Context, name, secret string) error {
	if store == nil || store.vault == nil {
		return errors.New("secret vault is unavailable")
	}
	if err := config.ValidateTSIGSecret(secret); err != nil {
		return fmt.Errorf("TSIG secret %w", err)
	}
	if err := store.vault.Put(ctx, secretEntry(name), []byte(strings.TrimSpace(secret))); err != nil {
		return fmt.Errorf("store TSIG secret: %w", err)
	}
	return nil
}

// ForgetSecret retires the secret for a key that no longer exists.
func (store *Store) ForgetSecret(ctx context.Context, name string) error {
	if store == nil || store.vault == nil {
		return errors.New("secret vault is unavailable")
	}
	if err := store.vault.Delete(ctx, secretEntry(name)); err != nil {
		return fmt.Errorf("delete TSIG secret: %w", err)
	}
	return nil
}

// Hydrate returns the configured keys with their secrets filled in from the
// vault, along with the names of any key the vault could not answer for. A
// missing secret is not fatal: the key stays configured and every signed
// message it guards fails verification, which is the safe direction.
func (store *Store) Hydrate(ctx context.Context, keys []config.TSIGKey) ([]config.TSIGKey, []string) {
	hydrated := make([]config.TSIGKey, len(keys))
	copy(hydrated, keys)
	missing := make([]string, 0)
	for index := range hydrated {
		if hydrated[index].Secret != "" {
			continue
		}
		secret, found := store.Secret(ctx, hydrated[index].Name)
		if !found {
			missing = append(missing, hydrated[index].Name)
			continue
		}
		hydrated[index].Secret = secret
	}
	return hydrated, missing
}

// Migrate moves any secret still written in TOML into the vault and blanks the
// configuration field. It returns how many keys it moved so the caller knows
// whether the file needs writing back. Running it again is harmless.
func (store *Store) Migrate(ctx context.Context, configuration *config.Config) (int, error) {
	migrated := 0
	for index := range configuration.TSIGKeys {
		key := &configuration.TSIGKeys[index]
		if key.Secret == "" {
			continue
		}
		if err := store.PutSecret(ctx, key.Name, key.Secret); err != nil {
			return migrated, fmt.Errorf("migrate TSIG key %q: %w", key.Name, err)
		}
		key.Secret = ""
		migrated++
	}
	return migrated, nil
}

// Pending reports whether any secret is still written in the configuration
// file. Checking first keeps an ordinary boot from rewriting sable.toml.
func Pending(configuration config.Config) bool {
	return slices.ContainsFunc(configuration.TSIGKeys, func(key config.TSIGKey) bool {
		return key.Secret != ""
	})
}

// GenerateSecret produces a random shared secret sized to the algorithm's hash,
// which is what RFC 2104 recommends for an HMAC key.
func GenerateSecret(algorithm string) (string, error) {
	size := 32
	switch canonicalAlgorithm(algorithm) {
	case dns.HmacSHA384:
		size = 48
	case dns.HmacSHA512:
		size = 64
	}
	material := make([]byte, size)
	if _, err := rand.Read(material); err != nil {
		return "", fmt.Errorf("generate TSIG secret: %w", err)
	}
	return base64.StdEncoding.EncodeToString(material), nil
}

// Algorithms lists the HMAC algorithms a key may use, most preferred first.
func Algorithms() []string {
	return []string{dns.HmacSHA256, dns.HmacSHA384, dns.HmacSHA512}
}

func canonicalAlgorithm(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	if value == "" {
		return dns.HmacSHA256
	}
	return dns.Fqdn(value)
}

// normalizeName matches how the configuration loader canonicalizes key names,
// so a key looked up through the console finds the same vault entry the DNS
// server does.
func normalizeName(name string) string {
	return strings.ToLower(dns.Fqdn(strings.TrimSpace(name)))
}

func secretEntry(name string) string { return secretPrefix + normalizeName(name) }
