package tsig

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/drudge/sable/internal/config"
)

// ConfigEditor is the slice of the configuration manager this package needs.
type ConfigEditor interface {
	Current() config.Snapshot
	Update(context.Context, func(*config.Config) error) error
}

// Key describes a configured key to the console. The secret never travels with
// it: Configured only says whether the vault holds one.
type Key struct {
	Name       string
	Algorithm  string
	Configured bool
}

// Request is an add or a rotate. A blank Secret keeps whatever the vault
// already holds, and generates one when the key is new. Rotate forces a fresh
// secret even when the vault already has one.
type Request struct {
	Name      string
	Algorithm string
	Secret    string
	Rotate    bool
}

// Result reports what was stored. Secret is only filled in when this package
// generated it, because that is the one moment the operator can copy it.
type Result struct {
	Name      string
	Algorithm string
	Secret    string
	Generated bool
	Created   bool
}

// Manager edits the two halves of a key together: the name and algorithm in
// the configuration file, the secret in the vault.
type Manager struct {
	configuration ConfigEditor
	secrets       *Store
}

// NewManager binds the console's key editor to the configuration and the vault.
func NewManager(configuration ConfigEditor, secrets *Store) *Manager {
	return &Manager{configuration: configuration, secrets: secrets}
}

// Keys lists the configured keys and whether each one has a usable secret.
func (manager *Manager) Keys(ctx context.Context) []Key {
	if manager == nil || manager.configuration == nil {
		return nil
	}
	configured := manager.configuration.Current().Config.TSIGKeys
	keys := make([]Key, 0, len(configured))
	for _, key := range configured {
		_, found := manager.secrets.Secret(ctx, key.Name)
		keys = append(keys, Key{Name: key.Name, Algorithm: key.Algorithm, Configured: found})
	}
	return keys
}

// Save adds a key or rotates an existing one.
//
// The secret is written to the vault before the configuration, because the
// configuration write is what reloads the runtime and the reload reads the
// secret back out. Doing it the other way round would activate a key still
// carrying its previous secret.
func (manager *Manager) Save(ctx context.Context, request Request) (Result, error) {
	if manager == nil || manager.configuration == nil {
		return Result{}, errors.New("TSIG keys are read-only")
	}
	name := normalizeName(request.Name)
	if name == "." {
		return Result{}, errors.New("a key name is required")
	}
	algorithm := canonicalAlgorithm(request.Algorithm)
	if !slices.Contains(Algorithms(), algorithm) {
		return Result{}, errors.New("algorithm must be hmac-sha256, hmac-sha384, or hmac-sha512")
	}
	existing := slices.ContainsFunc(
		manager.configuration.Current().Config.TSIGKeys,
		func(key config.TSIGKey) bool { return key.Name == name },
	)
	result := Result{Name: name, Algorithm: algorithm, Created: !existing}

	secret := strings.TrimSpace(request.Secret)
	stored, held := manager.secrets.Secret(ctx, name)
	switch {
	case secret != "":
		if err := config.ValidateTSIGSecret(secret); err != nil {
			return Result{}, fmt.Errorf("secret %w", err)
		}
	case held && !request.Rotate:
		secret = stored
	default:
		generated, err := GenerateSecret(algorithm)
		if err != nil {
			return Result{}, err
		}
		secret = generated
		result.Secret = generated
		result.Generated = true
	}
	if err := manager.secrets.PutSecret(ctx, name, secret); err != nil {
		return Result{}, err
	}
	if err := manager.configuration.Update(ctx, func(candidate *config.Config) error {
		upsertKey(candidate, name, algorithm)
		return nil
	}); err != nil {
		return Result{}, fmt.Errorf("the secret was stored but could not be activated: %w", err)
	}
	return result, nil
}

// Delete retires a key. The configuration is updated first: a key a zone still
// references fails validation there, which leaves the secret intact instead of
// destroying material the server is about to need.
func (manager *Manager) Delete(ctx context.Context, name string) error {
	if manager == nil || manager.configuration == nil {
		return errors.New("TSIG keys are read-only")
	}
	normalized := normalizeName(name)
	if normalized == "." {
		return errors.New("a key name is required")
	}
	found := false
	if err := manager.configuration.Update(ctx, func(candidate *config.Config) error {
		before := len(candidate.TSIGKeys)
		candidate.TSIGKeys = slices.DeleteFunc(candidate.TSIGKeys, func(key config.TSIGKey) bool {
			return key.Name == normalized
		})
		found = len(candidate.TSIGKeys) != before
		return nil
	}); err != nil {
		return err
	}
	if !found {
		return fmt.Errorf("no TSIG key named %q is configured", normalized)
	}
	return manager.secrets.ForgetSecret(ctx, normalized)
}

func upsertKey(candidate *config.Config, name, algorithm string) {
	for index := range candidate.TSIGKeys {
		if candidate.TSIGKeys[index].Name != name {
			continue
		}
		candidate.TSIGKeys[index].Algorithm = algorithm
		candidate.TSIGKeys[index].Secret = ""
		return
	}
	candidate.TSIGKeys = append(candidate.TSIGKeys, config.TSIGKey{Name: name, Algorithm: algorithm})
}
