package dnsprovider

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

const (
	credentialSecretPrefix       = "external-dns/providers/"
	legacyCredentialSecretPrefix = "public-tls/acme/"
)

// Vault is the encrypted secret storage used for provider credentials.
type Vault interface {
	Put(context.Context, string, []byte) error
	Get(context.Context, string) ([]byte, error)
}

// Store keeps external DNS credentials independent of the feature consuming
// them, so ACME and dynamic DNS can share a provider connection.
type Store struct {
	vault Vault
}

func NewStore(vault Vault) *Store {
	return &Store{vault: vault}
}

func (store *Store) Put(ctx context.Context, provider string, credentials Credentials) error {
	provider = strings.ToLower(strings.TrimSpace(provider))
	if current, found := store.Get(ctx, provider); found {
		credentials = MergeCredentials(current, credentials)
	}
	return store.Replace(ctx, provider, credentials)
}

// Replace stores an exact provider credential set. Cluster replication uses it
// so removing an optional source credential also removes it on replicas.
func (store *Store) Replace(ctx context.Context, provider string, credentials Credentials) error {
	provider = strings.ToLower(strings.TrimSpace(provider))
	if err := ValidateCredentials(provider, credentials); err != nil {
		return err
	}
	encoded, err := json.Marshal(credentials)
	if err != nil {
		return fmt.Errorf("encode %s credentials: %w", provider, err)
	}
	if store.vault == nil {
		return errors.New("external DNS credential vault is unavailable")
	}
	if err := store.vault.Put(ctx, credentialSecretPrefix+provider, encoded); err != nil {
		return fmt.Errorf("store %s credentials: %w", provider, err)
	}
	return nil
}

func (store *Store) Get(ctx context.Context, provider string) (Credentials, bool) {
	if store == nil || store.vault == nil || strings.TrimSpace(provider) == "" {
		return Credentials{}, false
	}
	provider = strings.ToLower(strings.TrimSpace(provider))
	for _, prefix := range []string{credentialSecretPrefix, legacyCredentialSecretPrefix} {
		encoded, err := store.vault.Get(ctx, prefix+provider)
		if err != nil {
			continue
		}
		var credentials Credentials
		if json.Unmarshal(encoded, &credentials) == nil && ValidateCredentials(provider, credentials) == nil {
			return credentials, true
		}
	}
	return Credentials{}, false
}

// MergeCredentials preserves stored secret fields when a settings form leaves
// them blank, while allowing non-secret provider options to be changed.
func MergeCredentials(current, replacement Credentials) Credentials {
	if replacement.APIToken != "" {
		current.APIToken = replacement.APIToken
	}
	if replacement.APIKey != "" {
		current.APIKey = replacement.APIKey
	}
	if replacement.Secret != "" {
		current.Secret = replacement.Secret
	}
	if replacement.Username != "" {
		current.Username = replacement.Username
	}
	if replacement.ClientIP != "" {
		current.ClientIP = replacement.ClientIP
	}
	if replacement.ZoneID != "" {
		current.ZoneID = replacement.ZoneID
	}
	if replacement.Server != "" {
		current.Server = replacement.Server
	}
	if replacement.TSIGName != "" {
		current.TSIGName = replacement.TSIGName
	}
	if replacement.TSIGSecret != "" {
		current.TSIGSecret = replacement.TSIGSecret
	}
	if replacement.TSIGAlgorithm != "" {
		current.TSIGAlgorithm = replacement.TSIGAlgorithm
	}
	if replacement.AccessKeyID != "" {
		current.AccessKeyID = replacement.AccessKeyID
	}
	if replacement.SecretAccessKey != "" {
		current.SecretAccessKey = replacement.SecretAccessKey
	}
	if replacement.SessionToken != "" {
		current.SessionToken = replacement.SessionToken
	}
	if replacement.Endpoint != "" {
		current.Endpoint = replacement.Endpoint
	}
	if replacement.ApplicationKey != "" {
		current.ApplicationKey = replacement.ApplicationKey
	}
	if replacement.ApplicationSecret != "" {
		current.ApplicationSecret = replacement.ApplicationSecret
	}
	if replacement.ConsumerKey != "" {
		current.ConsumerKey = replacement.ConsumerKey
	}
	return current
}
