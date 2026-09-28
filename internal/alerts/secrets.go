package alerts

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"

	"github.com/drudge/sable/internal/config"
)

// secretPrefix namespaces destination secrets in the vault, matching the
// "tsig/" style other packages use.
const secretPrefix = "alerts/destination/"

// Vault is the encrypted secret store destination secrets are kept in.
type Vault interface {
	Put(context.Context, string, []byte) error
	Get(context.Context, string) ([]byte, error)
	Delete(context.Context, string) error
}

// Secrets are the parts of a destination worth stealing: a webhook URL
// usually carries a token, and Pushover keys and header values are
// credentials. They live in the vault, never in sable.toml.
type Secrets struct {
	URL           string               `json:"url,omitempty"`
	PushoverToken string               `json:"pushover_token,omitempty"`
	PushoverUser  string               `json:"pushover_user,omitempty"`
	Headers       []config.AlertHeader `json:"headers,omitempty"`
}

// SecretsOf takes the secrets out of a destination.
func SecretsOf(destination config.AlertDestination) Secrets {
	return Secrets{
		URL: destination.URL, PushoverToken: destination.PushoverToken, PushoverUser: destination.PushoverUser,
		Headers: slices.Clone(destination.Headers),
	}
}

// Empty reports whether there is no secret at all.
func (secrets Secrets) Empty() bool {
	return secrets.URL == "" && secrets.PushoverToken == "" && secrets.PushoverUser == "" && len(secrets.Headers) == 0
}

// Fill puts secrets into a destination, keeping any it already has.
func (secrets Secrets) Fill(destination config.AlertDestination) config.AlertDestination {
	if destination.URL == "" {
		destination.URL = secrets.URL
	}
	if destination.PushoverToken == "" {
		destination.PushoverToken = secrets.PushoverToken
	}
	if destination.PushoverUser == "" {
		destination.PushoverUser = secrets.PushoverUser
	}
	if len(destination.Headers) == 0 {
		destination.Headers = slices.Clone(secrets.Headers)
	}
	// Normalizing drops what the format cannot use, such as headers kept from
	// before the destination changed format.
	destination.Normalize()
	return destination
}

// Strip takes the secrets out of a destination, as it is written to the file.
func Strip(destination config.AlertDestination) config.AlertDestination {
	destination.URL, destination.PushoverToken, destination.PushoverUser, destination.Headers = "", "", "", nil
	return destination
}

// SecretStore keeps destination secrets in the vault.
type SecretStore struct {
	vault Vault
}

// NewSecretStore binds a secret store to the node's vault.
func NewSecretStore(vault Vault) *SecretStore { return &SecretStore{vault: vault} }

// Secrets returns the stored secrets for a destination. A destination the
// vault has nothing for reports false rather than an error, because that is
// the normal state of one whose secrets were never supplied.
func (store *SecretStore) Secrets(ctx context.Context, id string) (Secrets, bool) {
	if store == nil || store.vault == nil {
		return Secrets{}, false
	}
	sealed, err := store.vault.Get(ctx, secretPrefix+id)
	if err != nil || len(sealed) == 0 {
		return Secrets{}, false
	}
	var secrets Secrets
	if json.Unmarshal(sealed, &secrets) != nil || secrets.Empty() {
		return Secrets{}, false
	}
	return secrets, true
}

// Put stores or replaces the secrets for a destination.
func (store *SecretStore) Put(ctx context.Context, id string, secrets Secrets) error {
	if store == nil || store.vault == nil {
		return errors.New("secret vault is unavailable")
	}
	if id == "" {
		return errors.New("a destination needs an ID")
	}
	encoded, err := json.Marshal(secrets)
	if err != nil {
		return fmt.Errorf("encode alert secrets: %w", err)
	}
	if err := store.vault.Put(ctx, secretPrefix+id, encoded); err != nil {
		return fmt.Errorf("store alert secrets: %w", err)
	}
	return nil
}

// Forget retires the secrets of a destination that no longer exists.
func (store *SecretStore) Forget(ctx context.Context, id string) error {
	if store == nil || store.vault == nil {
		return errors.New("secret vault is unavailable")
	}
	if err := store.vault.Delete(ctx, secretPrefix+id); err != nil {
		return fmt.Errorf("delete alert secrets: %w", err)
	}
	return nil
}

// Hydrate returns destinations with their secrets filled in from the vault.
// Secrets still written in the file win, since someone put them there on
// purpose. A destination the vault has nothing for is returned as it is and
// fails when it sends, which the console shows.
func (store *SecretStore) Hydrate(ctx context.Context, destinations []config.AlertDestination) []config.AlertDestination {
	hydrated := make([]config.AlertDestination, 0, len(destinations))
	for _, destination := range destinations {
		if secrets, found := store.Secrets(ctx, destination.ID); found {
			destination = secrets.Fill(destination)
		}
		hydrated = append(hydrated, destination)
	}
	return hydrated
}

// Migrate moves any secret still written in the configuration into the vault
// and blanks it in the file. It returns how many destinations it moved, so the
// caller knows whether the file needs writing back. Running it again is
// harmless.
func (store *SecretStore) Migrate(ctx context.Context, configuration *config.Config) (int, error) {
	migrated := 0
	for index := range configuration.Alerts.Destinations {
		destination := &configuration.Alerts.Destinations[index]
		if !destination.HasSecrets() {
			continue
		}
		secrets := SecretsOf(*destination)
		// Whatever the file does not say stays as the vault has it.
		if current, found := store.Secrets(ctx, destination.ID); found {
			secrets = current.fillFrom(secrets)
		}
		if err := store.Put(ctx, destination.ID, secrets); err != nil {
			return migrated, fmt.Errorf("move secrets of alert destination %q: %w", destination.Label(), err)
		}
		*destination = Strip(*destination)
		migrated++
	}
	return migrated, nil
}

// fillFrom takes each secret written in the file over the one in the vault.
func (secrets Secrets) fillFrom(written Secrets) Secrets {
	if written.URL != "" {
		secrets.URL = written.URL
	}
	if written.PushoverToken != "" {
		secrets.PushoverToken = written.PushoverToken
	}
	if written.PushoverUser != "" {
		secrets.PushoverUser = written.PushoverUser
	}
	if len(written.Headers) > 0 {
		secrets.Headers = slices.Clone(written.Headers)
	}
	return secrets
}

// Pending reports whether any destination secret is still written in the
// configuration file. Checking first keeps an ordinary boot from rewriting
// sable.toml.
func Pending(configuration config.Config) bool {
	return slices.ContainsFunc(configuration.Alerts.Destinations, config.AlertDestination.HasSecrets)
}
