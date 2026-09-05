package dnsprovider

import (
	"context"
	"errors"
	"testing"
)

type memoryVault struct {
	values map[string][]byte
}

func (vault *memoryVault) Put(_ context.Context, name string, value []byte) error {
	if vault.values == nil {
		vault.values = make(map[string][]byte)
	}
	vault.values[name] = append([]byte(nil), value...)
	return nil
}

func (vault *memoryVault) Get(_ context.Context, name string) ([]byte, error) {
	value, found := vault.values[name]
	if !found {
		return nil, errors.New("not found")
	}
	return append([]byte(nil), value...), nil
}

func TestStoreUsesSharedExternalDNSNamespaceAndPreservesSecrets(t *testing.T) {
	vault := &memoryVault{}
	store := NewStore(vault)
	ctx := context.Background()
	if err := store.Put(ctx, "cloudflare", Credentials{APIToken: "secret", ZoneID: "old-zone"}); err != nil {
		t.Fatal(err)
	}
	if err := store.Put(ctx, "cloudflare", Credentials{ZoneID: "new-zone"}); err != nil {
		t.Fatal(err)
	}
	credentials, found := store.Get(ctx, "cloudflare")
	if !found || credentials.APIToken != "secret" || credentials.ZoneID != "new-zone" {
		t.Fatalf("credentials = %+v, found = %v", credentials, found)
	}
	if _, found := vault.values[credentialSecretPrefix+"cloudflare"]; !found {
		t.Fatalf("credential was not stored under %q", credentialSecretPrefix)
	}
}

func TestStoreReadsLegacyACMECredentials(t *testing.T) {
	vault := &memoryVault{values: map[string][]byte{
		legacyCredentialSecretPrefix + "cloudflare": []byte(`{"api_token":"legacy-token"}`),
	}}
	credentials, found := NewStore(vault).Get(context.Background(), "cloudflare")
	if !found || credentials.APIToken != "legacy-token" {
		t.Fatalf("credentials = %+v, found = %v", credentials, found)
	}
}
