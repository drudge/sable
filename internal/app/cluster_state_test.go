package app

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/drudge/sable/internal/auth"
	"github.com/drudge/sable/internal/config"
	"github.com/drudge/sable/internal/store"
	"github.com/drudge/sable/internal/tsig"
	"github.com/drudge/sable/internal/zone"
	"github.com/pelletier/go-toml/v2"
)

func TestClusterStateReplicatesRuntimeConfigurationAndZones(t *testing.T) {
	ctx := context.Background()
	sourceConfiguration := config.Defaults()
	sourceConfiguration.Resolver.Mode = "recursive"
	sourceConfiguration.Resolver.Forwarders = []string{"192.0.2.53:53"}
	sourceConfiguration.Resolver.RootHints = []string{"192.0.2.1:53"}
	sourceConfiguration.Blocking.Domains = []string{"ads.example"}
	sourceConfiguration.QueryLog.Enabled = false
	// The primary is already migrated: its configuration names the key and its
	// vault holds the secret, which is the state Capture has to reassemble.
	transferSecret := base64.StdEncoding.EncodeToString(make([]byte, 32))
	sourceConfiguration.TSIGKeys = []config.TSIGKey{{Name: "transfer-key", Algorithm: "hmac-sha256"}}
	sourceManager := newTestConfigurationManager(t, sourceConfiguration)
	sourceZones := newTestZoneManager(t, []zone.Zone{{
		ID: "zone-1", Name: "example.test", Type: "primary", DefaultTTL: 300,
		Records: []zone.Record{{Name: "example.test", Type: "A", Value: "192.0.2.10", TTL: 300}},
	}})

	targetConfiguration := config.Defaults()
	targetConfiguration.Server.HTTPListen = "127.0.0.1:6380"
	targetConfiguration.Cluster.NodeName = "replica-local"
	targetManager := newTestConfigurationManager(t, targetConfiguration)
	targetZones := newTestZoneManager(t, nil)

	sourceSecrets := newTestTSIGStore()
	if err := sourceSecrets.PutSecret(ctx, "transfer-key.", transferSecret); err != nil {
		t.Fatal(err)
	}
	targetSecrets := newTestTSIGStore()
	contents, err := newClusterStateReplicator(sourceManager, sourceZones, nil, sourceSecrets).Capture(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := newClusterStateReplicator(targetManager, targetZones, nil, targetSecrets).Apply(ctx, contents); err != nil {
		t.Fatal(err)
	}
	got := targetManager.Current().Config
	if got.Resolver.Mode != sourceConfiguration.Resolver.Mode ||
		!reflect.DeepEqual(got.Resolver.Forwarders, sourceConfiguration.Resolver.Forwarders) ||
		!reflect.DeepEqual(got.Resolver.RootHints, sourceConfiguration.Resolver.RootHints) ||
		!reflect.DeepEqual(got.Blocking.Domains, sourceConfiguration.Blocking.Domains) ||
		len(got.TSIGKeys) != 1 || got.TSIGKeys[0].Name != "transfer-key." ||
		got.QueryLog.Enabled != sourceConfiguration.QueryLog.Enabled {
		t.Fatalf("replicated runtime configuration = %#v", got)
	}
	// The secret reaches the replica but lands in its vault, so the replicated
	// configuration it writes to disk carries only the name and algorithm.
	if got.TSIGKeys[0].Secret != "" {
		t.Fatal("replicated configuration kept the TSIG secret in plaintext")
	}
	replicated, found := targetSecrets.Secret(ctx, "transfer-key.")
	if !found || replicated != transferSecret {
		t.Fatalf("replica vault secret = %q, found = %v", replicated, found)
	}
	if got.Server.HTTPListen != targetConfiguration.Server.HTTPListen || got.Cluster.NodeName != targetConfiguration.Cluster.NodeName {
		t.Fatalf("node-local configuration was overwritten: %#v", got)
	}
	if zones := targetZones.Current().Zones; !reflect.DeepEqual(zones, sourceZones.Current().Zones) {
		t.Fatalf("replicated zones = %#v", zones)
	}
}

func TestClusterStatePreparesRemoteBlockListsBeforeConfigurationApply(t *testing.T) {
	ctx := context.Background()
	sourceConfiguration := config.Defaults()
	sourceConfiguration.Blocking.Lists = []config.BlockList{{
		Name: "managed", Path: "data/blocklists/managed.txt",
		URL: "https://lists.example/managed.txt", Format: "domains",
	}}
	sourceManager := newTestConfigurationManager(t, sourceConfiguration)
	sourceZones := newTestZoneManager(t, nil)
	contents, err := newClusterStateReplicator(sourceManager, sourceZones, nil, newTestTSIGStore()).Capture(ctx)
	if err != nil {
		t.Fatal(err)
	}

	targetConfiguration := config.Defaults()
	directory := t.TempDir()
	configurationPath := filepath.Join(directory, "sable.toml")
	encoded, err := toml.Marshal(targetConfiguration)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(configurationPath, encoded, 0o600); err != nil {
		t.Fatal(err)
	}
	prepared := false
	targetManager := config.NewManager(configurationPath, targetConfiguration, func(_ context.Context, _, candidate config.Config) error {
		if !prepared {
			return errors.New("configuration applied before its artifacts were prepared")
		}
		path := candidate.BlockListPaths(directory)[0]
		if _, err := os.Stat(path); err != nil {
			return fmt.Errorf("prepared block list is unavailable: %w", err)
		}
		return nil
	})
	replicator := newClusterStateReplicator(targetManager, newTestZoneManager(t, nil), nil, newTestTSIGStore())
	replicator.prepareConfiguration = func(_ context.Context, candidate config.Config, baseDirectory string) error {
		prepared = true
		path := candidate.BlockListPaths(baseDirectory)[0]
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			return err
		}
		return os.WriteFile(path, []byte("ads.example\n"), 0o600)
	}
	if err := replicator.Apply(ctx, contents); err != nil {
		t.Fatal(err)
	}
	if !prepared {
		t.Fatal("replicated configuration artifacts were not prepared")
	}
}

func TestClusterStateReplicatesAuthorizationAndTokenRevocation(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 8, 14, 12, 0, 0, 0, time.UTC)
	sourceStore, err := store.Open(ctx, "sqlite", filepath.Join(t.TempDir(), "source.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer sourceStore.Close()
	targetStore, err := store.Open(ctx, "sqlite", filepath.Join(t.TempDir(), "target.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer targetStore.Close()
	sourceAuth, err := auth.NewService(sourceStore, auth.Options{Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	credentials, err := sourceAuth.Setup(ctx, "admin", "cluster-test-password-123!", "127.0.0.1", "test")
	if err != nil {
		t.Fatal(err)
	}
	administrator, err := sourceAuth.AuthenticateSession(ctx, credentials.SessionToken)
	if err != nil {
		t.Fatal(err)
	}
	if err := sourceAuth.CreateRole(ctx, administrator, "Example Zone API", "Manage records in one zone", []auth.Grant{{
		Permission: auth.PermissionZonesRecords, Surface: auth.SurfaceAPI,
		ResourceType: auth.ResourceZone, ResourceID: "example.test",
	}}, "127.0.0.1", "test"); err != nil {
		t.Fatal(err)
	}
	if err := sourceAuth.CreateUser(ctx, administrator, "automation", "Automation", "", "", []string{"Example Zone API"}, "127.0.0.1", "test"); err != nil {
		t.Fatal(err)
	}
	users, err := sourceStore.ListUsers(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var automationID int64
	for _, user := range users {
		if user.Username == "automation" {
			automationID = user.ID
		}
	}
	if automationID == 0 {
		t.Fatal("automation user was not created")
	}
	secret, _, err := sourceAuth.CreateAPIToken(ctx, administrator, automationID, "zone updater", []string{"Example Zone API"}, auth.APITokenExpiration{Never: true}, "127.0.0.1", "test")
	if err != nil {
		t.Fatal(err)
	}

	sourceReplicator := newClusterStateReplicator(newTestConfigurationManager(t, config.Defaults()), newTestZoneManager(t, nil), sourceStore, newTestTSIGStore())
	targetReplicator := newClusterStateReplicator(newTestConfigurationManager(t, config.Defaults()), newTestZoneManager(t, nil), targetStore, newTestTSIGStore())
	contents, err := sourceReplicator.Capture(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(contents), secret) || strings.Contains(string(contents), "cluster-test-password-123!") {
		t.Fatal("replicated authorization snapshot contains a plaintext credential")
	}
	if err := targetReplicator.Apply(ctx, contents); err != nil {
		t.Fatal(err)
	}
	targetAuth, err := auth.NewService(targetStore, auth.Options{Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	principal, err := targetAuth.AuthenticateToken(ctx, secret)
	if err != nil {
		t.Fatalf("authenticate replicated API token: %v", err)
	}
	if !auth.Authorize(principal, auth.PermissionZonesRecords, auth.ResourceZone, "example.test") || auth.Authorize(principal, auth.PermissionZonesRecords, auth.ResourceZone, "other.test") {
		t.Fatalf("replicated token grants = %+v", principal.Grants)
	}
	if _, err := targetAuth.AuthenticateSession(ctx, credentials.SessionToken); !errors.Is(err, auth.ErrUnauthorized) {
		t.Fatalf("primary browser session replicated to target: %v", err)
	}

	tokens, err := sourceStore.ListAPITokens(ctx, now)
	if err != nil || len(tokens) != 1 {
		t.Fatalf("source API tokens = %+v, error = %v", tokens, err)
	}
	if err := sourceAuth.RevokeAPIToken(ctx, administrator, tokens[0].ID, "127.0.0.1", "test"); err != nil {
		t.Fatal(err)
	}
	contents, err = sourceReplicator.Capture(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := targetReplicator.Apply(ctx, contents); err != nil {
		t.Fatal(err)
	}
	if _, err := targetAuth.AuthenticateToken(ctx, secret); !errors.Is(err, auth.ErrUnauthorized) {
		t.Fatalf("revoked replicated API token authentication error = %v", err)
	}
}

// memoryTSIGVault stands in for the encrypted vault so the replication tests
// can watch a secret move from one node's store to another's.
type memoryTSIGVault struct{ values map[string][]byte }

func (vault *memoryTSIGVault) Put(_ context.Context, name string, value []byte) error {
	vault.values[name] = append([]byte(nil), value...)
	return nil
}

func (vault *memoryTSIGVault) Get(_ context.Context, name string) ([]byte, error) {
	value, found := vault.values[name]
	if !found {
		return nil, errors.New("not found")
	}
	return value, nil
}

func (vault *memoryTSIGVault) Delete(_ context.Context, name string) error {
	delete(vault.values, name)
	return nil
}

func newTestTSIGStore() *tsig.Store {
	return tsig.NewStore(&memoryTSIGVault{values: make(map[string][]byte)})
}

func newTestConfigurationManager(t *testing.T, initial config.Config) *config.Manager {
	t.Helper()
	contents, err := toml.Marshal(initial)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "sable.toml")
	if err := os.WriteFile(path, contents, 0o600); err != nil {
		t.Fatal(err)
	}
	return config.NewManager(path, initial, func(context.Context, config.Config, config.Config) error { return nil })
}

type clusterStateZoneRepository struct{ zones []zone.Zone }

func (repository *clusterStateZoneRepository) ListZones(context.Context) ([]zone.Zone, error) {
	return zone.Clone(repository.zones), nil
}

func (repository *clusterStateZoneRepository) ReplaceZones(_ context.Context, _, candidate []zone.Zone) ([]zone.Zone, error) {
	repository.zones = zone.Clone(candidate)
	return zone.Clone(repository.zones), nil
}

func newTestZoneManager(t *testing.T, zones []zone.Zone) *zone.Manager {
	t.Helper()
	manager, err := zone.NewManager(context.Background(), &clusterStateZoneRepository{zones: zones}, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	return manager
}
