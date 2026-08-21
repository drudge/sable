package app

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"

	"github.com/drudge/sable/internal/config"
	"github.com/drudge/sable/internal/store"
	"github.com/drudge/sable/internal/tsig"
	"github.com/drudge/sable/internal/unifi"
	"github.com/drudge/sable/internal/zone"
	"github.com/pelletier/go-toml/v2"
)

const clusterStateFormatVersion = 2

type authorizationStateStore interface {
	ExportAuthorizationState(context.Context) (store.AuthorizationState, error)
	ReplaceAuthorizationState(context.Context, store.AuthorizationState) error
}

// unifiCredentialVault is the part of the UniFi credential store replication
// needs. Settings alone are not enough: a promoted replica that knows the
// controller URL but has no credentials still cannot sign in to it.
type unifiCredentialVault interface {
	Get(context.Context) (unifi.Credentials, bool)
	Replace(context.Context, unifi.Credentials) error
}

// oidcSecretVault is the part of the single sign-on secret store replication
// needs.
type oidcSecretVault interface {
	Get(context.Context) (string, error)
	Put(context.Context, string) error
}

type clusterStateReplicator struct {
	configuration        *config.Manager
	zones                *zone.Manager
	authorization        authorizationStateStore
	tsigSecrets          *tsig.Store
	unifiCredentials     unifiCredentialVault
	oidcSecret           oidcSecretVault
	baseDirectory        string
	prepareConfiguration func(context.Context, config.Config, string) error
}

type clusterStateSnapshot struct {
	FormatVersion int                      `json:"format_version"`
	Configuration []byte                   `json:"configuration_toml"`
	Zones         []zone.Zone              `json:"zones"`
	Authorization store.AuthorizationState `json:"authorization"`
}

type clusterRuntimeConfiguration struct {
	Resolver        config.Resolver  `toml:"resolver"`
	TSIGKeys        []config.TSIGKey `toml:"tsig_keys"`
	Blocking        config.Blocking  `toml:"blocking"`
	QueryLogEnabled bool             `toml:"query_log_enabled"`
	// UniFi synchronization only runs on the writable node, but the settings
	// travel to every node so a promoted replica keeps publishing hosts instead
	// of silently freezing the records it inherited.
	UniFi config.UniFi `toml:"unifi"`
	// UniFiCredentials ride beside the settings and are banked in the receiving
	// node's vault, the same way TSIG secrets are. Neither side keeps them on
	// disk in the clear.
	UniFiCredentials unifi.Credentials `toml:"unifi_credentials"`
	// OIDC travels with redirect_url cleared. Every node serves the callback at
	// the same path and fills in its own host, so the section is identical
	// cluster-wide and a node that needs a different callback keeps its own
	// override instead of having the primary's imposed on it.
	OIDC config.OIDC `toml:"oidc"`
	// OIDCClientSecret is banked in the receiving node's vault like the UniFi
	// credentials. Without it a replica shows the sign-in button and then fails
	// the token exchange.
	OIDCClientSecret string `toml:"oidc_client_secret"`
}

func newClusterStateReplicator(
	configuration *config.Manager,
	zones *zone.Manager,
	authorization authorizationStateStore,
	tsigSecrets *tsig.Store,
	unifiCredentials unifiCredentialVault,
	oidcSecret oidcSecretVault,
) *clusterStateReplicator {
	return &clusterStateReplicator{
		configuration: configuration, zones: zones, authorization: authorization,
		tsigSecrets: tsigSecrets, unifiCredentials: unifiCredentials, oidcSecret: oidcSecret,
		baseDirectory: configuration.BaseDirectory(), prepareConfiguration: ensureRemoteBlockLists,
	}
}

func (replicator *clusterStateReplicator) Capture(ctx context.Context) ([]byte, error) {
	active := replicator.configuration.Current().Config
	// Replicas need the shared secrets to answer signed transfers, so the
	// snapshot carries them even though neither side keeps them on disk in the
	// clear. The enrollment channel is already mutually authenticated; what
	// changed is that each node stores what it receives in its own vault.
	tsigKeys, _ := replicator.tsigSecrets.Hydrate(ctx, active.TSIGKeys)
	runtimeConfiguration := clusterRuntimeConfiguration{
		Resolver:        active.Resolver,
		TSIGKeys:        tsigKeys,
		Blocking:        active.Blocking,
		QueryLogEnabled: active.QueryLog.Enabled,
		UniFi:           active.UniFi,
		OIDC:            replicatedOIDC(active.OIDC),
	}
	if replicator.unifiCredentials != nil {
		if credentials, found := replicator.unifiCredentials.Get(ctx); found {
			runtimeConfiguration.UniFiCredentials = credentials
		}
	}
	if replicator.oidcSecret != nil {
		secret, _ := replicator.oidcSecret.Get(ctx)
		runtimeConfiguration.OIDCClientSecret = secret
	}
	configurationContents, err := toml.Marshal(runtimeConfiguration)
	if err != nil {
		return nil, fmt.Errorf("encode replicated runtime configuration: %w", err)
	}
	authorization := store.AuthorizationState{Users: []store.AuthorizationUser{}, Roles: []store.AuthorizationRole{}, Tokens: []store.AuthorizationToken{}}
	if replicator.authorization != nil {
		authorization, err = replicator.authorization.ExportAuthorizationState(ctx)
		if err != nil {
			return nil, fmt.Errorf("export replicated authorization state: %w", err)
		}
	}
	snapshot := clusterStateSnapshot{
		FormatVersion: clusterStateFormatVersion,
		Configuration: configurationContents,
		// Capture runs every heartbeat and only reads the zones to serialize them,
		// so take them by reference rather than deep-copying every zone and record.
		Zones:         replicator.zones.CurrentRef().Zones,
		Authorization: authorization,
	}
	contents, err := json.Marshal(snapshot)
	if err != nil {
		return nil, fmt.Errorf("encode replicated application state: %w", err)
	}
	return contents, nil
}

func (replicator *clusterStateReplicator) Apply(ctx context.Context, contents []byte) error {
	snapshot, runtimeConfiguration, err := decodeClusterState(contents)
	if err != nil {
		return err
	}
	// Secrets are banked before anything is compared so the two sides can be
	// matched on names and algorithms alone. Without this, an incoming
	// snapshot would differ from the local configuration on every heartbeat.
	secretsChanged, err := replicator.storeReplicatedTSIGSecrets(ctx, &runtimeConfiguration)
	if err != nil {
		return err
	}
	if err := replicator.storeReplicatedUniFiCredentials(ctx, &runtimeConfiguration); err != nil {
		return err
	}
	if err := replicator.storeReplicatedOIDCSecret(ctx, &runtimeConfiguration); err != nil {
		return err
	}
	activeConfiguration := replicatedRuntimeConfiguration(replicator.configuration.Current().Config)
	activeZones := replicator.zones.Current().Zones
	activeAuthorization := store.AuthorizationState{}
	authorizationChanged := false
	if replicator.authorization != nil {
		activeAuthorization, err = replicator.authorization.ExportAuthorizationState(ctx)
		if err != nil {
			return fmt.Errorf("export local authorization state: %w", err)
		}
		authorizationChanged = !reflect.DeepEqual(activeAuthorization, snapshot.Authorization)
	}

	// A rotated secret leaves the replicated configuration untouched, so it is
	// forced through the same update path to make the runtime pick it up.
	configurationChanged := secretsChanged || !replicatedConfigurationEqual(activeConfiguration, runtimeConfiguration)
	if configurationChanged {
		candidate := replicator.configuration.Current().Config
		applyReplicatedRuntimeConfiguration(&candidate, runtimeConfiguration)
		if err := replicator.prepareConfiguration(ctx, candidate, replicator.baseDirectory); err != nil {
			return fmt.Errorf("prepare replicated configuration: %w", err)
		}
		if err := replicator.updateConfiguration(ctx, runtimeConfiguration); err != nil {
			return err
		}
	}
	zonesChanged := !reflect.DeepEqual(activeZones, snapshot.Zones)
	if zonesChanged {
		if err := replicator.zones.UpdateZones(ctx, func(candidate *[]zone.Zone) error {
			*candidate = zone.Clone(snapshot.Zones)
			return nil
		}); err != nil {
			var rollbackErr error
			if configurationChanged {
				rollbackErr = replicator.updateConfiguration(ctx, activeConfiguration)
			}
			return errors.Join(fmt.Errorf("apply replicated zones: %w", err), rollbackErr)
		}
	}
	if !authorizationChanged {
		return nil
	}
	if err := replicator.authorization.ReplaceAuthorizationState(ctx, snapshot.Authorization); err != nil {
		var rollbackErr error
		if zonesChanged {
			rollbackErr = replicator.zones.UpdateZones(ctx, func(candidate *[]zone.Zone) error {
				*candidate = zone.Clone(activeZones)
				return nil
			})
		}
		if configurationChanged {
			rollbackErr = errors.Join(rollbackErr, replicator.updateConfiguration(ctx, activeConfiguration))
		}
		return errors.Join(fmt.Errorf("apply replicated authorization: %w", err), rollbackErr)
	}
	return nil
}

func decodeClusterState(contents []byte) (clusterStateSnapshot, clusterRuntimeConfiguration, error) {
	var snapshot clusterStateSnapshot
	if err := json.Unmarshal(contents, &snapshot); err != nil {
		return clusterStateSnapshot{}, clusterRuntimeConfiguration{}, fmt.Errorf("decode replicated application state: %w", err)
	}
	if snapshot.FormatVersion != clusterStateFormatVersion {
		return clusterStateSnapshot{}, clusterRuntimeConfiguration{}, errors.New("replicated application state format is unsupported")
	}
	var runtimeConfiguration clusterRuntimeConfiguration
	if err := toml.Unmarshal(snapshot.Configuration, &runtimeConfiguration); err != nil {
		return clusterStateSnapshot{}, clusterRuntimeConfiguration{}, fmt.Errorf("decode replicated runtime configuration: %w", err)
	}
	return snapshot, runtimeConfiguration, nil
}

// storeReplicatedTSIGSecrets writes the secrets the primary sent into this
// node's vault and strips them from the snapshot, leaving only the names and
// algorithms that belong in the replica's configuration file. It reports
// whether any secret actually changed.
func (replicator *clusterStateReplicator) storeReplicatedTSIGSecrets(
	ctx context.Context,
	runtimeConfiguration *clusterRuntimeConfiguration,
) (bool, error) {
	changed := false
	for index := range runtimeConfiguration.TSIGKeys {
		key := &runtimeConfiguration.TSIGKeys[index]
		if key.Secret == "" {
			continue
		}
		stored, found := replicator.tsigSecrets.Secret(ctx, key.Name)
		if !found || stored != key.Secret {
			if err := replicator.tsigSecrets.PutSecret(ctx, key.Name, key.Secret); err != nil {
				return changed, fmt.Errorf("store replicated TSIG secret %q: %w", key.Name, err)
			}
			changed = true
		}
		key.Secret = ""
	}
	return changed, nil
}

// replicatedConfigurationEqual compares the two sides the way they will be
// written rather than field by field. An empty list is nil on the node that
// never had one and an empty slice once it has been through TOML, which
// reflect.DeepEqual reports as a difference that never converges: the snapshot
// arrives every second, so the replica would rewrite sable.toml and reapply its
// whole runtime configuration once a second, forever.
func replicatedConfigurationEqual(left, right clusterRuntimeConfiguration) bool {
	leftContents, leftErr := toml.Marshal(left)
	rightContents, rightErr := toml.Marshal(right)
	if leftErr != nil || rightErr != nil {
		return reflect.DeepEqual(left, right)
	}
	return bytes.Equal(leftContents, rightContents)
}

func replicatedRuntimeConfiguration(source config.Config) clusterRuntimeConfiguration {
	return clusterRuntimeConfiguration{
		Resolver:        source.Resolver,
		TSIGKeys:        source.TSIGKeys,
		Blocking:        source.Blocking,
		QueryLogEnabled: source.QueryLog.Enabled,
		UniFi:           source.UniFi,
		OIDC:            replicatedOIDC(source.OIDC),
	}
}

func (replicator *clusterStateReplicator) updateConfiguration(ctx context.Context, source clusterRuntimeConfiguration) error {
	return replicator.configuration.Update(ctx, func(candidate *config.Config) error {
		applyReplicatedRuntimeConfiguration(candidate, source)
		return nil
	})
}

func applyReplicatedRuntimeConfiguration(candidate *config.Config, source clusterRuntimeConfiguration) {
	candidate.Resolver = source.Resolver
	candidate.TSIGKeys = append([]config.TSIGKey(nil), source.TSIGKeys...)
	candidate.Blocking = source.Blocking
	candidate.QueryLog.Enabled = source.QueryLogEnabled
	candidate.UniFi = source.UniFi
	// The override stays put. It names this node, and the primary has no say in
	// what hostname a browser reaches it at.
	override := candidate.OIDC.RedirectURL
	candidate.OIDC = source.OIDC
	candidate.OIDC.RedirectURL = override
}

// replicatedOIDC is the section as it crosses the wire: everything except the
// callback, which each node fills in for itself.
func replicatedOIDC(settings config.OIDC) config.OIDC {
	settings.RedirectURL = ""
	settings.Scopes = append([]string(nil), settings.Scopes...)
	settings.DefaultRoles = append([]string(nil), settings.DefaultRoles...)
	settings.RoleMappings = append([]config.OIDCRoleMapping(nil), settings.RoleMappings...)
	return settings
}

// storeReplicatedOIDCSecret banks the client secret the primary sent and strips
// it from the snapshot. Like the UniFi credentials it reports no change,
// because the relying party is rebuilt whenever the stored secret differs from
// the one it was built with.
func (replicator *clusterStateReplicator) storeReplicatedOIDCSecret(
	ctx context.Context,
	runtimeConfiguration *clusterRuntimeConfiguration,
) error {
	secret := runtimeConfiguration.OIDCClientSecret
	runtimeConfiguration.OIDCClientSecret = ""
	if replicator.oidcSecret == nil || secret == "" {
		return nil
	}
	if stored, err := replicator.oidcSecret.Get(ctx); err == nil && stored == secret {
		return nil
	}
	if err := replicator.oidcSecret.Put(ctx, secret); err != nil {
		return fmt.Errorf("store replicated single sign-on client secret: %w", err)
	}
	return nil
}

// storeReplicatedUniFiCredentials banks the credentials the primary sent and
// strips them from the snapshot, leaving a section that matches what this node
// keeps in TOML. Unlike TSIG keys it reports no change, because the
// synchronizer reads the vault on every run rather than caching what it was
// configured with.
func (replicator *clusterStateReplicator) storeReplicatedUniFiCredentials(
	ctx context.Context,
	runtimeConfiguration *clusterRuntimeConfiguration,
) error {
	credentials := runtimeConfiguration.UniFiCredentials
	runtimeConfiguration.UniFiCredentials = unifi.Credentials{}
	if replicator.unifiCredentials == nil || !credentials.Configured() {
		return nil
	}
	if stored, found := replicator.unifiCredentials.Get(ctx); found && stored == credentials {
		return nil
	}
	if err := replicator.unifiCredentials.Replace(ctx, credentials); err != nil {
		return fmt.Errorf("store replicated UniFi credentials: %w", err)
	}
	return nil
}
