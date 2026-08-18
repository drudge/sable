package app

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"

	"github.com/drudge/sable/internal/config"
	"github.com/drudge/sable/internal/store"
	"github.com/drudge/sable/internal/tsig"
	"github.com/drudge/sable/internal/zone"
	"github.com/pelletier/go-toml/v2"
)

const clusterStateFormatVersion = 2

type authorizationStateStore interface {
	ExportAuthorizationState(context.Context) (store.AuthorizationState, error)
	ReplaceAuthorizationState(context.Context, store.AuthorizationState) error
}

type clusterStateReplicator struct {
	configuration        *config.Manager
	zones                *zone.Manager
	authorization        authorizationStateStore
	tsigSecrets          *tsig.Store
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
}

func newClusterStateReplicator(
	configuration *config.Manager,
	zones *zone.Manager,
	authorization authorizationStateStore,
	tsigSecrets *tsig.Store,
) *clusterStateReplicator {
	return &clusterStateReplicator{
		configuration: configuration, zones: zones, authorization: authorization,
		tsigSecrets:   tsigSecrets,
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
		Zones:         replicator.zones.Current().Zones,
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
	configurationChanged := secretsChanged || !reflect.DeepEqual(activeConfiguration, runtimeConfiguration)
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

func replicatedRuntimeConfiguration(source config.Config) clusterRuntimeConfiguration {
	return clusterRuntimeConfiguration{
		Resolver:        source.Resolver,
		TSIGKeys:        source.TSIGKeys,
		Blocking:        source.Blocking,
		QueryLogEnabled: source.QueryLog.Enabled,
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
}
