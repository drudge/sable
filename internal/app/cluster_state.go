package app

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"slices"
	"strings"
	"time"

	"github.com/drudge/sable/internal/alerts"
	"github.com/drudge/sable/internal/config"
	"github.com/drudge/sable/internal/dnsprovider"
	"github.com/drudge/sable/internal/store"
	"github.com/drudge/sable/internal/tsig"
	"github.com/drudge/sable/internal/unifi"
	"github.com/drudge/sable/internal/webpush"
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

type dnsProviderCredentialVault interface {
	Get(context.Context, string) (dnsprovider.Credentials, bool)
	Replace(context.Context, string, dnsprovider.Credentials) error
}

// pushKeyVault is the part of the push key store replication needs. Reading
// the key must never make one, since the state is captured every second.
type pushKeyVault interface {
	Sealed(context.Context) ([]byte, error)
	Replace(context.Context, []byte) error
}

// pushSubscriptionStore keeps the browsers that turned alerts on.
type pushSubscriptionStore interface {
	PushSubscriptions(context.Context) ([]webpush.Subscription, error)
	SavePushSubscription(context.Context, webpush.Subscription) error
	DeletePushSubscription(context.Context, string) error
}

type clusterStateReplicator struct {
	configuration          *config.Manager
	zones                  *zone.Manager
	authorization          authorizationStateStore
	tsigSecrets            *tsig.Store
	unifiCredentials       unifiCredentialVault
	oidcSecret             oidcSecretVault
	dnsProviderCredentials dnsProviderCredentialVault
	alertSecrets           *alerts.SecretStore
	pushKeys               pushKeyVault
	pushSubscriptions      pushSubscriptionStore
	baseDirectory          string
	prepareConfiguration   func(context.Context, config.Config, string) error
}

type clusterStateSnapshot struct {
	FormatVersion int                      `json:"format_version"`
	Configuration []byte                   `json:"configuration_toml"`
	Zones         []zone.Zone              `json:"zones"`
	Authorization store.AuthorizationState `json:"authorization"`
}

type clusterRuntimeConfiguration struct {
	PasskeysDisabled bool             `toml:"passkeys_disabled"`
	Resolver         config.Resolver  `toml:"resolver"`
	TSIGKeys         []config.TSIGKey `toml:"tsig_keys"`
	Blocking         config.Blocking  `toml:"blocking"`
	QueryLogEnabled  bool             `toml:"query_log_enabled"`
	// UniFi synchronization only runs on the writable node, but the settings
	// travel to every node so a promoted replica keeps publishing hosts instead
	// of silently freezing the records it inherited.
	UniFi config.UniFi `toml:"unifi"`
	// UniFiCredentials ride beside the settings and are banked in the receiving
	// node's vault, the same way TSIG secrets are. Neither side keeps them on
	// disk in the clear.
	UniFiCredentials unifi.Credentials `toml:"unifi_credentials"`
	// Dynamic DNS follows the writable primary. Every configured provider
	// credential travels with the settings so a promoted replica can immediately
	// resume all publishers. The singular field accepts snapshots from the
	// original one-provider implementation.
	DynamicDNS                    config.DynamicDNS               `toml:"dynamic_dns"`
	DynamicDNSProviderCredentials []clusterDNSProviderCredentials `toml:"dynamic_dns_provider_credentials,omitempty"`
	DynamicDNSCredentials         dnsprovider.Credentials         `toml:"dynamic_dns_credentials,omitempty"`
	// OIDC travels with redirect_url cleared. Every node serves the callback at
	// the same path and fills in its own host, so the section is identical
	// cluster-wide and a node that needs a different callback keeps its own
	// override instead of having the primary's imposed on it.
	OIDC config.OIDC `toml:"oidc"`
	// OIDCClientSecret is banked in the receiving node's vault like the UniFi
	// credentials. Without it a replica shows the sign-in button and then fails
	// the token exchange.
	OIDCClientSecret string `toml:"oidc_client_secret"`
	// Alerts travel whole, so a promoted replica sends to the same places and
	// a replica can say so when the lead stops answering. A snapshot from a
	// primary that predates them has none, which leaves this node's own alerts
	// as they are.
	Alerts *clusterAlerts `toml:"alerts,omitempty"`
}

// clusterAlerts is the alert state that follows the primary.
type clusterAlerts struct {
	// Settings is the [alerts] section with every destination's URL, keys,
	// and header values filled in from the primary's vault. The receiving
	// node banks them in its own vault, the way TSIG secrets cross, so the
	// destinations it writes to sable.toml carry none.
	Settings config.Alerts `toml:"settings"`
	// PushKey is the key browser pushes are signed with, as the vault keeps
	// it, base64 encoded. Browsers bind each subscription to the key they
	// subscribed with, so every node has to sign with the same one. It is
	// empty until a browser first asks for it.
	PushKey string `toml:"push_key,omitempty"`
	// PushSubscriptions are the browsers that turned alerts on. The list is
	// always whole, so an empty one means there are none.
	PushSubscriptions []clusterPushSubscription `toml:"push_subscriptions,omitempty"`
}

// clusterPushSubscription is a browser that turned alerts on, as it crosses
// to a replica.
type clusterPushSubscription struct {
	Endpoint  string    `toml:"endpoint"`
	P256DH    string    `toml:"p256dh"`
	Auth      string    `toml:"auth"`
	Label     string    `toml:"label,omitempty"`
	CreatedBy string    `toml:"created_by,omitempty"`
	CreatedAt time.Time `toml:"created_at"`
}

type clusterDNSProviderCredentials struct {
	Provider    string                  `toml:"provider"`
	Credentials dnsprovider.Credentials `toml:"credentials"`
}

func (replicator *clusterStateReplicator) setDNSProviderCredentials(credentials dnsProviderCredentialVault) {
	replicator.dnsProviderCredentials = credentials
}

// setAlerts has the replicator carry alert settings, destination secrets, and
// what browser pushes need. Alerts replicate only once all three are known,
// because a replica takes the snapshot's subscriptions as the whole list.
func (replicator *clusterStateReplicator) setAlerts(secrets *alerts.SecretStore, pushKeys pushKeyVault, subscriptions pushSubscriptionStore) {
	replicator.alertSecrets, replicator.pushKeys, replicator.pushSubscriptions = secrets, pushKeys, subscriptions
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
		Resolver:         active.Resolver,
		TSIGKeys:         tsigKeys,
		Blocking:         active.Blocking,
		QueryLogEnabled:  active.QueryLog.Enabled,
		UniFi:            active.UniFi,
		DynamicDNS:       active.DynamicDNS,
		OIDC:             replicatedOIDC(active.OIDC),
		PasskeysDisabled: active.Security.PasskeysDisabled,
	}
	if replicator.dnsProviderCredentials != nil {
		for _, provider := range active.DynamicDNS.ProviderNames() {
			if credentials, found := replicator.dnsProviderCredentials.Get(ctx, provider); found {
				runtimeConfiguration.DynamicDNSProviderCredentials = append(
					runtimeConfiguration.DynamicDNSProviderCredentials,
					clusterDNSProviderCredentials{Provider: provider, Credentials: credentials},
				)
			}
		}
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
	runtimeConfiguration.Alerts = replicator.captureAlerts(ctx, active.Alerts)
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
	if err := replicator.storeReplicatedDNSProviderCredentials(ctx, &runtimeConfiguration); err != nil {
		return err
	}
	if err := replicator.storeReplicatedOIDCSecret(ctx, &runtimeConfiguration); err != nil {
		return err
	}
	retiredAlertSecrets, err := replicator.storeReplicatedAlerts(ctx, &runtimeConfiguration)
	if err != nil {
		return err
	}
	activeConfiguration := replicatedRuntimeConfiguration(replicator.configuration.Current().Config)
	if runtimeConfiguration.Alerts == nil {
		// The primary said nothing about alerts, so this node's are neither
		// compared nor changed.
		activeConfiguration.Alerts = nil
	}
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
	if authorizationChanged {
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
	}
	replicator.forgetAlertSecrets(ctx, retiredAlertSecrets)
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
		Resolver:         source.Resolver,
		TSIGKeys:         source.TSIGKeys,
		Blocking:         source.Blocking,
		QueryLogEnabled:  source.QueryLog.Enabled,
		UniFi:            source.UniFi,
		DynamicDNS:       source.DynamicDNS,
		OIDC:             replicatedOIDC(source.OIDC),
		PasskeysDisabled: source.Security.PasskeysDisabled,
		Alerts:           &clusterAlerts{Settings: cloneAlertSettings(source.Alerts)},
	}
}

func (replicator *clusterStateReplicator) updateConfiguration(ctx context.Context, source clusterRuntimeConfiguration) error {
	return replicator.configuration.Update(ctx, func(candidate *config.Config) error {
		applyReplicatedRuntimeConfiguration(candidate, source)
		return nil
	})
}

func applyReplicatedRuntimeConfiguration(candidate *config.Config, source clusterRuntimeConfiguration) {
	candidate.Security.PasskeysDisabled = source.PasskeysDisabled
	candidate.Resolver = source.Resolver
	candidate.TSIGKeys = append([]config.TSIGKey(nil), source.TSIGKeys...)
	candidate.Blocking = source.Blocking
	candidate.QueryLog.Enabled = source.QueryLogEnabled
	candidate.UniFi = source.UniFi
	candidate.DynamicDNS = source.DynamicDNS
	// The override stays put. It names this node, and the primary has no say in
	// what hostname a browser reaches it at.
	override := candidate.OIDC.RedirectURL
	candidate.OIDC = source.OIDC
	candidate.OIDC.RedirectURL = override
	if source.Alerts != nil {
		candidate.Alerts = cloneAlertSettings(source.Alerts.Settings)
	}
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

func (replicator *clusterStateReplicator) storeReplicatedDNSProviderCredentials(
	ctx context.Context,
	runtimeConfiguration *clusterRuntimeConfiguration,
) error {
	credentialsByProvider := runtimeConfiguration.DynamicDNSProviderCredentials
	runtimeConfiguration.DynamicDNSProviderCredentials = nil
	if legacy := runtimeConfiguration.DynamicDNSCredentials; legacy != (dnsprovider.Credentials{}) {
		providers := runtimeConfiguration.DynamicDNS.ProviderNames()
		if len(providers) == 1 {
			credentialsByProvider = append(credentialsByProvider, clusterDNSProviderCredentials{Provider: providers[0], Credentials: legacy})
		}
	}
	runtimeConfiguration.DynamicDNSCredentials = dnsprovider.Credentials{}
	if replicator.dnsProviderCredentials == nil {
		return nil
	}
	var storeErrors []error
	for _, entry := range credentialsByProvider {
		if entry.Provider == "" || entry.Credentials == (dnsprovider.Credentials{}) {
			continue
		}
		if stored, found := replicator.dnsProviderCredentials.Get(ctx, entry.Provider); found && stored == entry.Credentials {
			continue
		}
		if err := replicator.dnsProviderCredentials.Replace(ctx, entry.Provider, entry.Credentials); err != nil {
			storeErrors = append(storeErrors, fmt.Errorf("store replicated %s DNS credentials: %w", entry.Provider, err))
		}
	}
	return errors.Join(storeErrors...)
}

// captureAlerts gathers the alert state that follows the primary. It gathers
// nothing on a node not given all the stores alerts live in, and nothing when
// the browsers cannot be read, which leaves each replica's alerts as they are
// rather than telling it there are no browsers.
func (replicator *clusterStateReplicator) captureAlerts(ctx context.Context, settings config.Alerts) *clusterAlerts {
	if replicator.alertSecrets == nil || replicator.pushKeys == nil || replicator.pushSubscriptions == nil {
		return nil
	}
	subscriptions, err := replicator.pushSubscriptions.PushSubscriptions(ctx)
	if err != nil {
		return nil
	}
	captured := &clusterAlerts{Settings: cloneAlertSettings(settings)}
	captured.Settings.Destinations = replicator.alertSecrets.Hydrate(ctx, captured.Settings.Destinations)
	// A key the vault cannot read right now is left out, which leaves each
	// replica's key as it is.
	if sealed, err := replicator.pushKeys.Sealed(ctx); err == nil && len(sealed) > 0 {
		captured.PushKey = base64.StdEncoding.EncodeToString(sealed)
	}
	for _, subscription := range subscriptions {
		captured.PushSubscriptions = append(captured.PushSubscriptions, clusterPushSubscription{
			Endpoint: subscription.Endpoint, P256DH: subscription.P256DH, Auth: subscription.Auth,
			Label: subscription.Label, CreatedBy: subscription.CreatedBy, CreatedAt: subscription.CreatedAt,
		})
	}
	// The store orders browsers by when they subscribed, which can tie. The
	// snapshot must not change unless the browsers do, or every capture
	// would look like a new generation.
	slices.SortFunc(captured.PushSubscriptions, func(left, right clusterPushSubscription) int {
		return strings.Compare(left.Endpoint, right.Endpoint)
	})
	return captured
}

// storeReplicatedAlerts banks what the primary sent about alerts: destination
// secrets into this node's vault, the push key, and the browsers. It leaves
// only the settings, without their secrets, to compare with what this node
// keeps in sable.toml, and returns the destinations whose secrets to forget
// once the rest of the state is in place. Like the UniFi credentials, secrets
// count as no change to the configuration: the dispatcher reads the vault
// every round.
func (replicator *clusterStateReplicator) storeReplicatedAlerts(
	ctx context.Context,
	runtimeConfiguration *clusterRuntimeConfiguration,
) ([]string, error) {
	incoming := runtimeConfiguration.Alerts
	if incoming == nil {
		return nil, nil
	}
	pushKey, subscriptions := incoming.PushKey, incoming.PushSubscriptions
	incoming.PushKey, incoming.PushSubscriptions = "", nil
	var storeErrors []error
	kept := make(map[string]bool, len(incoming.Settings.Destinations))
	for index := range incoming.Settings.Destinations {
		destination := &incoming.Settings.Destinations[index]
		secrets := alerts.SecretsOf(*destination)
		*destination = alerts.Strip(*destination)
		kept[destination.ID] = true
		if replicator.alertSecrets == nil {
			continue
		}
		if err := replicator.bankAlertSecrets(ctx, destination.ID, secrets); err != nil {
			storeErrors = append(storeErrors, fmt.Errorf("store replicated secrets of alert destination %q: %w", destination.Label(), err))
		}
	}
	if pushKey != "" && replicator.pushKeys != nil {
		sealed, err := base64.StdEncoding.DecodeString(pushKey)
		if err == nil {
			err = replicator.pushKeys.Replace(ctx, sealed)
		}
		if err != nil {
			storeErrors = append(storeErrors, fmt.Errorf("store replicated push key: %w", err))
		}
	}
	if replicator.pushSubscriptions != nil {
		if err := replicator.replacePushSubscriptions(ctx, subscriptions); err != nil {
			storeErrors = append(storeErrors, err)
		}
	}
	var retired []string
	for _, destination := range replicator.configuration.Current().Config.Alerts.Destinations {
		if !kept[destination.ID] {
			retired = append(retired, destination.ID)
		}
	}
	return retired, errors.Join(storeErrors...)
}

// bankAlertSecrets makes this node's vault hold what the primary's holds for
// one destination. When the primary holds none, neither does this node: a
// secret left behind would send where the primary no longer does.
func (replicator *clusterStateReplicator) bankAlertSecrets(ctx context.Context, id string, secrets alerts.Secrets) error {
	stored, found := replicator.alertSecrets.Secrets(ctx, id)
	switch {
	case secrets.Empty() && !found:
		return nil
	case secrets.Empty():
		return replicator.alertSecrets.Forget(ctx, id)
	case found && sameAlertSecrets(stored, secrets):
		return nil
	default:
		return replicator.alertSecrets.Put(ctx, id, secrets)
	}
}

// replacePushSubscriptions makes this node's browsers exactly the primary's.
// Browsers can turn alerts on only at the primary, so there is nothing of this
// node's own to keep.
func (replicator *clusterStateReplicator) replacePushSubscriptions(ctx context.Context, incoming []clusterPushSubscription) error {
	current, err := replicator.pushSubscriptions.PushSubscriptions(ctx)
	if err != nil {
		return fmt.Errorf("read push subscriptions: %w", err)
	}
	wanted := make(map[string]bool, len(incoming))
	for _, subscription := range incoming {
		wanted[subscription.Endpoint] = true
	}
	held := make(map[string]webpush.Subscription, len(current))
	for _, subscription := range current {
		if wanted[subscription.Endpoint] {
			held[subscription.Endpoint] = subscription
			continue
		}
		if err := replicator.pushSubscriptions.DeletePushSubscription(ctx, subscription.Endpoint); err != nil {
			return fmt.Errorf("remove push subscription: %w", err)
		}
	}
	for _, replicated := range incoming {
		subscription := webpush.Subscription{
			Endpoint: replicated.Endpoint, P256DH: replicated.P256DH, Auth: replicated.Auth,
			Label: replicated.Label, CreatedBy: replicated.CreatedBy, CreatedAt: replicated.CreatedAt,
		}
		if subscription.Endpoint == "" {
			continue
		}
		if existing, found := held[subscription.Endpoint]; found && samePushSubscription(existing, subscription) {
			continue
		}
		if err := replicator.pushSubscriptions.SavePushSubscription(ctx, subscription); err != nil {
			return fmt.Errorf("save push subscription: %w", err)
		}
	}
	return nil
}

// forgetAlertSecrets retires the secrets of destinations the primary removed.
// It is best effort: a secret left behind names no destination, so nothing
// sends with it.
func (replicator *clusterStateReplicator) forgetAlertSecrets(ctx context.Context, ids []string) {
	if replicator.alertSecrets == nil {
		return
	}
	for _, id := range ids {
		_ = replicator.alertSecrets.Forget(ctx, id)
	}
}

// cloneAlertSettings copies the [alerts] section, so a snapshot never shares
// a slice with the running configuration.
func cloneAlertSettings(settings config.Alerts) config.Alerts {
	settings.Destinations = slices.Clone(settings.Destinations)
	for index := range settings.Destinations {
		settings.Destinations[index].Sends = slices.Clone(settings.Destinations[index].Sends)
		settings.Destinations[index].Headers = slices.Clone(settings.Destinations[index].Headers)
	}
	return settings
}

func sameAlertSecrets(left, right alerts.Secrets) bool {
	return left.URL == right.URL && left.PushoverToken == right.PushoverToken &&
		left.PushoverUser == right.PushoverUser && slices.Equal(left.Headers, right.Headers)
}

// samePushSubscription compares subscriptions to the second, since databases
// keep subscription times at different precisions.
func samePushSubscription(left, right webpush.Subscription) bool {
	return left.Endpoint == right.Endpoint && left.P256DH == right.P256DH && left.Auth == right.Auth &&
		left.Label == right.Label && left.CreatedBy == right.CreatedBy && left.CreatedAt.Unix() == right.CreatedAt.Unix()
}
