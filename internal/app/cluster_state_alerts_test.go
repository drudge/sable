package app

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/drudge/sable/internal/alerts"
	"github.com/drudge/sable/internal/config"
	"github.com/drudge/sable/internal/webpush"
	"github.com/pelletier/go-toml/v2"
)

// memoryPushSubscriptions is the database's list of browsers, in memory. It
// hands the list back in a different order each time, as the database may for
// browsers that subscribed in the same instant, and counts its writes.
type memoryPushSubscriptions struct {
	mu            sync.Mutex
	subscriptions map[string]webpush.Subscription
	reversed      bool
	writes        int
}

func newMemoryPushSubscriptions(subscriptions ...webpush.Subscription) *memoryPushSubscriptions {
	store := &memoryPushSubscriptions{subscriptions: make(map[string]webpush.Subscription)}
	for _, subscription := range subscriptions {
		store.subscriptions[subscription.Endpoint] = subscription
	}
	return store
}

func (store *memoryPushSubscriptions) PushSubscriptions(context.Context) ([]webpush.Subscription, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	list := make([]webpush.Subscription, 0, len(store.subscriptions))
	for _, subscription := range store.subscriptions {
		list = append(list, subscription)
	}
	slices.SortFunc(list, func(left, right webpush.Subscription) int { return strings.Compare(left.Endpoint, right.Endpoint) })
	if store.reversed {
		slices.Reverse(list)
	}
	store.reversed = !store.reversed
	return list, nil
}

func (store *memoryPushSubscriptions) SavePushSubscription(_ context.Context, subscription webpush.Subscription) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	store.writes++
	store.subscriptions[subscription.Endpoint] = subscription
	return nil
}

func (store *memoryPushSubscriptions) DeletePushSubscription(_ context.Context, endpoint string) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	store.writes++
	delete(store.subscriptions, endpoint)
	return nil
}

func (store *memoryPushSubscriptions) endpoints() []string {
	store.mu.Lock()
	defer store.mu.Unlock()
	endpoints := make([]string, 0, len(store.subscriptions))
	for endpoint, subscription := range store.subscriptions {
		endpoints = append(endpoints, endpoint+" "+subscription.Label)
	}
	slices.Sort(endpoints)
	return endpoints
}

// replicatedNode is one node's alert state: its configuration, its vault, and its
// browsers.
type replicatedNode struct {
	path          string
	manager       *config.Manager
	applies       int
	vault         *memoryBackupVault
	secrets       *alerts.SecretStore
	pushKeys      *pushKeyStore
	subscriptions *memoryPushSubscriptions
	replicator    *clusterStateReplicator
}

func newReplicatedNode(t *testing.T, configuration config.Config, secrets map[string]alerts.Secrets, subscriptions ...webpush.Subscription) *replicatedNode {
	t.Helper()
	ctx := context.Background()
	node := &replicatedNode{path: filepath.Join(t.TempDir(), "sable.toml"), vault: &memoryBackupVault{}}
	encoded, err := toml.Marshal(configuration)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(node.path, encoded, 0o600); err != nil {
		t.Fatal(err)
	}
	node.manager = config.NewManager(node.path, configuration, func(context.Context, config.Config, config.Config) error {
		node.applies++
		return nil
	})
	// Loading normalizes in production, so the file here is written the same
	// way before anything is compared with it.
	if err := node.manager.Update(ctx, func(*config.Config) error { return nil }); err != nil {
		t.Fatal(err)
	}
	node.applies = 0
	node.secrets = alerts.NewSecretStore(node.vault)
	for id, destinationSecrets := range secrets {
		if err := node.secrets.Put(ctx, id, destinationSecrets); err != nil {
			t.Fatal(err)
		}
	}
	node.pushKeys = newPushKeyStore(node.vault)
	if _, err := node.pushKeys.PushKey(ctx); err != nil {
		t.Fatal(err)
	}
	node.subscriptions = newMemoryPushSubscriptions(subscriptions...)
	node.replicator = newClusterStateReplicator(node.manager, newTestZoneManager(t, nil), nil, newTestTSIGStore(), newTestUniFiCredentials(), newTestOIDCSecrets())
	node.replicator.setAlerts(node.secrets, node.pushKeys, node.subscriptions)
	return node
}

// replicate carries the primary's state to a replica, as one generation does.
func replicate(t *testing.T, primary, replica *replicatedNode) {
	t.Helper()
	contents, err := primary.replicator.Capture(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if err := replica.replicator.Apply(context.Background(), contents); err != nil {
		t.Fatal(err)
	}
}

func (node *replicatedNode) alertSettings(t *testing.T) []byte {
	t.Helper()
	encoded, err := toml.Marshal(node.manager.Current().Config.Alerts)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

func primaryAlertConfiguration() config.Config {
	configuration := config.Defaults()
	configuration.Alerts.Send.Insights = false
	configuration.Alerts.Send.Backups = config.AlertBackupsAll
	configuration.Alerts.SignIns.After = 3
	configuration.Alerts.Destinations = []config.AlertDestination{
		{ID: "chat", Name: "Home Slack", Format: config.AlertFormatSlack, Sends: []string{config.AlertGroupCluster}},
		{ID: "phone", Name: "Phone", Format: config.AlertFormatPushover},
		{ID: "topic", Name: "Topic", Format: config.AlertFormatText, NtfyReceipt: true},
		{ID: "browsers", Format: config.AlertFormatBrowser},
	}
	return configuration
}

func primaryAlertSecrets() map[string]alerts.Secrets {
	return map[string]alerts.Secrets{
		"chat":  {URL: "https://hooks.slack.com/services/T0/B0/slack-token"},
		"phone": {PushoverToken: "pushover-app-token", PushoverUser: "pushover-user-key"},
		"topic": {URL: "https://ntfy.example.test/sable", Headers: []config.AlertHeader{{Name: "Authorization", Value: "Bearer ntfy-token"}}},
	}
}

var (
	laptop = webpush.Subscription{Endpoint: "https://push.example.test/laptop", P256DH: "laptop-key", Auth: "laptop-auth",
		Label: "Firefox on Mac", CreatedBy: "admin", CreatedAt: time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)}
	phone = webpush.Subscription{Endpoint: "https://push.example.test/phone", P256DH: "phone-key", Auth: "phone-auth",
		Label: "Safari on iPhone", CreatedBy: "admin", CreatedAt: time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)}
)

func TestClusterStateReplicatesAlertsWithTheirSecretsAndBrowsers(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	primary := newReplicatedNode(t, primaryAlertConfiguration(), primaryAlertSecrets(), laptop, phone)
	// The replica ran alone before it joined: it has a destination of its own,
	// stale secrets under an ID the primary also uses, its own push key, and
	// browsers of its own.
	replicaConfiguration := config.Defaults()
	replicaConfiguration.Alerts.Destinations = []config.AlertDestination{{ID: "old", Name: "Old hook"}, {ID: "chat", Format: config.AlertFormatSlack}}
	staleLaptop := laptop
	staleLaptop.Label = "Old label"
	replica := newReplicatedNode(t, replicaConfiguration, map[string]alerts.Secrets{
		"old":  {URL: "https://old.example.test/hook"},
		"chat": {URL: "https://hooks.slack.com/services/stale"},
	}, staleLaptop, webpush.Subscription{Endpoint: "https://push.example.test/gone", P256DH: "gone", Auth: "gone"})

	replicate(t, primary, replica)

	if got, want := replica.alertSettings(t), primary.alertSettings(t); !bytes.Equal(got, want) {
		t.Fatalf("replica alert settings:\n%s\nwant:\n%s", got, want)
	}
	written, err := os.ReadFile(replica.path)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{"slack-token", "pushover-app-token", "pushover-user-key", "ntfy-token", "Authorization"} {
		if strings.Contains(string(written), secret) {
			t.Fatalf("the replica wrote %q to sable.toml", secret)
		}
	}
	// With its own vault, the replica fills in each destination as the
	// primary would, so it can send.
	fromPrimary := primary.secrets.Hydrate(ctx, primary.manager.Current().Config.Alerts.Destinations)
	fromReplica := replica.secrets.Hydrate(ctx, replica.manager.Current().Config.Alerts.Destinations)
	for index := range fromPrimary {
		if !sameAlertSecrets(alerts.SecretsOf(fromReplica[index]), alerts.SecretsOf(fromPrimary[index])) {
			t.Errorf("replica destination %q = %+v, want %+v", fromReplica[index].ID, fromReplica[index], fromPrimary[index])
		}
	}
	if _, found := replica.secrets.Secrets(ctx, "old"); found {
		t.Error("the replica kept the secrets of a destination the primary does not have")
	}
	primaryKey, err := primary.pushKeys.PushKey(ctx)
	if err != nil {
		t.Fatal(err)
	}
	replicaKey, err := replica.pushKeys.PushKey(ctx)
	if err != nil || !replicaKey.Equal(primaryKey) {
		t.Fatalf("the replica signs pushes with its own key: %v", err)
	}
	// It keeps signing with it after a restart.
	restartedKey, err := newPushKeyStore(replica.vault).PushKey(ctx)
	if err != nil || !restartedKey.Equal(primaryKey) {
		t.Fatalf("the replicated push key was not sealed in the vault: %v", err)
	}
	if got, want := replica.subscriptions.endpoints(), primary.subscriptions.endpoints(); !slices.Equal(got, want) {
		t.Fatalf("replica browsers = %v, want %v", got, want)
	}
}

func TestClusterStateAlertReplicationSettlesAndFollowsChanges(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	for _, test := range []struct {
		name string
		// change is what happens on the primary after the replica caught up.
		change func(t *testing.T, primary *replicatedNode)
		// rewrites is whether the replica writes its configuration again.
		rewrites bool
		// browserWrites counts the replica's writes to its browser list.
		browserWrites int
		check         func(t *testing.T, replica *replicatedNode)
	}{
		{name: "nothing changed", change: func(*testing.T, *replicatedNode) {}},
		{
			name: "a rotated webhook URL reaches the vault and leaves the file alone",
			change: func(t *testing.T, primary *replicatedNode) {
				if err := primary.secrets.Put(ctx, "chat", alerts.Secrets{URL: "https://hooks.slack.com/services/T0/B0/rotated"}); err != nil {
					t.Fatal(err)
				}
			},
			check: func(t *testing.T, replica *replicatedNode) {
				if secrets, _ := replica.secrets.Secrets(ctx, "chat"); secrets.URL != "https://hooks.slack.com/services/T0/B0/rotated" {
					t.Fatalf("replica webhook URL = %q", secrets.URL)
				}
			},
		},
		{
			name: "a removed destination takes its secrets with it",
			change: func(t *testing.T, primary *replicatedNode) {
				if err := primary.manager.Update(ctx, func(candidate *config.Config) error {
					candidate.Alerts.Destinations = slices.DeleteFunc(candidate.Alerts.Destinations, func(destination config.AlertDestination) bool {
						return destination.ID == "phone"
					})
					return nil
				}); err != nil {
					t.Fatal(err)
				}
			},
			rewrites: true,
			check: func(t *testing.T, replica *replicatedNode) {
				if _, found := replica.secrets.Secrets(ctx, "phone"); found {
					t.Fatal("the replica kept the Pushover keys of a removed destination")
				}
			},
		},
		{
			name: "cleared keys are cleared on the replica too",
			change: func(t *testing.T, primary *replicatedNode) {
				if err := primary.secrets.Forget(ctx, "phone"); err != nil {
					t.Fatal(err)
				}
			},
			check: func(t *testing.T, replica *replicatedNode) {
				if _, found := replica.secrets.Secrets(ctx, "phone"); found {
					t.Fatal("the replica kept Pushover keys the primary cleared")
				}
			},
		},
		{
			name: "pausing alerts reaches the replica",
			change: func(t *testing.T, primary *replicatedNode) {
				if err := primary.manager.Update(ctx, func(candidate *config.Config) error {
					candidate.Alerts.Paused = true
					return nil
				}); err != nil {
					t.Fatal(err)
				}
			},
			rewrites: true,
			check: func(t *testing.T, replica *replicatedNode) {
				if !replica.manager.Current().Config.Alerts.Paused {
					t.Fatal("the replica still sends")
				}
			},
		},
		{
			name: "a browser removed on the primary is removed on the replica",
			change: func(t *testing.T, primary *replicatedNode) {
				if err := primary.subscriptions.DeletePushSubscription(ctx, phone.Endpoint); err != nil {
					t.Fatal(err)
				}
			},
			browserWrites: 1,
			check: func(t *testing.T, replica *replicatedNode) {
				if got := replica.subscriptions.endpoints(); !slices.Equal(got, []string{laptop.Endpoint + " " + laptop.Label}) {
					t.Fatalf("replica browsers = %v", got)
				}
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			primary := newReplicatedNode(t, primaryAlertConfiguration(), primaryAlertSecrets(), laptop, phone)
			replica := newReplicatedNode(t, config.Defaults(), nil)
			replicate(t, primary, replica)
			applies, browserWrites := replica.applies, replica.subscriptions.writes
			test.change(t, primary)
			replicate(t, primary, replica)
			if rewrote := replica.applies != applies; rewrote != test.rewrites {
				t.Fatalf("the replica rewrote its configuration: %t, want %t", rewrote, test.rewrites)
			}
			if writes := replica.subscriptions.writes - browserWrites; writes != test.browserWrites {
				t.Fatalf("the replica wrote its browsers %d times, want %d", writes, test.browserWrites)
			}
			if got, want := replica.alertSettings(t), primary.alertSettings(t); !bytes.Equal(got, want) {
				t.Fatalf("replica alert settings:\n%s\nwant:\n%s", got, want)
			}
			if test.check != nil {
				test.check(t, replica)
			}
		})
	}
}

// A primary from before alerts replicated says nothing about them, which is
// not the same as saying there are none.
func TestClusterStateFromAnOlderPrimaryLeavesAlertsAlone(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	older := newReplicatedNode(t, config.Defaults(), nil)
	older.replicator.setAlerts(nil, nil, nil)
	replica := newReplicatedNode(t, primaryAlertConfiguration(), primaryAlertSecrets(), laptop)
	settings := replica.alertSettings(t)
	key, err := replica.pushKeys.PushKey(ctx)
	if err != nil {
		t.Fatal(err)
	}
	replicate(t, older, replica)
	if got := replica.alertSettings(t); !bytes.Equal(got, settings) {
		t.Fatalf("replica alert settings changed to:\n%s", got)
	}
	if secrets, found := replica.secrets.Secrets(ctx, "chat"); !found || secrets.URL == "" {
		t.Fatal("the replica lost its destination secrets")
	}
	if kept, err := replica.pushKeys.PushKey(ctx); err != nil || !kept.Equal(key) {
		t.Fatalf("the replica lost its push key: %v", err)
	}
	if got := replica.subscriptions.endpoints(); len(got) != 1 {
		t.Fatalf("the replica lost its browsers: %v", got)
	}
}

// The primary captures its state every second and publishes a new generation
// whenever the capture changes, so the same alert state has to capture the
// same way each time, whatever order the database lists browsers in.
func TestClusterStateCapturesTheSameAlertsTheSameWay(t *testing.T) {
	t.Parallel()
	primary := newReplicatedNode(t, primaryAlertConfiguration(), primaryAlertSecrets(), laptop, phone)
	first, err := primary.replicator.Capture(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for range 3 {
		again, err := primary.replicator.Capture(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(again, first) {
			t.Fatal("an unchanged alert state captured differently")
		}
	}
}

// Insights alerts come from the lead, so a replica takes the primary's
// Insights settings, and a promoted replica judges findings the way the old
// lead did.
func TestClusterStateReplicatesInsightSettings(t *testing.T) {
	t.Parallel()
	configuration := config.Defaults()
	configuration.Insights.Findings.CheckIn.Mode = config.InsightModeShow
	configuration.Insights.Findings.WentQuiet.MinimumDailyLookups = 200
	primary := newReplicatedNode(t, configuration, nil)
	replica := newReplicatedNode(t, config.Defaults(), nil)
	replicate(t, primary, replica)
	findings := replica.manager.Current().Config.Insights.Findings
	if findings.CheckIn.Mode != config.InsightModeShow || findings.WentQuiet.MinimumDailyLookups != 200 {
		t.Fatalf("replica Insights settings = %+v", findings)
	}
	// Carried again unchanged, they leave the replica's configuration alone.
	applies := replica.applies
	replicate(t, primary, replica)
	if replica.applies != applies {
		t.Fatal("replicating the same Insights settings rewrote the configuration")
	}
}
