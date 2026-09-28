package cluster

import (
	"context"
	"encoding/json"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/drudge/sable/internal/querylog"
)

// identityStore stands in for a node's store: it answers reads with what it
// holds, remembers when it was asked from, and hands every recorded batch to
// a channel.
type identityStore struct {
	mu       sync.Mutex
	held     []querylog.ClientIdentity
	since    []time.Time
	recorded chan []querylog.ClientIdentity
}

func (store *identityStore) Read(_ context.Context, since time.Time) ([]querylog.ClientIdentity, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	store.since = append(store.since, since)
	found := make([]querylog.ClientIdentity, 0, len(store.held))
	for _, identity := range store.held {
		if !identity.LastSeen.Before(since) {
			found = append(found, identity)
		}
	}
	return found, nil
}

func (store *identityStore) Record(_ context.Context, identities []querylog.ClientIdentity) error {
	store.recorded <- identities
	return nil
}

func (store *identityStore) reads() int {
	store.mu.Lock()
	defer store.mu.Unlock()
	return len(store.since)
}

func (store *identityStore) handler(lookback time.Duration) ClientIdentities {
	return ClientIdentities{Read: store.Read, Record: store.Record, Lookback: lookback}
}

// sharingCluster is a primary that knows a neighbor sighting from an hour ago
// and a UniFi sighting from a minute ago, and a replica that knows nothing.
func sharingCluster(t *testing.T, now time.Time) (*Service, *Service, *identityStore) {
	t.Helper()
	primary, replica := joinedClusterServices(t)
	lead := &identityStore{held: []querylog.ClientIdentity{
		{Address: "10.0.7.108", MAC: "94:2a:6f:ae:4c:5c", Source: "unifi-network", Hostname: "Basement U7 Pro", LastSeen: now.Add(-time.Minute)},
		{Address: "2603:7083:af01:1500:8966:3866:2276:d9e1", MAC: "66:ca:20:91:ab:fb", Source: "neighbor", LastSeen: now.Add(-time.Hour)},
		{Address: "10.0.7.88", MAC: "bc:24:11:91:d5:a4", Source: "unifi", Hostname: "dokploy", Kind: "server", KindConfidence: 48, KindSet: true, LastSeen: now.Add(-2 * time.Minute)},
	}}
	primary.SetClientIdentities(lead.handler(15 * 24 * time.Hour))
	follower := &identityStore{recorded: make(chan []querylog.ClientIdentity, 8)}
	replica.SetClientIdentities(follower.handler(15 * 24 * time.Hour))
	return primary, replica, follower
}

func receiveIdentities(t *testing.T, store *identityStore) []querylog.ClientIdentity {
	t.Helper()
	select {
	case identities := <-store.recorded:
		return identities
	case <-time.After(5 * time.Second):
		t.Fatal("the replica recorded nothing")
		return nil
	}
}

func identityAddresses(identities []querylog.ClientIdentity) []string {
	addresses := make([]string, 0, len(identities))
	for _, identity := range identities {
		addresses = append(addresses, identity.Address)
	}
	slices.Sort(addresses)
	return addresses
}

// A replica first hears the lead's recent sightings, then everything within
// the lookback once the lead has read it, with each sighting's source, name,
// and suggested type intact.
func TestReplicaRecordsTheLeadsClientIdentities(t *testing.T) {
	t.Parallel()
	now := time.Now()
	primary, replica, follower := sharingCluster(t, now)

	primary.gatherClientIdentitiesOnce(context.Background(), now)
	synchronize(t, replica, 1)
	recent := receiveIdentities(t, follower)
	if got := identityAddresses(recent); !slices.Equal(got, []string{"10.0.7.108", "10.0.7.88"}) {
		t.Fatalf("recent batch = %v, want the two sightings from the last 15 minutes", got)
	}

	// That synchronization asked for a full batch, which the next gathering
	// reads and the next synchronization carries.
	primary.gatherClientIdentitiesOnce(context.Background(), time.Now())
	synchronize(t, replica, 1)
	full := receiveIdentities(t, follower)
	if got := identityAddresses(full); len(got) != 3 {
		t.Fatalf("full batch = %v, want all three sightings", got)
	}
	index := slices.IndexFunc(full, func(identity querylog.ClientIdentity) bool { return identity.Address == "10.0.7.88" })
	if got := full[index]; got.Source != "unifi" || got.Hostname != "dokploy" || got.Kind != "server" || got.KindConfidence != 48 || !got.KindSet ||
		!got.SeenAt.Equal(now.Add(-2*time.Minute).UTC()) {
		t.Fatalf("dokploy arrived as %+v", got)
	}
}

// Recent sightings are carried once a minute, not in every one-second
// synchronization.
func TestLeadHandsEachReplicaRecentIdentitiesOncePerMinute(t *testing.T) {
	t.Parallel()
	now := time.Now()
	sharer := &identitySharer{}
	sharer.setRecent(json.RawMessage(`[]`))
	sharer.setFull(json.RawMessage(`[{"address":"10.0.7.1"}]`), now)
	if got := sharer.due("dns-2", now); string(got) != `[{"address":"10.0.7.1"}]` {
		t.Fatalf("first batch = %s, want the full one", got)
	}
	if got := sharer.due("dns-2", now.Add(time.Second)); got != nil {
		t.Fatalf("a second later the replica was handed %s", got)
	}
	if got := sharer.due("dns-2", now.Add(identityShareInterval)); string(got) != `[]` {
		t.Fatalf("a minute later the replica was handed %s, want the recent batch", got)
	}
	// A full batch gathered too long ago would leave a gap, so a new replica
	// gets the recent one and a fresh full read is asked for.
	later := now.Add(identityFullFreshness)
	if got := sharer.due("dns-3", later); string(got) != `[]` || !sharer.fullWanted() {
		t.Fatalf("a new replica got %s with a full read wanted %t", got, sharer.fullWanted())
	}
	// Twelve hours on, every replica is handed the whole picture again.
	sharer.setFull(json.RawMessage(`[{"address":"10.0.7.2"}]`), now.Add(identityFullEvery))
	if got := sharer.due("dns-2", now.Add(identityFullEvery)); string(got) != `[{"address":"10.0.7.2"}]` {
		t.Fatalf("after twelve hours the replica was handed %s, want the full batch", got)
	}
}

// Only the lead reads its store to share; a replica has nothing to hand out.
func TestClientIdentitiesAreGatheredOnlyByTheLead(t *testing.T) {
	t.Parallel()
	primary, replica := joinedClusterServices(t)
	for _, test := range []struct {
		name    string
		service *Service
		want    int
	}{
		{name: "the lead", service: primary, want: 1},
		{name: "a replica", service: replica, want: 0},
	} {
		store := &identityStore{}
		test.service.SetClientIdentities(store.handler(time.Hour))
		test.service.gatherClientIdentitiesOnce(context.Background(), time.Now())
		if got := store.reads(); got != test.want {
			t.Errorf("%s read its store %d times, want %d", test.name, got, test.want)
		}
	}
}

// A replica that is not set up to record what it is handed ignores it, as a
// release that predates sharing does.
func TestReplicaWithoutARecorderIgnoresSharedIdentities(t *testing.T) {
	t.Parallel()
	primary, replica := joinedClusterServices(t)
	lead := &identityStore{held: []querylog.ClientIdentity{{Address: "10.0.7.20", MAC: "f4:ab:5c:0b:47:8a", Source: "unifi", LastSeen: time.Now()}}}
	primary.SetClientIdentities(lead.handler(time.Hour))
	primary.gatherClientIdentitiesOnce(context.Background(), time.Now())
	synchronize(t, replica, 2)
}
