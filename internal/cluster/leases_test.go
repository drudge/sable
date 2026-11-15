package cluster

import (
	"context"
	"fmt"
	"slices"
	"sync"
	"testing"
	"time"
)

// leaseStore stands in for a node's lease table: rows keyed by owner and
// address, the owner's counter, and how often a mirror wrote something.
type leaseStore struct {
	mu      sync.Mutex
	rows    map[[2]string]SharedLease
	counter map[string]int64
	changed int
}

func newLeaseStore() *leaseStore {
	return &leaseStore{rows: map[[2]string]SharedLease{}, counter: map[string]int64{}}
}

// save writes a lease the node owns with its next sequence number.
func (store *leaseStore) save(nodeID, address, hostname string) {
	store.mu.Lock()
	defer store.mu.Unlock()
	store.counter[nodeID]++
	store.rows[[2]string{nodeID, address}] = SharedLease{NodeID: nodeID, Address: address, ScopeID: "lan",
		ClientKey: "01:" + address, Hostname: hostname, State: "active", Seq: store.counter[nodeID],
		ExpiresAt: time.Now().Add(time.Hour).UTC().Truncate(time.Second)}
}

func (store *leaseStore) Held(context.Context) (map[string]int64, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	held := map[string]int64{}
	for key, row := range store.rows {
		held[key[0]] = max(held[key[0]], row.Seq)
	}
	return held, nil
}

func (store *leaseStore) Since(_ context.Context, nodeID string, seq int64, limit int) ([]SharedLease, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	var found []SharedLease
	for key, row := range store.rows {
		if key[0] == nodeID && row.Seq > seq {
			found = append(found, row)
		}
	}
	slices.SortFunc(found, func(a, b SharedLease) int { return int(a.Seq - b.Seq) })
	return found[:min(limit, len(found))], nil
}

func (store *leaseStore) Mirror(_ context.Context, rows []SharedLease) (int, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	written := 0
	for _, row := range rows {
		key := [2]string{row.NodeID, row.Address}
		if held, ok := store.rows[key]; ok && held.Seq >= row.Seq {
			continue
		}
		store.rows[key] = row
		written++
	}
	return written, nil
}

func (store *leaseStore) Raise(_ context.Context, nodeID string, seq int64) (bool, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.counter[nodeID] >= seq {
		return false, nil
	}
	store.counter[nodeID] = seq
	for key, row := range store.rows {
		if key[0] == nodeID {
			store.counter[nodeID]++
			row.Seq = store.counter[nodeID]
			store.rows[key] = row
		}
	}
	return true, nil
}

func (store *leaseStore) Changed() {
	store.mu.Lock()
	defer store.mu.Unlock()
	store.changed++
}

func (store *leaseStore) mirror() LeaseMirror {
	return LeaseMirror{Held: store.Held, Since: store.Since, Mirror: store.Mirror, Raise: store.Raise, Changed: store.Changed}
}

func (store *leaseStore) hostnames(nodeID string) []string {
	store.mu.Lock()
	defer store.mu.Unlock()
	var names []string
	for key, row := range store.rows {
		if key[0] == nodeID {
			names = append(names, row.Hostname)
		}
	}
	slices.Sort(names)
	return names
}

func (store *leaseStore) seq(nodeID, address string) int64 {
	store.mu.Lock()
	defer store.mu.Unlock()
	return store.rows[[2]string{nodeID, address}].Seq
}

func mirroringCluster(t *testing.T) (*Service, *Service, *leaseStore, *leaseStore) {
	t.Helper()
	primary, replica := joinedClusterServices(t)
	lead, follower := newLeaseStore(), newLeaseStore()
	primary.SetLeaseMirror(lead.mirror())
	replica.SetLeaseMirror(follower.mirror())
	return primary, replica, lead, follower
}

// Every node holds every lease (docs/design/dhcp.md §3): a replica's own
// leases reach the primary on its heartbeat, and the primary's, with every
// other node's, come back on the sync response, each keeping its owner's
// sequence number.
func TestLeasesMirrorBothWaysThroughTheHeartbeat(t *testing.T) {
	t.Parallel()
	primary, replica, lead, follower := mirroringCluster(t)
	lead.save(primary.nodeID, "10.0.0.10", "printer")
	lead.save("gone-node", "10.0.0.200", "old-laptop")
	follower.save(replica.nodeID, "10.0.0.150", "phone")
	follower.save(replica.nodeID, "10.0.0.151", "tablet")

	// The first answer advertises the mirror; the next two carry it.
	synchronize(t, replica, 3)

	if got := lead.hostnames(replica.nodeID); !slices.Equal(got, []string{"phone", "tablet"}) {
		t.Fatalf("the primary holds %v of the replica's leases", got)
	}
	if got := follower.hostnames(primary.nodeID); !slices.Equal(got, []string{"printer"}) {
		t.Fatalf("the replica holds %v of the primary's leases", got)
	}
	if got := follower.hostnames("gone-node"); !slices.Equal(got, []string{"old-laptop"}) {
		t.Fatalf("the replica holds %v of a third node's leases", got)
	}
	if lead.seq(replica.nodeID, "10.0.0.151") != 2 || follower.seq(primary.nodeID, "10.0.0.10") != 1 {
		t.Fatal("a mirrored lease lost its owner's sequence number")
	}
	if lead.changed == 0 || follower.changed == 0 {
		t.Fatalf("mirrors changed %d and %d times; want a change on each side", lead.changed, follower.changed)
	}

	// A later lease travels on its own, and a renewal replaces the mirror.
	follower.save(replica.nodeID, "10.0.0.150", "phone-renamed")
	synchronize(t, replica, 1)
	if got := lead.hostnames(replica.nodeID); !slices.Equal(got, []string{"phone-renamed", "tablet"}) {
		t.Fatalf("after a renewal the primary holds %v", got)
	}
}

// A replica writes only its own rows on the primary: a heartbeat row that
// names another node is dropped, so no member can forge another's leases.
func TestPrimaryMirrorsOnlyTheSendersOwnLeases(t *testing.T) {
	t.Parallel()
	primary, replica, lead, follower := mirroringCluster(t)
	synchronize(t, replica, 1)
	follower.save(primary.nodeID, "10.0.0.10", "forged")
	follower.save(replica.nodeID, "10.0.0.150", "phone")
	report, _ := replica.leaseReportForPrimary(context.Background())
	report.Rows = append(report.Rows, SharedLease{NodeID: primary.nodeID, Address: "10.0.0.10", ScopeID: "lan",
		ClientKey: "01:x", Hostname: "forged", State: "active", Seq: 9})
	lead.exchangeAsPrimary(t, primary, replica.nodeID, report)
	if got := lead.hostnames(primary.nodeID); len(got) != 0 {
		t.Fatalf("the primary took %v as its own leases from a replica", got)
	}
	if got := lead.hostnames(replica.nodeID); !slices.Equal(got, []string{"phone"}) {
		t.Fatalf("the primary holds %v of the replica's leases", got)
	}
}

func (store *leaseStore) exchangeAsPrimary(t *testing.T, primary *Service, from string, report *LeaseReport) *LeaseReport {
	t.Helper()
	return primary.exchangeLeases(context.Background(), store.mirror(), from, report)
}

// A heartbeat carries at most leaseBatchLimit rows, and the rest follow on
// the next beats.
func TestLeaseMirrorSendsAtMostOneBatchABeat(t *testing.T) {
	t.Parallel()
	_, replica, lead, follower := mirroringCluster(t)
	for index := range leaseBatchLimit + 20 {
		follower.save(replica.nodeID, fmt.Sprintf("10.0.%d.%d", index/250, index%250+1), fmt.Sprintf("host-%d", index))
	}
	synchronize(t, replica, 2)
	if got := len(lead.hostnames(replica.nodeID)); got != leaseBatchLimit {
		t.Fatalf("one beat carried %d leases, want %d", got, leaseBatchLimit)
	}
	synchronize(t, replica, 1)
	if got := len(lead.hostnames(replica.nodeID)); got != leaseBatchLimit+20 {
		t.Fatalf("after the next beat the primary holds %d leases", got)
	}
}

// A replica whose database was wiped starts its counter again below what the
// primary already holds of it. It raises the counter past that and renumbers
// its rows, so its new leases aren't passed over as older than the mirrors
// and no number is used twice (docs/design/dhcp.md §3).
func TestLeaseMirrorWipedReplicaRaisesItsCounterPastThePrimary(t *testing.T) {
	t.Parallel()
	primary, replica, lead, follower := mirroringCluster(t)
	for _, address := range []string{"10.0.0.150", "10.0.0.151", "10.0.0.152"} {
		follower.save(replica.nodeID, address, "before")
	}
	synchronize(t, replica, 3)

	wiped := newLeaseStore()
	wiped.save(replica.nodeID, "10.0.0.150", "after-wipe")
	replica.SetLeaseMirror(wiped.mirror())
	synchronize(t, replica, 2)

	if got := wiped.seq(replica.nodeID, "10.0.0.150"); got <= 3 {
		t.Fatalf("the wiped replica's lease kept sequence %d, at or below the primary's 3", got)
	}
	if got := lead.hostnames(replica.nodeID); !slices.Contains(got, "after-wipe") {
		t.Fatalf("the primary holds %v; the lease written after the wipe never reached it", got)
	}
	_ = primary
}

// Without a mirror on either side nothing about leases crosses, and an older
// replica's heartbeat stays as it was.
func TestLeaseMirrorOffLeavesTheHeartbeatAlone(t *testing.T) {
	t.Parallel()
	primary, replica := joinedClusterServices(t)
	synchronize(t, replica, 2)
	report, _ := replica.leaseReportForPrimary(context.Background())
	if report != nil {
		t.Fatalf("a replica without a mirror reported %+v", report)
	}
	primary.mu.Lock()
	configuration, err := primary.syncConfigurationLocked(replica.nodeID, "", time.Now(), true)
	primary.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	if configuration.LeaseProtocol != 0 {
		t.Fatal("a primary without a mirror advertised one")
	}
}
