//go:build integration

package clusterfault

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/drudge/sable/internal/cluster"
	"github.com/drudge/sable/internal/clustertest"
	"github.com/drudge/sable/internal/dnsclient"
)

// stateKey names one cluster state: a node's term and generation.
type stateKey struct {
	term       uint64
	generation uint64
}

// invariants holds what the checker has seen so far, so each observation can
// be held against every earlier one.
type invariants struct {
	primaries map[uint64]string   // term -> the node that was primary in it
	serials   map[string]uint32   // node -> last SOA serial it served
	states    map[stateKey]uint32 // converged state -> its ledger SOA serial
}

func newInvariants() *invariants {
	return &invariants{primaries: map[uint64]string{}, serials: map[string]uint32{}, states: map[stateKey]uint32{}}
}

// observe checks one round of every running node: one primary per term
// (fencing, #529) and SOA serials that never go backward on a node, compared
// with RFC 1982 serial arithmetic (RFC 1982 §3.2, RFC 1035 §3.3.13).
func (checks *invariants) observe(t *testing.T, faults *faultCluster) {
	t.Helper()
	for _, node := range faults.running() {
		state := node.state(t)
		if state.LocalRole == cluster.RolePrimary {
			checks.checkPrimary(t, state)
		}
		checks.observeSerial(t, node)
	}
}

// observeSerial checks that the ledger SOA serial node serves, if it serves
// one, is not older than the last one seen on it. It needs no cluster API,
// so it also works while a node restarts.
func (checks *invariants) observeSerial(t *testing.T, node *member) bool {
	t.Helper()
	serial, ok := ledgerSerial(node)
	if !ok {
		return false
	}
	if last, seen := checks.serials[node.name]; seen && serialLess(serial, last) {
		t.Errorf("%s SOA serial went backward: %d after %d", node.name, serial, last)
	}
	checks.serials[node.name] = serial
	return true
}

func (checks *invariants) checkPrimary(t *testing.T, state cluster.State) {
	t.Helper()
	if earlier, seen := checks.primaries[state.Term]; seen && earlier != state.NodeID {
		t.Errorf("two primaries in term %d: %s and %s", state.Term, earlier, state.NodeID)
	}
	checks.primaries[state.Term] = state.NodeID
}

// converged gives the cluster until clustertest.Timeout to settle: every
// running node synchronized, serving the primary's SOA serial, and answering
// every acknowledged write. Writes reach replicas only once the primary folds
// them into a new generation, so a synchronized cluster alone isn't enough.
// It then checks all three, and that a state seen before still has the serial
// it had then.
func (checks *invariants) converged(t *testing.T, faults *faultCluster, records *ledger) {
	t.Helper()
	deadline := time.Now().Add(clustertest.Timeout)
	for time.Now().Before(deadline) && !settled(t, faults, records) {
		time.Sleep(clustertest.PollingInterval)
	}
	faults.waitSynchronized()
	checks.observe(t, faults)
	primary := faults.primary()
	serial, ok := ledgerSerial(primary)
	if !ok {
		t.Fatalf("%s does not serve the ledger zone SOA", primary.name)
	}
	for _, node := range faults.running() {
		if got, _ := ledgerSerial(node); got != serial {
			t.Errorf("SOA serials differ after convergence: %s=%d %s=%d", primary.name, serial, node.name, got)
		}
		checks.checkLedger(t, node, records)
	}
	state := primary.state(t)
	key := stateKey{term: state.Term, generation: state.Generation}
	if earlier, seen := checks.states[key]; seen && earlier != serial {
		t.Errorf("term %d generation %d held SOA serial %d before and %d now", key.term, key.generation, earlier, serial)
	}
	checks.states[key] = serial
}

// settled reports whether every running node serves the primary's ledger SOA
// serial and every acknowledged write.
func settled(t *testing.T, faults *faultCluster, records *ledger) bool {
	t.Helper()
	running := faults.running()
	serial, ok := ledgerSerial(running[0])
	for _, node := range running {
		got, served := ledgerSerial(node)
		if !ok || !served || got != serial || missingWrite(node, records) {
			return false
		}
	}
	return true
}

func missingWrite(node *member, records *ledger) bool {
	for _, entry := range records.acknowledged {
		if resolveA(node, entry.name+"."+ledgerZone) != entry.address {
			return true
		}
	}
	return false
}

func (checks *invariants) checkLedger(t *testing.T, node *member, records *ledger) {
	t.Helper()
	for _, entry := range records.acknowledged {
		if got := resolveA(node, entry.name+"."+ledgerZone); got != entry.address {
			t.Errorf("%s lost acknowledged write %s (A %s): answered %q", node.name, entry.name, entry.address, got)
		}
	}
}

func ledgerSerial(node *member) (uint32, bool) {
	response, err := query(node, ledgerZone, "SOA")
	if err != nil || len(response.Answer) != 1 {
		return 0, false
	}
	soa, ok := response.Answer[0].(*dns.SOA)
	if !ok {
		return 0, false
	}
	return soa.Serial, true
}

func resolveA(node *member, name string) string {
	response, err := query(node, name, "A")
	if err != nil || len(response.Answer) != 1 {
		return ""
	}
	if record, ok := response.Answer[0].(*dns.A); ok {
		return record.A.String()
	}
	return ""
}

func query(node *member, name, recordType string) (*dns.Msg, error) {
	result, err := dnsclient.Query(context.Background(), dnsclient.Request{
		Server: node.ports.DNS, Name: name, Type: recordType, Transport: "udp", Timeout: time.Second,
	})
	if err != nil {
		return nil, err
	}
	if result.Response.Rcode != dns.RcodeSuccess {
		return nil, fmt.Errorf("%s %s: %s", name, recordType, dns.RcodeToString[result.Response.Rcode])
	}
	return result.Response, nil
}

// serialLess reports whether a precedes b in RFC 1982 §3.2 serial arithmetic.
func serialLess(a, b uint32) bool {
	return a != b && int32(b-a) > 0
}
