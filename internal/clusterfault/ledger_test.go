//go:build integration

package clusterfault

import (
	"fmt"
	"net/http"
	"net/url"
	"testing"
)

// write is one change the primary acknowledged: an A record in the ledger zone.
type write struct {
	name    string
	address string
}

// ledger records every write the cluster acknowledged, so a check can prove
// no acknowledged write was lost however the faults fell.
type ledger struct {
	acknowledged []write
	attempted    int
	// window holds acknowledged writes no replica had when the primary
	// crashed. A recovery promotion may lose them (docs/clustering.md), so
	// they are held to all-or-nothing instead of always surviving.
	window []write
}

// insideWindow moves the last count acknowledged writes into the window.
func (records *ledger) insideWindow(count int) {
	split := len(records.acknowledged) - count
	records.window = append(records.window, records.acknowledged[split:]...)
	records.acknowledged = records.acknowledged[:split]
}

// write adds the next ledger record through node and records it only when
// the node answers 200. A refused or failed write is not acknowledged and
// may or may not survive; the invariants only hold acknowledged ones.
func (records *ledger) write(node *member) bool {
	records.attempted++
	entry := write{
		name:    fmt.Sprintf("w%d", records.attempted),
		address: fmt.Sprintf("198.51.%d.%d", records.attempted/250, records.attempted%250+1),
	}
	status, err := node.postForm("/ui/zones/records/add", url.Values{
		"zone": {ledgerZone}, "name": {entry.name}, "type": {"A"}, "value": {entry.address}, "ttl": {"60"},
	})
	if err != nil || status != http.StatusOK {
		return false
	}
	records.acknowledged = append(records.acknowledged, entry)
	return true
}

// mustWrite writes through the current primary and fails the test if the
// write is not acknowledged.
func (records *ledger) mustWrite(t *testing.T, faults *faultCluster) {
	t.Helper()
	if !records.write(faults.primary()) {
		t.Fatalf("primary refused ledger write %d", records.attempted)
	}
}
