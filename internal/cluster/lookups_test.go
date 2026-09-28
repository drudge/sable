package cluster

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sync"
	"testing"
	"time"
)

// lookupRecorder passes synchronization to the primary and remembers whether
// each heartbeat carried lookups. An older primary never advertises that it
// takes them.
type lookupRecorder struct {
	primary *Service
	older   bool
	mu      sync.Mutex
	carried []bool
}

func (recorder *lookupRecorder) RoundTrip(request *http.Request) (*http.Response, error) {
	if request.URL.Path != syncPath {
		return serviceRoundTripper{primary: recorder.primary}.RoundTrip(request)
	}
	contents, err := io.ReadAll(request.Body)
	if err != nil {
		return nil, err
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(contents, &fields); err != nil {
		return nil, err
	}
	_, carried := fields["lookups"]
	recorder.mu.Lock()
	recorder.carried = append(recorder.carried, carried)
	recorder.mu.Unlock()
	request.Body = io.NopCloser(bytes.NewReader(contents))
	response, err := serviceRoundTripper{primary: recorder.primary}.RoundTrip(request)
	if err != nil || !recorder.older || response.StatusCode != http.StatusOK {
		return response, err
	}
	var configuration SyncConfiguration
	if err := json.NewDecoder(response.Body).Decode(&configuration); err != nil {
		return nil, err
	}
	configuration.LookupProtocol = 0
	return clusterTestResponse(request, http.StatusOK, configuration)
}

func (recorder *lookupRecorder) takeCarried() []bool {
	recorder.mu.Lock()
	defer recorder.mu.Unlock()
	carried := recorder.carried
	recorder.carried = nil
	return carried
}

func lookupCluster(t *testing.T, older bool, found map[string]time.Time) (*Service, *Service, *lookupRecorder) {
	t.Helper()
	primary, replica := joinedClusterServices(t)
	recorder := &lookupRecorder{primary: primary, older: older}
	replica.baseHTTPClient = &http.Client{Transport: recorder}
	replica.httpClient = replica.baseHTTPClient
	replica.clientsMu.Lock()
	clear(replica.memberClients)
	replica.clientsMu.Unlock()
	replica.SetLocalLookups(func(context.Context, time.Time) (map[string]time.Time, error) { return found, nil })
	return primary, replica, recorder
}

// A replica tells the lead when each client address last asked it anything,
// once after it reads its lookups and again every few minutes, and the lead
// lists every replica whether or not it has reported.
func TestReplicaLookupsReachTheLead(t *testing.T) {
	t.Parallel()
	asked := time.Now().Add(-time.Hour).Truncate(time.Second).UTC()
	primary, replica, recorder := lookupCluster(t, false, map[string]time.Time{"10.0.0.5": asked, "2001:db8::5": asked})

	before, leads := primary.ReplicaLookups()
	if !leads || len(before) != 1 || !before[0].Reported.IsZero() {
		t.Fatalf("before any report the lead lists %+v (leads %t), want the replica with no report", before, leads)
	}
	synchronize(t, replica, 1)
	replica.gatherLocalLookupsOnce(context.Background(), time.Now())
	synchronize(t, replica, 2)
	if carried := recorder.takeCarried(); len(carried) != 3 || carried[0] || !carried[1] || carried[2] {
		t.Fatalf("heartbeats carried lookups %v, want only the one after the read", carried)
	}
	reported, _ := primary.ReplicaLookups()
	if len(reported) != 1 || reported[0].NodeID != replica.nodeID || reported[0].Reported.IsZero() ||
		!reported[0].Last["10.0.0.5"].Equal(asked) || !reported[0].Last["2001:db8::5"].Equal(asked) {
		t.Fatalf("the lead holds %+v, want both addresses asked at %s", reported, asked)
	}
	// Reading again within the interval is skipped; the report still repeats
	// once the interval passes.
	if replica.lookupReport.due(time.Now()) {
		t.Fatal("a replica that just read its lookups reads them again")
	}
	replica.lookupReport.mu.Lock()
	replica.lookupReport.sentAt = replica.lookupReport.sentAt.Add(-lookupReportInterval)
	replica.lookupReport.mu.Unlock()
	synchronize(t, replica, 1)
	if carried := recorder.takeCarried(); len(carried) != 1 || !carried[0] {
		t.Fatalf("an unchanged report was not repeated after the interval: %v", carried)
	}
	if _, leads := replica.ReplicaLookups(); leads {
		t.Fatal("a replica claims to lead")
	}
	if err := primary.Remove(context.Background(), replica.nodeID); err != nil {
		t.Fatal(err)
	}
	if removed, _ := primary.ReplicaLookups(); len(removed) != 0 {
		t.Fatalf("the lead kept the lookups of a removed node: %+v", removed)
	}
}

func TestReplicaNeverSendsLookupsToAPrimaryThatDoesNotTakeThem(t *testing.T) {
	t.Parallel()
	primary, replica, recorder := lookupCluster(t, true, map[string]time.Time{"10.0.0.5": time.Now()})
	synchronize(t, replica, 1)
	replica.gatherLocalLookupsOnce(context.Background(), time.Now())
	synchronize(t, replica, 2)
	for _, carried := range recorder.takeCarried() {
		if carried {
			t.Fatal("a heartbeat carried lookups to a primary that does not take them")
		}
	}
	if reported, _ := primary.ReplicaLookups(); len(reported) != 1 || !reported[0].Reported.IsZero() {
		t.Fatalf("the lead holds %+v", reported)
	}
}

// A report too large to carry keeps the addresses that asked most recently.
func TestLookupReportKeepsTheMostRecentAddresses(t *testing.T) {
	t.Parallel()
	now := time.Now().Truncate(time.Second)
	found := make(map[string]time.Time)
	for index := range 20_000 {
		found[fmt.Sprintf("2001:db8:ffff:ffff:ffff:ffff:%x:%04x", index/0x10000, index%0x10000)] = now.Add(-time.Duration(index) * time.Second)
	}
	encoded, left := encodeLookupReport(found)
	if len(encoded) > maximumLookupReportBytes || left == 0 {
		t.Fatalf("report is %d bytes leaving out %d, want it capped", len(encoded), left)
	}
	var kept map[string]int64
	if err := json.Unmarshal(encoded, &kept); err != nil {
		t.Fatal(err)
	}
	if len(kept)+left != len(found) {
		t.Fatalf("kept %d and left out %d of %d", len(kept), left, len(found))
	}
	oldest := now.Unix()
	for _, seconds := range kept {
		oldest = min(oldest, seconds)
	}
	for address, moment := range found {
		if _, present := kept[address]; !present && moment.Unix() > oldest {
			t.Fatalf("left out %s, asked at %s, while keeping one from %s", address, moment, time.Unix(oldest, 0))
		}
	}
}
