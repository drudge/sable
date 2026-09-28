package cluster

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/drudge/sable/internal/alerts"
)

// replicaAlert is the kind of news a replica sees in itself. Its text is
// awkward on purpose: markup, a byte that is not UTF-8, and a time with an
// offset all have to survive the signed heartbeat unchanged.
func replicaAlert(id string, observedAt time.Time) alerts.Alert {
	return alerts.Alert{
		ID: id, Group: "backups", Kind: "backups.failed", Problem: true, Tone: alerts.ToneAttention,
		Title: "Backup failed", Subject: "dns-2", Headline: "The <nightly> backup & copy failed",
		Summary: "Disk full \xff on /var/lib/sable.", Reasons: []string{"No space left"},
		Path: "/settings?tab=backup", PathLabel: "Open Backups",
		ObservedAt: observedAt.In(time.FixedZone("EDT", -4*60*60)),
	}
}

// staticLocalAlerts stands in for the dispatcher's Local.
type staticLocalAlerts struct {
	mu    sync.Mutex
	found []alerts.Alert
	err   error
	calls int
}

func (local *staticLocalAlerts) set(err error, found ...alerts.Alert) {
	local.mu.Lock()
	defer local.mu.Unlock()
	local.found, local.err = found, err
}

func (local *staticLocalAlerts) Local(context.Context, time.Time) ([]alerts.Alert, error) {
	local.mu.Lock()
	defer local.mu.Unlock()
	local.calls++
	return slices.Clone(local.found), local.err
}

// heartbeatRecorder passes synchronization to the primary and remembers
// whether each heartbeat carried alerts. An older primary, when asked for,
// refuses fields it does not know, as the real endpoint does, and never
// advertises that it takes alerts.
type heartbeatRecorder struct {
	primary *Service
	older   bool
	mu      sync.Mutex
	carried []bool
}

func (recorder *heartbeatRecorder) RoundTrip(request *http.Request) (*http.Response, error) {
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
	_, carried := fields["alerts"]
	recorder.mu.Lock()
	recorder.carried = append(recorder.carried, carried)
	recorder.mu.Unlock()
	if recorder.older && carried {
		return clusterTestResponse(request, http.StatusBadRequest, map[string]string{"error": "invalid cluster synchronization request"})
	}
	request.Body = io.NopCloser(bytes.NewReader(contents))
	response, err := serviceRoundTripper{primary: recorder.primary}.RoundTrip(request)
	if err != nil || !recorder.older || response.StatusCode != http.StatusOK {
		return response, err
	}
	var configuration SyncConfiguration
	if err := json.NewDecoder(response.Body).Decode(&configuration); err != nil {
		return nil, err
	}
	configuration.AlertProtocol = 0
	return clusterTestResponse(request, http.StatusOK, configuration)
}

func (recorder *heartbeatRecorder) takeCarried() []bool {
	recorder.mu.Lock()
	defer recorder.mu.Unlock()
	carried := recorder.carried
	recorder.carried = nil
	return carried
}

func clusterTestResponse(request *http.Request, status int, body any) (*http.Response, error) {
	contents, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}
	return &http.Response{
		StatusCode: status, Status: http.StatusText(status), Header: make(http.Header),
		Body: io.NopCloser(bytes.NewReader(contents)), Request: request,
	}, nil
}

// reportingCluster is a primary and a replica whose heartbeats pass through a
// recorder.
func reportingCluster(t *testing.T, older bool) (*Service, *Service, *heartbeatRecorder, *staticLocalAlerts) {
	t.Helper()
	primary, replica := joinedClusterServices(t)
	recorder := &heartbeatRecorder{primary: primary, older: older}
	replica.baseHTTPClient = &http.Client{Transport: recorder}
	replica.httpClient = replica.baseHTTPClient
	replica.clientsMu.Lock()
	clear(replica.memberClients)
	replica.clientsMu.Unlock()
	local := &staticLocalAlerts{}
	replica.SetLocalAlerts(local.Local)
	return primary, replica, recorder, local
}

func synchronize(t *testing.T, replica *Service, times int) {
	t.Helper()
	for range times {
		if err := replica.syncFromPrimary(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
}

func alertIDs(found []alerts.Alert) []string {
	ids := make([]string, 0, len(found))
	for _, alert := range found {
		ids = append(ids, alert.ID)
	}
	return ids
}

func TestReplicaAlertsReachTheLeadThroughTheHeartbeat(t *testing.T) {
	t.Parallel()
	primary, replica, recorder, local := reportingCluster(t, false)
	now := time.Now()
	failed := replicaAlert("backups.failed:dns-2:1", now.Add(-time.Hour))
	local.set(nil, failed)
	replica.gatherLocalAlertsOnce(context.Background(), now)
	synchronize(t, replica, 1)
	if carried := recorder.takeCarried(); !slices.Equal(carried, []bool{true}) {
		t.Fatalf("heartbeats carried alerts %v, want the first to", carried)
	}
	reported := primary.ReportedAlerts(time.Now())
	if len(reported) != 1 {
		t.Fatalf("the lead holds %v, want the replica's alert", alertIDs(reported))
	}
	// What arrives is the alert itself, down to the text JSON had to escape
	// and the moment it was seen.
	want := failed
	want.Summary = strings.ToValidUTF8(want.Summary, "�")
	if got := reported[0]; !got.ObservedAt.Equal(want.ObservedAt) || got.Summary != want.Summary ||
		got.Headline != want.Headline || !slices.Equal(got.Reasons, want.Reasons) || got.Problem != want.Problem {
		t.Fatalf("the lead holds %+v, want %+v", got, want)
	}
	if held := replica.ReportedAlerts(time.Now()); len(held) != 0 {
		t.Fatalf("a replica returned reported alerts %v", alertIDs(held))
	}
	if stale := primary.ReportedAlerts(time.Now().Add(alertReportFreshness)); len(stale) != 0 {
		t.Fatalf("the lead kept a list three minutes old: %v", alertIDs(stale))
	}
	if err := primary.Remove(context.Background(), replica.nodeID); err != nil {
		t.Fatal(err)
	}
	if removed := primary.ReportedAlerts(time.Now()); len(removed) != 0 {
		t.Fatalf("the lead kept the alerts of a removed node: %v", alertIDs(removed))
	}
}

func TestReplicaCarriesItsAlertsOnlyWhenTheyChangeOrEveryMinute(t *testing.T) {
	t.Parallel()
	type step struct {
		name string
		// gather is the list the replica gathers first, if it gathers.
		gather []alerts.Alert
		// minutePassed moves the last delivery back a minute.
		minutePassed bool
		want         bool
		reported     []string
	}
	first := replicaAlert("backups.failed:dns-2:1", time.Now().Add(-time.Hour))
	second := replicaAlert("sign-ins.failed:dns-2:2", time.Now().Add(-time.Minute))
	steps := []step{
		{name: "a new list goes out", gather: []alerts.Alert{first}, want: true, reported: []string{first.ID}},
		{name: "the same list waits", want: false, reported: []string{first.ID}},
		{name: "gathering the same list again still waits", gather: []alerts.Alert{first}, want: false, reported: []string{first.ID}},
		{name: "a minute later it goes out again", minutePassed: true, want: true, reported: []string{first.ID}},
		{name: "a changed list goes out at once", gather: []alerts.Alert{first, second}, want: true, reported: []string{first.ID, second.ID}},
		{name: "an empty list goes out and clears the lead", gather: []alerts.Alert{}, want: true, reported: []string{}},
	}
	primary, replica, recorder, local := reportingCluster(t, false)
	for _, step := range steps {
		if step.gather != nil {
			local.set(nil, step.gather...)
			replica.gatherLocalAlertsOnce(context.Background(), time.Now())
		}
		if step.minutePassed {
			replica.alertReport.mu.Lock()
			replica.alertReport.sentAt = replica.alertReport.sentAt.Add(-alertReportInterval)
			replica.alertReport.mu.Unlock()
		}
		synchronize(t, replica, 1)
		if carried := recorder.takeCarried(); !slices.Equal(carried, []bool{step.want}) {
			t.Fatalf("%s: heartbeat carried alerts %v, want %t", step.name, carried, step.want)
		}
		if got := alertIDs(primary.ReportedAlerts(time.Now())); !slices.Equal(got, step.reported) {
			t.Fatalf("%s: the lead holds %v, want %v", step.name, got, step.reported)
		}
	}
}

func TestReplicaNeverSendsAlertsToAPrimaryThatDoesNotTakeThem(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name string
		// downgraded has the replica gather before it next hears from the
		// primary, which advertised alerts before it went back to a release
		// that refuses them.
		downgraded bool
		want       []bool
	}{
		{name: "an older primary never hears of them", want: []bool{false, false, false, false}},
		{name: "a downgraded primary refuses one heartbeat and hears no more", downgraded: true, want: []bool{true, false, false, false}},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			primary, replica, recorder, local := reportingCluster(t, true)
			local.set(nil, replicaAlert("backups.failed:dns-2:1", time.Now()))
			if !test.downgraded {
				// The primary this replica joined advertised alerts; the first
				// answer from the older one takes that back.
				synchronize(t, replica, 1)
			}
			replica.gatherLocalAlertsOnce(context.Background(), time.Now())
			if test.downgraded {
				if err := replica.syncFromPrimary(context.Background()); err == nil {
					t.Fatal("the downgraded primary accepted a field it does not know")
				}
			}
			synchronize(t, replica, 3)
			if carried := recorder.takeCarried(); !slices.Equal(carried, test.want) {
				t.Fatalf("heartbeats carried alerts %v, want %v", carried, test.want)
			}
			if got := primary.ReportedAlerts(time.Now()); len(got) != 0 {
				t.Fatalf("the lead holds %v", alertIDs(got))
			}
		})
	}
}

func TestLocalAlertsAreGatheredOnlyOnReplicas(t *testing.T) {
	t.Parallel()
	primary, replica := joinedClusterServices(t)
	for _, test := range []struct {
		name    string
		service *Service
		want    int
	}{
		{name: "the lead sends its own", service: primary, want: 0},
		{name: "a replica gathers", service: replica, want: 1},
	} {
		local := &staticLocalAlerts{}
		local.set(nil, replicaAlert("backups.failed:node:1", time.Now()))
		test.service.SetLocalAlerts(local.Local)
		test.service.gatherLocalAlertsOnce(context.Background(), time.Now())
		if local.calls != test.want {
			t.Errorf("%s: gathered %d times, want %d", test.name, local.calls, test.want)
		}
	}
}

func TestAlertReportKeepsNewsFromASourceThatFailed(t *testing.T) {
	t.Parallel()
	now := time.Now()
	first := replicaAlert("backups.failed:dns-2:1", now.Add(-time.Hour))
	second := replicaAlert("sign-ins.failed:dns-2:2", now.Add(-time.Minute))
	for _, test := range []struct {
		name    string
		partial bool
		want    []string
	}{
		{name: "a complete list replaces the last", partial: false, want: []string{second.ID}},
		{name: "a list with a failed source keeps what the last one said", partial: true, want: []string{first.ID, second.ID}},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			var reporter alertReporter
			reporter.record([]alerts.Alert{first, second}, false, now)
			reporter.record([]alerts.Alert{second}, test.partial, now.Add(time.Minute))
			report, _ := reporter.pending("primary", now.Add(time.Minute))
			if got := reportedIDs(t, report); !slices.Equal(got, test.want) {
				t.Fatalf("report = %v, want %v", got, test.want)
			}
		})
	}
}

func TestAlertReportStaysSmallEnoughToCarry(t *testing.T) {
	t.Parallel()
	now := time.Now()
	found := make([]alerts.Alert, 0, 64)
	for index := range 64 {
		alert := replicaAlert(fmt.Sprintf("backups.failed:dns-2:%d", index), now)
		alert.Summary = strings.Repeat("x", 1024)
		found = append(found, alert)
	}
	var reporter alertReporter
	left := reporter.record(found, false, now)
	if left == 0 || len(reporter.encoded) > maximumAlertReportBytes {
		t.Fatalf("report of %d bytes left out %d alerts", len(reporter.encoded), left)
	}
	report, _ := reporter.pending("primary", now)
	if kept := reportedIDs(t, report); len(kept) != len(found)-left || kept[0] != found[0].ID {
		t.Fatalf("report kept %d of %d alerts", len(kept), len(found))
	}
	// A list gathered too long ago is not carried at all.
	if stale, _ := reporter.pending("primary", now.Add(alertReportFreshness)); stale != nil {
		t.Fatal("a stale list was carried")
	}
}

// The primary refuses heartbeat fields it does not know and verifies the
// signature over the heartbeat as it decoded it, so the list has to arrive
// byte for byte, and an alert from a later release, with fields this one does
// not know, still has to be taken.
func TestReportedAlertsCrossTheSignedHeartbeat(t *testing.T) {
	t.Parallel()
	encoded, _, _ := encodeAlertReport([]alerts.Alert{replicaAlert("backups.failed:dns-2:1", time.Now())})
	for _, test := range []struct {
		name string
		list json.RawMessage
	}{
		{name: "alerts this release knows", list: encoded},
		{name: "an alert from a later release", list: json.RawMessage(`[{"id":"backups.failed:dns-2:2","group":"backups","kind":"backups.failed","tone":"attention","title":"Backup failed","subject":"dns-2","headline":"x","summary":"y","path":"/","path_label":"Open","observed_at":"2026-09-25T12:00:00Z","node_id":"dns-2","severity":{"level":2}}]`)},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			primary, replica := joinedClusterServices(t)
			heartbeat := Heartbeat{
				NodeID: replica.nodeID, AppliedGeneration: primary.manifest.Generation, StateDigest: primary.manifest.StateDigest,
				UpSince: time.Now(), SentAt: time.Now(), Alerts: test.list,
			}
			signature := heartbeatSignature(primary.manifest.StatusKey, heartbeat)
			contents, err := json.Marshal(heartbeat)
			if err != nil {
				t.Fatal(err)
			}
			var received Heartbeat
			decoder := json.NewDecoder(bytes.NewReader(contents))
			decoder.DisallowUnknownFields()
			if err := decoder.Decode(&received); err != nil {
				t.Fatal(err)
			}
			if _, err := primary.Synchronize(context.Background(), received, signature); err != nil {
				t.Fatal(err)
			}
			want := reportedIDs(t, test.list)
			if got := alertIDs(primary.ReportedAlerts(time.Now())); !slices.Equal(got, want) {
				t.Fatalf("the lead holds %v, want %v", got, want)
			}
		})
	}
}

func reportedIDs(t *testing.T, encoded json.RawMessage) []string {
	t.Helper()
	var list []alerts.Alert
	if err := json.Unmarshal(encoded, &list); err != nil {
		t.Fatalf("report %q: %v", encoded, err)
	}
	return alertIDs(list)
}

func TestPromotionDropsReportsFromTheFormerTerm(t *testing.T) {
	t.Parallel()
	primary, replica, _, local := reportingCluster(t, false)
	local.set(nil, replicaAlert("backups.failed:dns-2:1", time.Now()))
	replica.gatherLocalAlertsOnce(context.Background(), time.Now())
	synchronize(t, replica, 1)
	if len(primary.ReportedAlerts(time.Now())) != 1 {
		t.Fatal("fixture did not report")
	}
	if err := primary.Promote(context.Background(), replica.nodeID); err != nil {
		t.Fatal(err)
	}
	if got := primary.ReportedAlerts(time.Now()); len(got) != 0 {
		t.Fatalf("a demoted node still returns %v", alertIDs(got))
	}
}
