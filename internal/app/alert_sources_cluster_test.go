package app

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/drudge/sable/internal/alerts"
	"github.com/drudge/sable/internal/cluster"
	"github.com/drudge/sable/internal/config"
)

var clusterAlertStart = time.Date(2026, 9, 25, 12, 0, 0, 0, time.UTC)

// Node IDs in the order they sort, so a test can say which replica is lowest.
const (
	firstNodeID  = "10000000-0000-4000-8000-000000000000"
	secondNodeID = "20000000-0000-4000-8000-000000000000"
	thirdNodeID  = "30000000-0000-4000-8000-000000000000"
)

// fakeClusterView is the cluster as a test says it is.
type fakeClusterView struct {
	mu       sync.Mutex
	state    cluster.State
	rollout  cluster.RolloutStatus
	reported []alerts.Alert
}

func (view *fakeClusterView) set(state cluster.State) {
	view.mu.Lock()
	defer view.mu.Unlock()
	view.state = state
}

func (view *fakeClusterView) Snapshot() cluster.State {
	view.mu.Lock()
	defer view.mu.Unlock()
	state := view.state
	state.Nodes = slices.Clone(state.Nodes)
	return state
}

func (view *fakeClusterView) RolloutStatus() cluster.RolloutStatus {
	view.mu.Lock()
	defer view.mu.Unlock()
	return view.rollout
}

func (view *fakeClusterView) ReportedAlerts(time.Time) []alerts.Alert {
	view.mu.Lock()
	defer view.mu.Unlock()
	return slices.Clone(view.reported)
}

// clusterMoment is the cluster as one node sees it at one moment, and the
// alerts that node should hold then.
type clusterMoment struct {
	after time.Duration
	// lapse means the source was not asked since the moment before, as when
	// this node stopped leading for a while. Otherwise it was asked every
	// minute, and saw the cluster as the moment before left it.
	lapse bool
	// primary is the lead's ID, firstNodeID unless a test hands the lead on.
	primary string
	// nodes are the other nodes as this one sees them.
	nodes []cluster.Node
	want  []string
}

func answering(id, name string) cluster.Node {
	return cluster.Node{ID: id, Name: name, Role: cluster.RoleReplica, State: cluster.StateOnline, Version: "1.9.0", Addresses: []string{"192.0.2.2"}}
}

// silent is a node last heard from a while after the start.
func silent(id, name string, lastContact time.Duration) cluster.Node {
	node := answering(id, name)
	node.State, node.LastContact = "unreachable", clusterAlertStart.Add(lastContact)
	return node
}

// unheard is a node this one has not heard from since it started watching.
func unheard(id, name string) cluster.Node {
	node := answering(id, name)
	node.State = "unknown"
	return node
}

// clusterStateFor is the cluster as the node with selfID sees it: itself
// online, and the others as the moment says.
func clusterStateFor(selfID, selfName string, moment clusterMoment) cluster.State {
	primary := moment.primary
	if primary == "" {
		primary = firstNodeID
	}
	state := cluster.State{Initialized: true, ClusterID: "cluster", NodeID: selfID, PrimaryID: primary}
	self := answering(selfID, selfName)
	state.Nodes = append([]cluster.Node{self}, moment.nodes...)
	for index := range state.Nodes {
		if state.Nodes[index].ID == primary {
			state.Nodes[index].Role = cluster.RolePrimary
		}
	}
	state.LocalRole = cluster.RoleReplica
	if primary == selfID {
		state.LocalRole = cluster.RolePrimary
	}
	return state
}

func clusterAlertID(kind, nodeID string, since time.Duration) string {
	return fmt.Sprintf("cluster.%s:%s:%d", kind, nodeID, clusterAlertStart.Add(since).Unix())
}

// playClusterMoments shows a source each moment in turn, asking every minute
// in between as the dispatcher does, and checks what it holds at each one.
// It returns what the source held at the last.
func playClusterMoments(t *testing.T, source alerts.Source, view *fakeClusterView, selfID, selfName string, moments []clusterMoment) []alerts.Alert {
	t.Helper()
	ask := func(moment clusterMoment, after time.Duration) []alerts.Alert {
		view.set(clusterStateFor(selfID, selfName, moment))
		found, err := source.Alerts(context.Background(), clusterAlertStart.Add(after))
		if err != nil {
			t.Fatal(err)
		}
		return found
	}
	var found []alerts.Alert
	for index, moment := range moments {
		if index > 0 && !moment.lapse {
			for after := moments[index-1].after + time.Minute; after < moment.after; after += time.Minute {
				ask(moments[index-1], after)
			}
		}
		found = ask(moment, moment.after)
		got := make([]string, 0, len(found))
		for _, alert := range found {
			got = append(got, alert.ID)
		}
		want := slices.Clone(moment.want)
		slices.Sort(got)
		slices.Sort(want)
		if !slices.Equal(got, want) {
			t.Fatalf("after %s: holds %v, want %v", moment.after, got, want)
		}
	}
	return found
}

func TestNodeOutageSourceAlertsAfterFiveMinutesAndWhenTheNodeIsBack(t *testing.T) {
	t.Parallel()
	down := func(since time.Duration) string { return clusterAlertID("node-down", secondNodeID, since) }
	up := func(since time.Duration) string { return clusterAlertID("node-up", secondNodeID, since) }
	ns2 := func() cluster.Node { return answering(secondNodeID, "ns2") }
	quiet := func(lastContact time.Duration) cluster.Node { return silent(secondNodeID, "ns2", lastContact) }
	never := func() cluster.Node { return unheard(secondNodeID, "ns2") }
	for _, test := range []struct {
		name    string
		moments []clusterMoment
	}{
		{name: "a node out of touch for under five minutes stays quiet", moments: []clusterMoment{
			{after: 0, nodes: []cluster.Node{ns2()}},
			{after: time.Minute, nodes: []cluster.Node{quiet(50 * time.Second)}},
			{after: 5*time.Minute + 49*time.Second, nodes: []cluster.Node{quiet(50 * time.Second)}},
			{after: 6 * time.Minute, nodes: []cluster.Node{ns2()}},
		}},
		{name: "a node out of touch for five minutes is down until it is back, which stays news for a day", moments: []clusterMoment{
			{after: 0, nodes: []cluster.Node{ns2()}},
			{after: time.Minute, nodes: []cluster.Node{quiet(50 * time.Second)}},
			{after: 5*time.Minute + 50*time.Second, nodes: []cluster.Node{quiet(50 * time.Second)}, want: []string{down(50 * time.Second)}},
			{after: 7 * time.Minute, nodes: []cluster.Node{quiet(50 * time.Second)}, want: []string{down(50 * time.Second)}},
			{after: 9 * time.Minute, nodes: []cluster.Node{ns2()}, want: []string{up(50 * time.Second)}},
			{after: 24*time.Hour + 8*time.Minute, nodes: []cluster.Node{ns2()}, want: []string{up(50 * time.Second)}},
			{after: 24*time.Hour + 9*time.Minute, nodes: []cluster.Node{ns2()}},
		}},
		{name: "a node that goes down again later alerts again under a new ID", moments: []clusterMoment{
			{after: time.Minute, nodes: []cluster.Node{quiet(50 * time.Second)}},
			{after: 6 * time.Minute, nodes: []cluster.Node{quiet(50 * time.Second)}, want: []string{down(50 * time.Second)}},
			{after: 9 * time.Minute, nodes: []cluster.Node{ns2()}, want: []string{up(50 * time.Second)}},
			{after: 10 * time.Minute, nodes: []cluster.Node{quiet(9*time.Minute + 30*time.Second)}, want: []string{up(50 * time.Second)}},
			{after: 12 * time.Minute, nodes: []cluster.Node{quiet(9*time.Minute + 30*time.Second)}, want: []string{up(50 * time.Second)}},
			{after: 14*time.Minute + 30*time.Second, nodes: []cluster.Node{quiet(9*time.Minute + 30*time.Second)},
				want: []string{up(50 * time.Second), down(9*time.Minute + 30*time.Second)}},
		}},
		{name: "a node not heard from since the lead started watching gets five minutes", moments: []clusterMoment{
			{after: 0, nodes: []cluster.Node{never()}},
			{after: 4*time.Minute + 59*time.Second, nodes: []cluster.Node{never()}},
			{after: 5 * time.Minute, nodes: []cluster.Node{never()}, want: []string{down(0)}},
		}},
		{name: "after a lapse in watching, as after taking the lead again, a node gets five fresh minutes", moments: []clusterMoment{
			{after: 0, nodes: []cluster.Node{never()}},
			{after: 2 * time.Minute, nodes: []cluster.Node{never()}},
			{after: 12 * time.Minute, lapse: true, nodes: []cluster.Node{never()}},
			{after: 16 * time.Minute, nodes: []cluster.Node{never()}},
			{after: 17 * time.Minute, nodes: []cluster.Node{never()}, want: []string{down(12 * time.Minute)}},
		}},
		{name: "a node heard from before it alerts gets a fresh wait", moments: []clusterMoment{
			{after: 0, nodes: []cluster.Node{never()}},
			{after: 4 * time.Minute, nodes: []cluster.Node{quiet(3*time.Minute + 50*time.Second)}},
			{after: 8*time.Minute + 49*time.Second, nodes: []cluster.Node{quiet(3*time.Minute + 50*time.Second)}},
			{after: 8*time.Minute + 50*time.Second, nodes: []cluster.Node{quiet(3*time.Minute + 50*time.Second)},
				want: []string{down(3*time.Minute + 50*time.Second)}},
		}},
		{name: "a removed node's outage ends without an all-clear", moments: []clusterMoment{
			{after: time.Minute, nodes: []cluster.Node{quiet(50 * time.Second)}},
			{after: 6 * time.Minute, nodes: []cluster.Node{quiet(50 * time.Second)}, want: []string{down(50 * time.Second)}},
			{after: 7 * time.Minute},
			{after: 8 * time.Minute, nodes: []cluster.Node{ns2()}},
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			view := &fakeClusterView{}
			source := clusterAlertSources(view)[0]
			playClusterMoments(t, source, view, firstNodeID, "ns1", test.moments)
		})
	}
}

func TestLeadOutageSourceTellsOnceFromTheLowestReplica(t *testing.T) {
	t.Parallel()
	down := func(leadID string, since time.Duration) string { return clusterAlertID("lead-down", leadID, since) }
	up := func(leadID string, since time.Duration) string { return clusterAlertID("lead-up", leadID, since) }
	ns1 := func() cluster.Node { return answering(firstNodeID, "ns1") }
	ns3 := func() cluster.Node { return answering(thirdNodeID, "ns3") }
	quiet := func(lastContact time.Duration) cluster.Node { return silent(firstNodeID, "ns1", lastContact) }
	for _, test := range []struct {
		name string
		// self is this replica; the lowest replica is ns2 unless it is ns3.
		self    string
		moments []clusterMoment
	}{
		{name: "the lowest replica tells when the lead is out of touch for five minutes, and when it is back", self: secondNodeID, moments: []clusterMoment{
			{after: 0, nodes: []cluster.Node{ns1(), ns3()}},
			{after: time.Minute, nodes: []cluster.Node{quiet(50 * time.Second), ns3()}},
			{after: 5*time.Minute + 49*time.Second, nodes: []cluster.Node{quiet(50 * time.Second), ns3()}},
			{after: 5*time.Minute + 50*time.Second, nodes: []cluster.Node{quiet(50 * time.Second), ns3()}, want: []string{down(firstNodeID, 50*time.Second)}},
			{after: 8 * time.Minute, nodes: []cluster.Node{ns1(), ns3()}, want: []string{up(firstNodeID, 50*time.Second)}},
			{after: 24*time.Hour + 7*time.Minute, nodes: []cluster.Node{ns1(), ns3()}, want: []string{up(firstNodeID, 50*time.Second)}},
			{after: 24*time.Hour + 8*time.Minute, nodes: []cluster.Node{ns1(), ns3()}},
		}},
		{name: "any other replica stays quiet", self: thirdNodeID, moments: []clusterMoment{
			{after: time.Minute, nodes: []cluster.Node{quiet(50 * time.Second), answering(secondNodeID, "ns2")}},
			{after: 10 * time.Minute, nodes: []cluster.Node{quiet(50 * time.Second), answering(secondNodeID, "ns2")}},
			{after: 12 * time.Minute, nodes: []cluster.Node{ns1(), answering(secondNodeID, "ns2")}},
		}},
		{name: "a planned handoff inside five minutes does not alert", self: secondNodeID, moments: []clusterMoment{
			{after: 0, nodes: []cluster.Node{ns1(), ns3()}},
			{after: time.Minute, nodes: []cluster.Node{quiet(50 * time.Second), ns3()}},
			{after: 3 * time.Minute, primary: thirdNodeID, nodes: []cluster.Node{quiet(50 * time.Second), ns3()}},
			{after: 7 * time.Minute, primary: thirdNodeID, nodes: []cluster.Node{quiet(50 * time.Second), ns3()}},
		}},
		// ns1 is the lowest replica here, so it tells about both leads.
		{name: "a new lead that goes quiet alerts about itself", self: firstNodeID, moments: []clusterMoment{
			{after: 0, primary: secondNodeID, nodes: []cluster.Node{answering(secondNodeID, "ns2"), ns3()}},
			{after: time.Minute, primary: thirdNodeID, nodes: []cluster.Node{answering(secondNodeID, "ns2"), ns3()}},
			{after: 2 * time.Minute, primary: thirdNodeID, nodes: []cluster.Node{answering(secondNodeID, "ns2"), silent(thirdNodeID, "ns3", 90*time.Second)}},
			{after: 6*time.Minute + 29*time.Second, primary: thirdNodeID, nodes: []cluster.Node{answering(secondNodeID, "ns2"), silent(thirdNodeID, "ns3", 90*time.Second)}},
			{after: 6*time.Minute + 30*time.Second, primary: thirdNodeID, nodes: []cluster.Node{answering(secondNodeID, "ns2"), silent(thirdNodeID, "ns3", 90*time.Second)},
				want: []string{down(thirdNodeID, 90*time.Second)}},
		}},
		{name: "a lead not heard from since this replica started gets five minutes", self: secondNodeID, moments: []clusterMoment{
			{after: 0, nodes: []cluster.Node{unheard(firstNodeID, "ns1"), ns3()}},
			{after: 4 * time.Minute, nodes: []cluster.Node{unheard(firstNodeID, "ns1"), ns3()}},
			{after: 5 * time.Minute, nodes: []cluster.Node{unheard(firstNodeID, "ns1"), ns3()}, want: []string{down(firstNodeID, 0)}},
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			view := &fakeClusterView{}
			source := clusterAlertSources(view)[3]
			name := map[string]string{firstNodeID: "ns1", secondNodeID: "ns2", thirdNodeID: "ns3"}[test.self]
			playClusterMoments(t, source, view, test.self, name, test.moments)
		})
	}
}

func TestRolloutAlertSourceTellsEachStepForADay(t *testing.T) {
	t.Parallel()
	now := clusterAlertStart
	rollout := func(phase string, startedAgo, finishedAgo time.Duration) cluster.RolloutStatus {
		status := cluster.RolloutStatus{
			ID: "rollout-1", ClusterID: "cluster", PrimaryID: firstNodeID, Version: "v1.9.0", Phase: phase,
			Nodes: []cluster.RolloutNode{{ID: secondNodeID, Name: "ns2"}, {ID: thirdNodeID, Name: "ns3"}, {ID: firstNodeID, Name: "ns1"}},
		}
		if startedAgo > 0 {
			status.StartedAt = now.Add(-startedAgo)
		}
		if finishedAgo > 0 {
			status.FinishedAt = now.Add(-finishedAgo)
		}
		return status
	}
	failed := rollout(cluster.RolloutFailed, time.Hour, 30*time.Minute)
	failed.FailedNode, failed.Error = "ns3", "ns3: checksum mismatch"
	elsewhere := rollout("updating", time.Hour, 0)
	elsewhere.ClusterID = "another-cluster"
	for _, test := range []struct {
		name    string
		rollout cluster.RolloutStatus
		role    string
		want    []string
		// problem is the ID of the one alert that should be a problem.
		problem string
		// mentions are what the alert that ends the rollout has to say.
		mentions []string
	}{
		{name: "no rollout says nothing"},
		{name: "a running rollout is news from when it started", rollout: rollout("updating", time.Hour, 0),
			want: []string{"cluster.rollout-started:rollout-1"}},
		{name: "a finished rollout is news for a day after it ends", rollout: rollout(cluster.RolloutComplete, 23*time.Hour, 22*time.Hour),
			want:     []string{"cluster.rollout-started:rollout-1", "cluster.rollout-finished:rollout-1"},
			mentions: []string{"v1.9.0", "ns2, ns3, and ns1", "1 hour"}},
		{name: "only the end is still news when the start was over a day ago", rollout: rollout(cluster.RolloutComplete, 25*time.Hour, 23*time.Hour),
			want: []string{"cluster.rollout-finished:rollout-1"}},
		{name: "a day after it ends a rollout is no longer news", rollout: rollout(cluster.RolloutComplete, 25*time.Hour, 24*time.Hour)},
		{name: "a failed rollout is a problem that names the version and the node", rollout: failed,
			want:    []string{"cluster.rollout-started:rollout-1", "cluster.rollout-failed:rollout-1"},
			problem: "cluster.rollout-failed:rollout-1", mentions: []string{"v1.9.0", "ns3"}},
		{name: "a stopped rollout is not a problem", rollout: rollout(cluster.RolloutStopped, time.Hour, 50*time.Minute),
			want: []string{"cluster.rollout-started:rollout-1", "cluster.rollout-stopped:rollout-1"}, mentions: []string{"v1.9.0"}},
		{name: "a rollout saved by an older release has no times and says nothing", rollout: rollout(cluster.RolloutComplete, 0, 0)},
		{name: "a rollout of another cluster says nothing", rollout: elsewhere},
		{name: "a replica says nothing about rollouts", rollout: rollout("updating", time.Hour, 0), role: cluster.RoleReplica},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			view := &fakeClusterView{rollout: test.rollout}
			moment := clusterMoment{nodes: []cluster.Node{answering(secondNodeID, "ns2"), answering(thirdNodeID, "ns3")}}
			if test.role == cluster.RoleReplica {
				moment.primary = secondNodeID
			}
			view.set(clusterStateFor(firstNodeID, "ns1", moment))
			found, err := clusterAlertSources(view)[1].Alerts(context.Background(), now)
			if err != nil {
				t.Fatal(err)
			}
			got := make([]string, 0, len(found))
			for _, alert := range found {
				got = append(got, alert.ID)
				if alert.Problem != (alert.ID == test.problem) || alert.Group != config.AlertGroupCluster ||
					alert.Subject != "v1.9.0" || alert.Path != "/cluster" || alert.PathLabel != "Open Cluster" {
					t.Errorf("alert = %+v", alert)
				}
				if strings.HasPrefix(alert.ID, "cluster.rollout-started") {
					continue
				}
				for _, mention := range test.mentions {
					if !strings.Contains(alert.Headline+" "+alert.Summary+" "+strings.Join(alert.Reasons, " "), mention) {
						t.Errorf("%s does not mention %q: %+v", alert.ID, mention, alert)
					}
				}
			}
			if !slices.Equal(got, test.want) && !(len(got) == 0 && len(test.want) == 0) {
				t.Fatalf("holds %v, want %v", got, test.want)
			}
		})
	}
}

func TestClusterAlertsAreWordedPlainly(t *testing.T) {
	t.Parallel()
	nodeDown := clusterAlertID("node-down", secondNodeID, 30*time.Second)
	for _, test := range []struct {
		name    string
		source  int
		self    string
		moments []clusterMoment
		want    alerts.Alert
	}{
		{
			name: "a node down", source: 0, self: firstNodeID,
			moments: []clusterMoment{{after: 6 * time.Minute, nodes: []cluster.Node{silent(secondNodeID, "ns2", 30*time.Second)}, want: []string{nodeDown}}},
			want: alerts.Alert{
				Kind: "cluster.node-down", Problem: true, Tone: alerts.ToneAttention, Title: "Node down", Subject: "ns2",
				Headline: "ns2 stopped checking in",
				Summary:  "ns2 has not checked in with ns1 for 5 minutes. It may be down or cut off from the other nodes.",
				Reasons:  []string{"Last check-in 5 minutes ago", "DNS at 192.0.2.2"},
			},
		},
		{
			name: "a node back up", source: 0, self: firstNodeID,
			moments: []clusterMoment{
				{after: 6 * time.Minute, nodes: []cluster.Node{silent(secondNodeID, "ns2", 30*time.Second)}, want: []string{nodeDown}},
				{after: 72 * time.Minute, nodes: []cluster.Node{answering(secondNodeID, "ns2")}, want: []string{clusterAlertID("node-up", secondNodeID, 30*time.Second)}},
			},
			want: alerts.Alert{
				Kind: "cluster.node-up", Tone: alerts.TonePositive, Title: "Node back up", Subject: "ns2",
				Headline: "ns2 is checking in again",
				Summary:  "ns2 checked in with ns1 again after 1 hour 11 minutes out of touch.",
				Reasons:  []string{"Out of touch for 1 hour 11 minutes", "Runs Sable 1.9.0"},
			},
		},
		{
			name: "the lead not answering", source: 3, self: secondNodeID,
			moments: []clusterMoment{{after: 7 * time.Minute, nodes: []cluster.Node{silent(firstNodeID, "ns1", time.Minute)},
				want: []string{clusterAlertID("lead-down", firstNodeID, time.Minute)}}},
			want: alerts.Alert{
				Kind: "cluster.lead-down", Problem: true, Tone: alerts.ToneAttention, Title: "Lead node not answering", Subject: "ns1",
				Headline: "ns1 stopped answering",
				Summary:  "ns2 has not heard from ns1, the lead node, for 6 minutes. DNS keeps working on the other nodes, but changes wait until ns1 is back or another node is promoted.",
				Reasons:  []string{"Last answer 6 minutes ago", "Noticed by ns2"},
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			view := &fakeClusterView{}
			name := map[string]string{firstNodeID: "ns1", secondNodeID: "ns2"}[test.self]
			found := playClusterMoments(t, clusterAlertSources(view)[test.source], view, test.self, name, test.moments)
			got, want := found[0], test.want
			if got.Kind != want.Kind || got.Problem != want.Problem || got.Tone != want.Tone || got.Title != want.Title ||
				got.Subject != want.Subject || got.Headline != want.Headline || got.Summary != want.Summary ||
				!slices.Equal(got.Reasons, want.Reasons) || got.Group != config.AlertGroupCluster ||
				got.Path != "/cluster" || got.PathLabel != "Open Cluster" {
				t.Errorf("\n got %+v\nwant %+v", got, want)
			}
		})
	}
}

func TestClusterSourcesStayQuietOutsideTheirRole(t *testing.T) {
	t.Parallel()
	sources := clusterAlertSources(&fakeClusterView{})
	for index, want := range []alerts.Placement{alerts.OnLead, alerts.OnLead, alerts.OnLead, alerts.OnReplicas} {
		placement := alerts.OnLead
		if placed, ok := sources[index].(alerts.Placed); ok {
			placement = placed.Placement()
		}
		if placement != want {
			t.Errorf("source %d runs at %v, want %v", index, placement, want)
		}
	}
	quiet := []cluster.Node{silent(secondNodeID, "ns2", 0), silent(thirdNodeID, "ns3", 0)}
	for _, test := range []struct {
		name   string
		source int
		state  cluster.State
	}{
		{name: "a replica does not watch the other nodes", source: 0, state: clusterStateFor(firstNodeID, "ns1", clusterMoment{primary: secondNodeID, nodes: quiet})},
		{name: "a lone node has no nodes to watch", source: 0, state: cluster.State{NodeID: firstNodeID}},
		{name: "the lead does not watch itself", source: 3, state: clusterStateFor(firstNodeID, "ns1", clusterMoment{nodes: quiet})},
		{name: "a lone node has no lead to watch", source: 3, state: cluster.State{NodeID: firstNodeID}},
	} {
		view := &fakeClusterView{}
		source := clusterAlertSources(view)[test.source]
		for _, after := range []time.Duration{0, 10 * time.Minute, 11 * time.Minute} {
			view.set(test.state)
			found, err := source.Alerts(context.Background(), clusterAlertStart.Add(after))
			if err != nil || len(found) != 0 {
				t.Fatalf("%s: found %v, %v", test.name, found, err)
			}
		}
	}
}

func TestSpokenDuration(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		duration time.Duration
		want     string
	}{
		{duration: 30 * time.Second, want: "under a minute"},
		{duration: time.Minute, want: "1 minute"},
		{duration: 5*time.Minute + 59*time.Second, want: "5 minutes"},
		{duration: time.Hour, want: "1 hour"},
		{duration: 71 * time.Minute, want: "1 hour 11 minutes"},
		{duration: 49 * time.Hour, want: "2 days 1 hour"},
		{duration: 48 * time.Hour, want: "2 days"},
	} {
		if got := spokenDuration(test.duration); got != test.want {
			t.Errorf("spokenDuration(%s) = %q, want %q", test.duration, got, test.want)
		}
	}
}

// primaryTransport carries a replica's requests to a primary in the same
// process, refusing unknown heartbeat fields the way the real endpoint does.
type primaryTransport struct{ primary *cluster.Service }

func (transport primaryTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	status, body := http.StatusOK, any(nil)
	switch request.URL.Path {
	case "/api/v1/cluster/enroll":
		var input cluster.JoinRequest
		if err := json.NewDecoder(request.Body).Decode(&input); err != nil {
			return nil, err
		}
		configuration, err := transport.primary.Enroll(request.Context(), input)
		status, body = http.StatusCreated, configuration
		if err != nil {
			status, body = http.StatusUnprocessableEntity, map[string]string{"error": err.Error()}
		}
	case "/api/v1/cluster/sync":
		var heartbeat cluster.Heartbeat
		decoder := json.NewDecoder(request.Body)
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&heartbeat); err != nil {
			return nil, err
		}
		configuration, err := transport.primary.Synchronize(request.Context(), heartbeat, request.Header.Get("X-Sable-Cluster-Signature"))
		body = configuration
		if err != nil {
			status, body = http.StatusUnauthorized, map[string]string{"error": err.Error()}
		}
	default:
		return nil, errors.New("unexpected cluster request " + request.URL.Path)
	}
	contents, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}
	return &http.Response{
		StatusCode: status, Status: http.StatusText(status), Header: make(http.Header),
		Body: io.NopCloser(bytes.NewReader(contents)), Request: request,
	}, nil
}

// A replica gathers its own alerts and hands them over in its heartbeats, and
// the lead's sources return them for its dispatcher to send.
func TestReplicaAlertsReachTheLeadsSources(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	primary, err := cluster.Open(cluster.Options{DataDirectory: t.TempDir(), NodeName: "ns1", AdvertiseURL: "https://ns1.example.test:5380"})
	if err != nil {
		t.Fatal(err)
	}
	if err := primary.Initialize(ctx, "cluster.example.test", []string{"192.0.2.1"}); err != nil {
		t.Fatal(err)
	}
	token, err := primary.CreateEnrollmentToken(ctx, 5*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	replica, err := cluster.Open(cluster.Options{
		DataDirectory: t.TempDir(), NodeName: "ns2", AdvertiseURL: "https://ns2.example.test:5380",
		HTTPClient: &http.Client{Transport: primaryTransport{primary: primary}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := replica.Join(ctx, cluster.JoinOptions{PrimaryURL: "https://ns1.example.test:5380", Token: token.Token, Addresses: []string{"192.0.2.2"}}); err != nil {
		t.Fatal(err)
	}
	failed := alerts.Alert{
		ID: "backups.failed:" + replica.Snapshot().NodeID + ":1", Group: config.AlertGroupBackups, Kind: "backups.failed",
		Problem: true, Tone: alerts.ToneAttention, Title: "Backup failed", Subject: "ns2", Summary: "The nightly backup failed.",
		ObservedAt: time.Now().Add(-time.Minute).UTC(),
	}
	replica.SetLocalAlerts(func(context.Context, time.Time) ([]alerts.Alert, error) { return []alerts.Alert{failed}, nil })
	replica.StartMonitoring(ctx)
	defer func() {
		if err := replica.Close(context.Background()); err != nil {
			t.Error(err)
		}
	}()
	sources := clusterAlertSources(primary)
	deadline := time.Now().Add(15 * time.Second)
	for {
		var held []string
		for _, source := range sources {
			if _, placed := source.(alerts.Placed); placed {
				continue
			}
			found, err := source.Alerts(ctx, time.Now())
			if err != nil {
				t.Fatal(err)
			}
			for _, alert := range found {
				held = append(held, alert.ID)
			}
		}
		if slices.Contains(held, failed.ID) {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("the lead's sources hold %v, want the replica's %s", held, failed.ID)
		}
		time.Sleep(50 * time.Millisecond)
	}
}
