package app

import (
	"context"
	"fmt"
	"maps"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/drudge/sable/internal/alerts"
	"github.com/drudge/sable/internal/cluster"
	"github.com/drudge/sable/internal/config"
)

const (
	// clusterOutageGrace is how long a node, or the lead, has to be out of
	// touch before it alerts. A restart or a planned handoff is over well
	// within it.
	clusterOutageGrace = 5 * time.Minute
	// clusterEventNews is how long a one-time event, such as a node coming
	// back or a rolling update finishing, stays news.
	clusterEventNews = 24 * time.Hour
	// clusterWatchGap is how long the dispatcher can go without asking an
	// outage source before the source stops trusting what it remembers. The
	// dispatcher asks every minute, but only while it has somewhere to send
	// and only while this node has the role the source runs in. A longer gap
	// means this node stopped watching for a while: nodes may have come and
	// gone unseen, and a node that just took the lead has heard from no one.
	clusterWatchGap = 3 * time.Minute
	// clusterPath is the console page that shows the cluster.
	clusterPath      = "/cluster"
	clusterPathLabel = "Open Cluster"
)

// clusterAlertView is the part of the cluster service the cluster alert
// sources read.
type clusterAlertView interface {
	Snapshot() cluster.State
	RolloutStatus() cluster.RolloutStatus
	ReportedAlerts(time.Time) []alerts.Alert
}

// clusterAlertSources are the cluster's alert sources. The lead tells about
// nodes going down and coming back, about rolling updates, and whatever each
// replica reports about itself. Replicas tell about the lead, which cannot
// tell about itself.
func clusterAlertSources(view clusterAlertView) []alerts.Source {
	return []alerts.Source{
		&nodeOutageSource{cluster: view, outages: make(map[string]clusterOutage)},
		rolloutAlertSource{cluster: view},
		alerts.SourceFunc(func(_ context.Context, now time.Time) ([]alerts.Alert, error) {
			return view.ReportedAlerts(now), nil
		}),
		alerts.Place(&leadOutageSource{cluster: view}, alerts.OnReplicas),
	}
}

// clusterOutage is one stretch of a node out of touch with the node watching
// it.
type clusterOutage struct {
	// since is the node's last contact, or, for a node not heard from since
	// this one started watching, when it was first missed. Alert IDs carry
	// it, so it never moves once the outage has alerted.
	since time.Time
	// declaredAt is when the outage grew long enough to alert. It is zero
	// until then.
	declaredAt time.Time
}

// follow carries an outage forward one round. A node heard from since the
// outage began gets a fresh wait, unless the outage already alerted: that
// alert keeps its ID until the node is back.
func (outage clusterOutage) follow(tracked bool, lastContact, now time.Time) clusterOutage {
	switch {
	case !tracked:
		outage = clusterOutage{since: now}
		if !lastContact.IsZero() && lastContact.Before(now) {
			outage.since = lastContact
		}
	case outage.declaredAt.IsZero() && lastContact.After(outage.since):
		outage.since = lastContact
	}
	return outage
}

// due reports whether the outage has lasted long enough to alert and has not
// yet.
func (outage clusterOutage) due(now time.Time) bool {
	return outage.declaredAt.IsZero() && now.Sub(outage.since) >= clusterOutageGrace
}

// nodeOutageSource runs on the lead. It alerts when a node has been out of
// touch for five minutes, and again when it is back. It remembers outages in
// memory: the lead's view of the other nodes starts over anyway when it
// restarts or takes the lead.
type nodeOutageSource struct {
	cluster clusterAlertView
	mu      sync.Mutex
	askedAt time.Time
	outages map[string]clusterOutage
	events  []alerts.Alert
}

func (source *nodeOutageSource) Alerts(_ context.Context, now time.Time) ([]alerts.Alert, error) {
	state := source.cluster.Snapshot()
	source.mu.Lock()
	defer source.mu.Unlock()
	leading := state.Initialized && state.LocalRole == cluster.RolePrimary
	if watchLapsed(source.askedAt, now) || !leading {
		clear(source.outages)
	}
	source.askedAt = now
	source.events = currentEvents(source.events, now)
	if !leading {
		return slices.Clone(source.events), nil
	}
	lead := clusterMemberName(state, state.NodeID)
	present := make(map[string]bool, len(state.Nodes))
	for _, node := range state.Nodes {
		if node.ID == state.NodeID {
			continue
		}
		present[node.ID] = true
		outage, tracked := source.outages[node.ID]
		if node.State == cluster.StateOnline {
			if tracked && !outage.declaredAt.IsZero() {
				source.events = appendEvent(source.events, nodeBackUpAlert(node, lead, outage, now))
			}
			delete(source.outages, node.ID)
			continue
		}
		outage = outage.follow(tracked, node.LastContact, now)
		if outage.due(now) {
			outage.declaredAt = now
		}
		source.outages[node.ID] = outage
	}
	// A node removed from the cluster is not coming back, so its outage ends
	// without an all-clear.
	maps.DeleteFunc(source.outages, func(id string, _ clusterOutage) bool { return !present[id] })
	found := slices.Clone(source.events)
	for _, node := range state.Nodes {
		if outage, tracked := source.outages[node.ID]; tracked && !outage.declaredAt.IsZero() {
			found = append(found, nodeDownAlert(node, lead, outage, now))
		}
	}
	return found, nil
}

// rolloutAlertSource runs on the lead and tells when a rolling update starts,
// finishes, fails, or is stopped. The rollout keeps when each happened, so
// each stays news for a day even across the lead's own restart, which is how
// a rollout ends.
type rolloutAlertSource struct {
	cluster clusterAlertView
}

func (source rolloutAlertSource) Alerts(_ context.Context, now time.Time) ([]alerts.Alert, error) {
	state := source.cluster.Snapshot()
	rollout := source.cluster.RolloutStatus()
	if !state.Initialized || state.LocalRole != cluster.RolePrimary || rollout.ID == "" ||
		rollout.ClusterID != state.ClusterID || rollout.PrimaryID != state.PrimaryID {
		return nil, nil
	}
	found := make([]alerts.Alert, 0, 2)
	if stillNews(rollout.StartedAt, now) {
		found = append(found, rolloutStartedAlert(rollout))
	}
	if !rollout.Active() && stillNews(rollout.FinishedAt, now) {
		if ended, ok := rolloutEndedAlert(rollout); ok {
			found = append(found, ended)
		}
	}
	return found, nil
}

// leadOutageSource runs on replicas. It alerts when the lead has been out of
// touch for five minutes, and again when it answers. Every replica sees the
// same outage, so only the replica with the lowest node ID tells, and the
// cluster alerts once.
type leadOutageSource struct {
	cluster clusterAlertView
	mu      sync.Mutex
	askedAt time.Time
	// leadID names the lead whose outage is being followed; it is empty while
	// the lead answers.
	leadID string
	outage clusterOutage
	events []alerts.Alert
}

func (source *leadOutageSource) Alerts(_ context.Context, now time.Time) ([]alerts.Alert, error) {
	state := source.cluster.Snapshot()
	source.mu.Lock()
	defer source.mu.Unlock()
	lead, known := clusterNode(state, state.PrimaryID)
	following := state.Initialized && state.LocalRole == cluster.RoleReplica && known
	if watchLapsed(source.askedAt, now) || !following || lead.ID != source.leadID {
		// A new lead, most often from a planned handoff, starts clean: the
		// last one's outage is no news about this one.
		source.leadID, source.outage = "", clusterOutage{}
	}
	source.askedAt = now
	source.events = currentEvents(source.events, now)
	if !following {
		return slices.Clone(source.events), nil
	}
	replica := clusterMemberName(state, state.NodeID)
	tracked := source.leadID != ""
	if lead.State == cluster.StateOnline {
		if tracked && !source.outage.declaredAt.IsZero() {
			source.events = appendEvent(source.events, leadBackUpAlert(lead, replica, source.outage, now))
		}
		source.leadID, source.outage = "", clusterOutage{}
		return slices.Clone(source.events), nil
	}
	source.leadID = lead.ID
	source.outage = source.outage.follow(tracked, lead.LastContact, now)
	if source.outage.due(now) && speaksForReplicas(state) {
		source.outage.declaredAt = now
	}
	found := slices.Clone(source.events)
	if !source.outage.declaredAt.IsZero() {
		found = append(found, leadDownAlert(lead, replica, source.outage, now))
	}
	return found, nil
}

// speaksForReplicas reports whether this replica is the one that tells about
// the lead: the replica with the lowest node ID in its last known cluster
// state.
func speaksForReplicas(state cluster.State) bool {
	lowest := ""
	for _, node := range state.Nodes {
		if node.Role == cluster.RoleReplica && (lowest == "" || node.ID < lowest) {
			lowest = node.ID
		}
	}
	return lowest != "" && lowest == state.NodeID
}

// watchLapsed reports whether an outage source went unasked long enough that
// what it remembers can no longer be trusted.
func watchLapsed(askedAt, now time.Time) bool {
	return askedAt.IsZero() || now.Before(askedAt) || now.Sub(askedAt) > clusterWatchGap
}

// currentEvents drops the events that are no longer news.
func currentEvents(events []alerts.Alert, now time.Time) []alerts.Alert {
	return slices.DeleteFunc(events, func(event alerts.Alert) bool { return !stillNews(event.ObservedAt, now) })
}

func appendEvent(events []alerts.Alert, event alerts.Alert) []alerts.Alert {
	if slices.ContainsFunc(events, func(held alerts.Alert) bool { return held.ID == event.ID }) {
		return events
	}
	return append(events, event)
}

// stillNews reports whether something that happened at a time is still news.
func stillNews(at, now time.Time) bool {
	return !at.IsZero() && now.Sub(at) < clusterEventNews
}

func clusterNode(state cluster.State, id string) (cluster.Node, bool) {
	index := slices.IndexFunc(state.Nodes, func(node cluster.Node) bool { return node.ID == id })
	if index < 0 {
		return cluster.Node{}, false
	}
	return state.Nodes[index], true
}

func clusterMemberName(state cluster.State, id string) string {
	if node, found := clusterNode(state, id); found && node.Name != "" {
		return node.Name
	}
	return "this node"
}

func nodeDownAlert(node cluster.Node, lead string, outage clusterOutage, now time.Time) alerts.Alert {
	reasons := []string{"No check-in since " + lead + " took the lead"}
	if !node.LastContact.IsZero() {
		reasons[0] = "Last check-in " + spokenDuration(now.Sub(node.LastContact)) + " ago"
	}
	if len(node.Addresses) > 0 {
		reasons = append(reasons, "DNS at "+strings.Join(node.Addresses, ", "))
	}
	return alerts.Alert{
		ID:    fmt.Sprintf("cluster.node-down:%s:%d", node.ID, outage.since.Unix()),
		Group: config.AlertGroupCluster, Kind: "cluster.node-down", Problem: true, Tone: alerts.ToneAttention,
		Title: "Node down", Subject: node.Name, Headline: node.Name + " stopped checking in",
		Summary: fmt.Sprintf("%s has not checked in with %s for %s. It may be down or cut off from the other nodes.",
			node.Name, lead, spokenDuration(now.Sub(outage.since))),
		Reasons: reasons, Path: clusterPath, PathLabel: clusterPathLabel, ObservedAt: outage.declaredAt,
	}
}

func nodeBackUpAlert(node cluster.Node, lead string, outage clusterOutage, now time.Time) alerts.Alert {
	away := spokenDuration(now.Sub(outage.since))
	reasons := []string{"Out of touch for " + away}
	if node.Version != "" {
		reasons = append(reasons, "Runs Sable "+node.Version)
	}
	return alerts.Alert{
		ID:    fmt.Sprintf("cluster.node-up:%s:%d", node.ID, outage.since.Unix()),
		Group: config.AlertGroupCluster, Kind: "cluster.node-up", Tone: alerts.TonePositive,
		Title: "Node back up", Subject: node.Name, Headline: node.Name + " is checking in again",
		Summary: fmt.Sprintf("%s checked in with %s again after %s out of touch.", node.Name, lead, away),
		Reasons: reasons, Path: clusterPath, PathLabel: clusterPathLabel, ObservedAt: now,
	}
}

func leadDownAlert(lead cluster.Node, replica string, outage clusterOutage, now time.Time) alerts.Alert {
	reasons := []string{"No answer since " + replica + " started", "Noticed by " + replica}
	if !lead.LastContact.IsZero() {
		reasons[0] = "Last answer " + spokenDuration(now.Sub(lead.LastContact)) + " ago"
	}
	return alerts.Alert{
		ID:    fmt.Sprintf("cluster.lead-down:%s:%d", lead.ID, outage.since.Unix()),
		Group: config.AlertGroupCluster, Kind: "cluster.lead-down", Problem: true, Tone: alerts.ToneAttention,
		Title: "Lead node not answering", Subject: lead.Name, Headline: lead.Name + " stopped answering",
		Summary: fmt.Sprintf("%s has not heard from %s, the lead node, for %s. DNS keeps working on the other nodes, but changes wait until %s is back or another node is promoted.",
			replica, lead.Name, spokenDuration(now.Sub(outage.since)), lead.Name),
		Reasons: reasons, Path: clusterPath, PathLabel: clusterPathLabel, ObservedAt: outage.declaredAt,
	}
}

func leadBackUpAlert(lead cluster.Node, replica string, outage clusterOutage, now time.Time) alerts.Alert {
	away := spokenDuration(now.Sub(outage.since))
	return alerts.Alert{
		ID:    fmt.Sprintf("cluster.lead-up:%s:%d", lead.ID, outage.since.Unix()),
		Group: config.AlertGroupCluster, Kind: "cluster.lead-up", Tone: alerts.TonePositive,
		Title: "Lead node back up", Subject: lead.Name, Headline: lead.Name + " is answering again",
		Summary: fmt.Sprintf("%s reached %s again after %s without an answer. Changes can be made again.", replica, lead.Name, away),
		Reasons: []string{"Out of touch for " + away}, Path: clusterPath, PathLabel: clusterPathLabel, ObservedAt: now,
	}
}

func rolloutStartedAlert(rollout cluster.RolloutStatus) alerts.Alert {
	return alerts.Alert{
		ID:    "cluster.rollout-started:" + rollout.ID,
		Group: config.AlertGroupCluster, Kind: "cluster.rollout-started", Tone: alerts.ToneNotice,
		Title: "Rolling update started", Subject: rollout.Version,
		Headline: fmt.Sprintf("Updating %s to %s", counted(len(rollout.Nodes), "node"), rollout.Version),
		Summary:  fmt.Sprintf("Sable is updating %s to %s, one node at a time.", spokenList(rolloutNodeNames(rollout)), rollout.Version),
		Path:     clusterPath, PathLabel: clusterPathLabel, ObservedAt: rollout.StartedAt,
	}
}

// rolloutEndedAlert words how a rollout ended. A rollout still running has
// not ended, and says nothing.
func rolloutEndedAlert(rollout cluster.RolloutStatus) (alerts.Alert, bool) {
	alert := alerts.Alert{
		Group: config.AlertGroupCluster, Subject: rollout.Version,
		Path: clusterPath, PathLabel: clusterPathLabel, ObservedAt: rollout.FinishedAt,
	}
	switch rollout.Phase {
	case cluster.RolloutComplete:
		alert.Kind, alert.Tone, alert.Title = "cluster.rollout-finished", alerts.TonePositive, "Rolling update finished"
		alert.Headline = "Every node runs " + rollout.Version
		alert.Summary = fmt.Sprintf("%s now run %s.", spokenList(rolloutNodeNames(rollout)), rollout.Version)
		if !rollout.StartedAt.IsZero() && rollout.FinishedAt.After(rollout.StartedAt) {
			alert.Reasons = []string{"Took " + spokenDuration(rollout.FinishedAt.Sub(rollout.StartedAt))}
		}
	case cluster.RolloutFailed:
		alert.Kind, alert.Problem, alert.Tone, alert.Title = "cluster.rollout-failed", true, alerts.ToneAttention, "Rolling update failed"
		alert.Headline = "The update to " + rollout.Version + " failed"
		if rollout.FailedNode != "" {
			alert.Headline += " on " + rollout.FailedNode
		}
		alert.Summary = alert.Headline + ". Nodes it had not reached yet keep their current release."
		if rollout.Error != "" {
			alert.Reasons = []string{rollout.Error}
		}
	case cluster.RolloutStopped:
		alert.Kind, alert.Tone, alert.Title = "cluster.rollout-stopped", alerts.ToneNotice, "Rolling update stopped"
		alert.Headline = "The update to " + rollout.Version + " was stopped"
		alert.Summary = alert.Headline + ". Nodes that already updated keep it, and no more will restart."
	default:
		return alerts.Alert{}, false
	}
	alert.ID = alert.Kind + ":" + rollout.ID
	return alert, true
}

func rolloutNodeNames(rollout cluster.RolloutStatus) []string {
	names := make([]string, 0, len(rollout.Nodes))
	for _, node := range rollout.Nodes {
		names = append(names, node.Name)
	}
	return names
}

// spokenList joins names the way a sentence does: "a", "a and b", or
// "a, b, and c".
func spokenList(names []string) string {
	switch len(names) {
	case 0:
		return "every node"
	case 1:
		return names[0]
	case 2:
		return names[0] + " and " + names[1]
	default:
		return strings.Join(names[:len(names)-1], ", ") + ", and " + names[len(names)-1]
	}
}

// spokenDuration says how long something lasted the way people say it, to the
// minute: "6 minutes", "1 hour 5 minutes", or "2 days 3 hours".
func spokenDuration(duration time.Duration) string {
	if duration < time.Minute {
		return "under a minute"
	}
	minutes := int(duration / time.Minute)
	days, hours := minutes/(24*60), minutes/60%24
	minutes %= 60
	switch {
	case days > 0 && hours > 0:
		return counted(days, "day") + " " + counted(hours, "hour")
	case days > 0:
		return counted(days, "day")
	case hours > 0 && minutes > 0:
		return counted(hours, "hour") + " " + counted(minutes, "minute")
	case hours > 0:
		return counted(hours, "hour")
	default:
		return counted(minutes, "minute")
	}
}

func counted(count int, unit string) string {
	if count == 1 {
		return "1 " + unit
	}
	return strconv.Itoa(count) + " " + unit + "s"
}
