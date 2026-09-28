// Package alerts tells people about what Sable notices, wherever they chose to
// hear it: ntfy, Pushover, Slack, Discord, a webhook, or their browsers.
//
// Sources say what is news right now: a finding Insights made, a node that
// stopped answering, a backup that failed. The dispatcher sends each alert once
// to each destination that wants its group, from the node leading the
// cluster, so a cluster alerts once. Problems go out at high priority where a
// destination has one.
package alerts

import (
	"context"
	"time"
)

// Tone is how an alert reads: worth attention, worth knowing, or good news.
// Slack and Discord color their cards by it.
type Tone string

const (
	ToneAttention Tone = "attention"
	ToneNotice    Tone = "notice"
	TonePositive  Tone = "positive"
)

// Alert is one piece of news, worded for people.
type Alert struct {
	// ID names the alert for as long as it is news. A destination is never sent
	// the same ID twice while it stays news, so an ID should change when the
	// news does: a node that goes down again gets a new one.
	ID string `json:"id"`
	// Group is the switch that covers the alert, one of config's AlertGroup
	// names, such as "cluster".
	Group string `json:"group"`
	// Kind names what happened, such as "cluster.node-down", for webhooks that
	// route on it.
	Kind string `json:"kind"`
	// Problem marks something wrong that needs a look. Destinations that have
	// a priority deliver problems at high priority.
	Problem bool `json:"problem,omitempty"`
	Tone    Tone `json:"tone"`
	// Title says what kind of news it is, such as "Node down"; Subject names
	// what it is about, such as "ns2". Together they make the notification's
	// title.
	Title   string `json:"title"`
	Subject string `json:"subject"`
	// Headline is the news in one short sentence.
	Headline string   `json:"headline"`
	Summary  string   `json:"summary"`
	Reasons  []string `json:"reasons,omitempty"`
	// Path is where in the console to look, such as "/insights", and
	// PathLabel is the button that opens it, such as "Open Insights".
	Path       string    `json:"path"`
	PathLabel  string    `json:"path_label"`
	ObservedAt time.Time `json:"observed_at"`
}

// Source reports the alerts that are news right now. An alert stays in the
// list for as long as it is news. The dispatcher sends it once to each
// destination and forgets it after it has been gone for a while, so the same
// news coming back much later alerts again. An error leaves the source's
// alerts out of that round without forgetting them.
type Source interface {
	Alerts(ctx context.Context, now time.Time) ([]Alert, error)
}

// Placement says which nodes run a source.
type Placement int

const (
	// OnLead runs on the node leading the cluster, or on a node alone. Most
	// sources look at the whole cluster, so they run once, there.
	OnLead Placement = iota
	// OnEachNode runs on every node, for problems a node sees in itself, such
	// as a failed backup. A replica hands its alerts to the lead, which sends
	// them; see Dispatcher.Local.
	OnEachNode
	// OnReplicas runs only on replicas, for what the lead cannot say about
	// itself, such as having stopped answering.
	OnReplicas
)

// Placed is a source that says where it runs. A source that does not runs on
// the lead.
type Placed interface {
	Source
	Placement() Placement
}

// SourceFunc makes a function a source that runs on the lead.
type SourceFunc func(ctx context.Context, now time.Time) ([]Alert, error)

func (function SourceFunc) Alerts(ctx context.Context, now time.Time) ([]Alert, error) {
	return function(ctx, now)
}

// Place gives a source a placement.
func Place(source Source, placement Placement) Placed {
	return placedSource{Source: source, placement: placement}
}

type placedSource struct {
	Source
	placement Placement
}

func (source placedSource) Placement() Placement { return source.placement }

func placementOf(source Source) Placement {
	if placed, ok := source.(Placed); ok {
		return placed.Placement()
	}
	return OnLead
}
