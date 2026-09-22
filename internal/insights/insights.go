// Package insights turns what Sable already records into short, evidence-backed
// findings. Everything here is deterministic and local: a finding is only
// produced when the data behind it can be shown to the operator, and each one
// carries that evidence so the console can explain itself instead of asking
// the operator to trust it.
//
// Each area of the network Sable understands lives in its own subpackage and
// produces the same Finding shape, so the console can present blocking
// findings today and other areas later without a second presentation model.
package insights

import (
	"context"
	"fmt"
	"math"
	"slices"
	"strconv"
	"strings"
	"time"
)

// Tone is how much a finding asks of the operator. It orders findings and
// colors them; it never implies an action Sable cannot justify.
type Tone string

const (
	// ToneAttention marks evidence that something went wrong, such as a name
	// that was blocked before an operator allowed it.
	ToneAttention Tone = "attention"
	// ToneNotice marks a fact worth knowing that is not a problem by itself.
	ToneNotice Tone = "notice"
	// TonePositive marks something that is working as intended.
	TonePositive Tone = "positive"
)

// Fact is one labeled piece of evidence.
type Fact struct {
	Label string
	Value string
	// Time is set instead of Value for a moment, which the console formats
	// with the operator's time display preferences.
	Time time.Time
	// Monospace marks DNS data, which the console sets in a monospace face.
	Monospace bool
}

// Count is one named value with its number of observations, such as a client
// and the queries it sent.
type Count struct {
	Name string
	Hits uint64
}

// QueryFilter describes the query log rows a finding was counted from. The
// console adds the finding's time window and an exact match, so following the
// evidence reproduces the finding's count rather than a broader search.
type QueryFilter struct {
	Name     string
	ClientIP string
	Blocked  bool
}

// DomainEvidence is one name behind a finding.
type DomainEvidence struct {
	Name      string
	FirstSeen time.Time
	Query     *QueryFilter
}

// Subject is what a finding is about. The label is for display; the typed
// references identify the subject durably, so a later dismissal, correction,
// or label can attach to the thing itself rather than to its display text.
// Only the references that apply are set.
type Subject struct {
	Label     string
	Monospace bool
	// Device is a device identity key such as "mac:3c:22:fb:01:02:03" or
	// "ip:10.0.0.5".
	Device    string
	Domain    string
	BlockList string
}

// key is the most specific durable reference to the subject.
func (subject Subject) key() string {
	switch {
	case subject.Device != "":
		return "device:" + subject.Device
	case subject.Domain != "":
		return "domain:" + subject.Domain
	case subject.BlockList != "":
		return "blocklist:" + subject.BlockList
	default:
		return "label:" + subject.Label
	}
}

// Finding is one thing worth knowing, with the evidence that supports it.
type Finding struct {
	// ID is stable for the same kind of finding about the same subject, so
	// analyzing the same situation again produces the same ID.
	ID string
	// Kind identifies the rule that produced the finding, namespaced by the
	// analyzer that owns it, such as "devices.went-quiet".
	Kind    string
	Tone    Tone
	Title   string
	Subject Subject
	// Summary states the evidence in one factual sentence.
	Summary string
	// Reasons are the individual observations behind the finding, each one a
	// short statement the operator can check against the facts below it.
	Reasons []string
	Facts   []Fact
	// Clients lists the clients the evidence involves, busiest first.
	Clients []Count
	// Domains lists the names the evidence involves, with the query filter
	// that reproduces each one's rows.
	Domains []DomainEvidence
	// Explanations are plain possibilities for what the finding could mean,
	// offered as next steps to check rather than conclusions.
	Explanations []string
	// Method is the rule that produced the finding, the same for every
	// finding of its kind, including what the rule does not claim.
	Method string
	// Query is set when the finding was counted from the query log.
	Query *QueryFilter
	// Destination is a console page where the subject can be managed.
	Destination      string
	DestinationLabel string
	// ObservedAt is the end of the window the finding describes.
	ObservedAt time.Time
}

// NewID builds a finding's stable identifier from its kind and subject.
func NewID(kind string, subject Subject) string {
	return kind + "/" + subject.key()
}

// Window is the period an analysis covers.
type Window struct {
	Start time.Time
	End   time.Time
}

// Analyzer examines one area of the network and reports what is worth
// knowing about it. Every area produces the same Finding shape, so the
// console presents blocking, devices, and future areas side by side.
// Analyzers run outside the DNS request path, on persisted and derived data.
type Analyzer interface {
	Analyze(context.Context, Window) ([]Finding, error)
}

// Collect runs every analyzer over a window and returns their findings, most
// urgent first, keeping each analyzer's own order within a tone. An analyzer
// that fails is reported through failed and leaves the others unaffected.
func Collect(ctx context.Context, window Window, analyzers []Analyzer, failed func(Analyzer, error)) []Finding {
	findings := make([]Finding, 0)
	for _, analyzer := range analyzers {
		produced, err := analyzer.Analyze(ctx, window)
		if err != nil {
			if failed != nil {
				failed(analyzer, err)
			}
			continue
		}
		for _, finding := range produced {
			if finding.ID == "" {
				finding.ID = NewID(finding.Kind, finding.Subject)
			}
			if finding.ObservedAt.IsZero() {
				finding.ObservedAt = window.End
			}
			findings = append(findings, finding)
		}
	}
	rank := map[Tone]int{ToneAttention: 0, ToneNotice: 1, TonePositive: 2}
	slices.SortStableFunc(findings, func(left, right Finding) int { return rank[left.Tone] - rank[right.Tone] })
	return findings
}

// FormatCount renders a count with thousands separators.
func FormatCount(value uint64) string {
	digits := strconv.FormatUint(value, 10)
	var grouped strings.Builder
	for index, digit := range digits {
		if index > 0 && (len(digits)-index)%3 == 0 {
			grouped.WriteByte(',')
		}
		grouped.WriteRune(digit)
	}
	return grouped.String()
}

// FormatShare renders part of a whole as a percentage with one decimal. A share
// that is not quite everything never prints as 100%, and one that is not quite
// nothing never prints as 0%, because either would overstate the evidence.
func FormatShare(part, whole uint64) string {
	if whole == 0 || part == 0 {
		return "0%"
	}
	if part >= whole {
		return "100%"
	}
	share := float64(part) * 100 / float64(whole)
	switch {
	case share < 0.1:
		return "<0.1%"
	case share > 99.9:
		return ">99.9%"
	}
	tenths := math.Round(share * 10)
	if tenths >= 1000 {
		tenths = 999
	}
	return strconv.FormatFloat(tenths/10, 'f', 1, 64) + "%"
}

// Plural picks the singular or plural form of a noun for a count.
func Plural[T ~int | ~int64 | ~uint64](count T, singular, plural string) string {
	if count == 1 {
		return singular
	}
	return plural
}

// FormatDuration renders a span of time in coarse, readable units.
func FormatDuration(elapsed time.Duration) string {
	switch {
	case elapsed < time.Minute:
		return "under a minute"
	case elapsed < time.Hour:
		minutes := int(elapsed / time.Minute)
		return fmt.Sprintf("%d %s", minutes, Plural(minutes, "minute", "minutes"))
	case elapsed < 24*time.Hour:
		hours := int(elapsed / time.Hour)
		return fmt.Sprintf("%d %s", hours, Plural(hours, "hour", "hours"))
	default:
		// Past a day, the nearest whole day reads better than a floor: 47
		// hours is "2 days", not "1 day".
		days := int((elapsed + 12*time.Hour) / (24 * time.Hour))
		return fmt.Sprintf("%d %s", days, Plural(days, "day", "days"))
	}
}
