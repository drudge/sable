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

// Reason is one observation behind a finding. Code holds DNS or network data
// the reason names, such as a hardware address or a domain, which the console
// sets in a monospace face after the text.
type Reason struct {
	Text string
	Code string
}

// Reasons turns plain statements into reasons.
func Reasons(texts ...string) []Reason {
	reasons := make([]Reason, 0, len(texts))
	for _, text := range texts {
		reasons = append(reasons, Reason{Text: text})
	}
	return reasons
}

// Subject is what a finding is about. The label is for display; the typed
// references identify the subject durably, so a later dismissal, correction,
// or label can attach to the thing itself rather than to its display text.
// Only the references that apply are set.
type Subject struct {
	Label string
	// LabelSource says where Label came from when it is a name Sable chose,
	// such as "UniFi" or "Reverse DNS", so the page can show its provenance.
	LabelSource string
	Monospace   bool
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
	// Headline is the finding as a short clause for the page's one-sentence
	// summary, such as "dock-camera-02 went quiet". Findings that are not
	// news, such as how much two block lists overlap, leave it empty.
	Headline string
	// Reasons are the individual observations behind the finding, each one a
	// short statement the operator can check against the facts below it.
	Reasons []Reason
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
	// Chart pictures the evidence, for a finding whose shape says more than
	// its numbers.
	Chart *Chart
}

// Chart is a picture of a finding's evidence. One of its parts is set.
type Chart struct {
	Days     *DayChart
	Hours    *HourChart
	Schedule *ScheduleChart
}

// DayChart compares a subject's last 24 hours with each day of the week
// before it.
type DayChart struct {
	// Before is the count for each 24 hours of the week before, oldest first,
	// and Average their daily average.
	Before  []uint64
	Average float64
	Last    uint64
}

// HourChart compares the hours of a subject's last day with its usual day, by
// local hour of the day.
type HourChart struct {
	// Usual is the average count for each hour over the days before. Unusual
	// is the count in the last 24 hours for each hour the finding is about,
	// and zero for the others.
	Usual   [24]float64
	Unusual [24]uint64
}

// ScheduleChart places each time something happened on a timeline, so a
// steady rhythm shows as evenly spaced marks.
type ScheduleChart struct {
	Start, End time.Time
	Times      []time.Time
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

// JoinAnd lists names in a sentence: "A", "A and B", or "A, B, and C".
func JoinAnd(names []string) string { return joinList(names, "and") }

// JoinOr lists alternatives in a sentence: "A", "A or B", or "A, B, or C".
func JoinOr(names []string) string { return joinList(names, "or") }

func joinList(names []string, conjunction string) string {
	switch len(names) {
	case 0:
		return ""
	case 1:
		return names[0]
	case 2:
		return names[0] + " " + conjunction + " " + names[1]
	default:
		return strings.Join(names[:len(names)-1], ", ") + ", " + conjunction + " " + names[len(names)-1]
	}
}

// Feedback actions an operator can take on a finding.
const (
	// FeedbackSnooze hides a finding until a moment.
	FeedbackSnooze = "snooze"
	// FeedbackNormal hides a finding for good: the operator says this is how
	// the subject normally behaves.
	FeedbackNormal = "normal"
)

// Feedback is what an operator said about one finding. It is kept by the
// finding's stable ID, which names its subject durably, so it survives the
// subject being renamed and can later teach Sable what is normal here.
type Feedback struct {
	FindingID string
	Action    string
	// Until ends a snooze; it is zero for a finding marked normal.
	Until time.Time
	// Label is how the finding read when the operator acted, for listing.
	Label     string
	CreatedBy string
	CreatedAt time.Time
}

// Active reports whether feedback still hides its finding at a moment.
func (feedback Feedback) Active(now time.Time) bool {
	return feedback.Action == FeedbackNormal || (feedback.Action == FeedbackSnooze && now.Before(feedback.Until))
}

// Hide splits findings into those to show and those the operator hid.
func Hide(findings []Finding, feedback []Feedback, now time.Time) (shown, hidden []Finding) {
	active := make(map[string]bool, len(feedback))
	for _, entry := range feedback {
		if entry.Active(now) {
			active[entry.FindingID] = true
		}
	}
	for _, finding := range findings {
		if active[finding.ID] {
			hidden = append(hidden, finding)
		} else {
			shown = append(shown, finding)
		}
	}
	return shown, hidden
}

// maximumHeadlines is how many findings the one-sentence summary names.
const maximumHeadlines = 3

// Headlines picks the findings the one-sentence summary of what stands out
// names, most important first, and counts the other findings with news the
// sentence leaves to the list below it.
func Headlines(findings []Finding) (named []Finding, more int) {
	named = make([]Finding, 0, maximumHeadlines)
	for _, finding := range findings {
		switch {
		case finding.Headline == "":
		case len(named) == maximumHeadlines:
			more++
		default:
			named = append(named, finding)
		}
	}
	return named, more
}
