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
	"fmt"
	"math"
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

// Finding is one thing worth knowing, with the evidence that supports it.
type Finding struct {
	// Kind identifies the rule that produced the finding.
	Kind string
	Tone Tone
	// Title names the kind of finding in plain words.
	Title string
	// Subject is what the finding is about: a domain, a list, a client.
	Subject          string
	SubjectMonospace bool
	// Summary states the evidence in one factual sentence.
	Summary string
	Facts   []Fact
	// Clients lists the clients the evidence involves, busiest first.
	Clients []Count
	// Method explains how Sable arrived at the finding and what it does not
	// claim.
	Method string
	// Query is set when the finding was counted from the query log.
	Query *QueryFilter
	// Destination is a console page where the subject can be managed.
	Destination      string
	DestinationLabel string
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
	case elapsed < 48*time.Hour:
		hours := int(elapsed / time.Hour)
		return fmt.Sprintf("%d %s", hours, Plural(hours, "hour", "hours"))
	default:
		days := int(elapsed / (24 * time.Hour))
		return fmt.Sprintf("%d %s", days, Plural(days, "day", "days"))
	}
}
