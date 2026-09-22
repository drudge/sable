package blocking

import (
	"cmp"
	"fmt"
	"slices"
	"time"

	blockcompiler "github.com/drudge/sable/internal/blocking"
	"github.com/drudge/sable/internal/insights"
	"github.com/drudge/sable/internal/querylog"
)

// Finding kinds produced by this package.
const (
	KindPastBlock      = "blocking.past-block"
	KindUpdateFailing  = "blocking.update-failing"
	KindListUnreadable = "blocking.list-unreadable"
	KindLowUnique      = "blocking.low-unique-coverage"
	KindUniqueCoverage = "blocking.unique-coverage"
)

// Thresholds for the coverage findings. They are deliberately conservative:
// the page should stay quiet unless a number is clearly worth reading.
const (
	// lowUniqueShare flags a list when less than this share of its domains is
	// covered by no other list.
	lowUniqueShare = 0.01
	// meaningfulUniqueShare and meaningfulUniqueDomains recognize a list that
	// clearly adds coverage of its own.
	meaningfulUniqueShare   = 0.2
	meaningfulUniqueDomains = 1_000
	// minimumComparedDomains keeps tiny lists from producing dramatic
	// percentages out of a handful of names.
	minimumComparedDomains = 100
	// staleUpdateIntervals is how many missed update intervals make a failing
	// list worth mentioning here. A single failed attempt is already visible
	// on the Blocking page and usually recovers on retry.
	staleUpdateIntervals = 2
	maximumPastBlocks    = 3
	maximumLowUnique     = 2
	maximumFindings      = 6
	maximumPastClients   = 10
)

// PastBlock is a name the query log shows as blocked in the window that an
// allow rule now matches.
type PastBlock struct {
	Rule     string
	Evidence querylog.BlockedNameEvidence
}

// ListHealth pairs a configured list with its download history.
type ListHealth struct {
	Name   string
	Health blockcompiler.SourceHealth
}

// FindingsInput is everything the blocking findings are derived from. A nil
// Contribution means the list comparison is unavailable, for example because
// the operator may read query history but not blocking configuration.
type FindingsInput struct {
	Now            time.Time
	Contribution   *Contribution
	Health         []ListHealth
	UpdateInterval time.Duration
	PastBlocks     []PastBlock
}

// Findings turns the inputs into a short list of evidence-backed findings,
// most important first. Every sentence states what the data shows and nothing
// it cannot: list findings describe overlap, never advise removing a list, and
// a past block is reported only when a name was blocked and is now explicitly
// allowed.
func Findings(input FindingsInput) []insights.Finding {
	findings := make([]insights.Finding, 0, maximumFindings)
	findings = append(findings, pastBlockFindings(input.PastBlocks)...)
	findings = append(findings, updateFindings(input)...)
	if input.Contribution != nil {
		findings = append(findings, unreadableFindings(*input.Contribution)...)
		findings = append(findings, coverageFindings(*input.Contribution)...)
	}
	return findings[:min(len(findings), maximumFindings)]
}

func pastBlockFindings(blocks []PastBlock) []insights.Finding {
	blocks = slices.Clone(blocks)
	slices.SortFunc(blocks, func(left, right PastBlock) int {
		if order := cmp.Compare(right.Evidence.Blocked, left.Evidence.Blocked); order != 0 {
			return order
		}
		return cmp.Compare(left.Evidence.Name, right.Evidence.Name)
	})
	findings := make([]insights.Finding, 0, min(len(blocks), maximumPastBlocks))
	for _, block := range blocks {
		if len(findings) == maximumPastBlocks {
			break
		}
		evidence := block.Evidence
		if evidence.Blocked == 0 || block.Rule == "" {
			continue
		}
		allowedBy := "is now explicitly allowed"
		if block.Rule != evidence.Name {
			allowedBy = "is now allowed by " + block.Rule
		}
		clients := rankedCounts(evidence.Clients, maximumPastClients)
		facts := []insights.Fact{
			{Label: "Blocked requests", Value: insights.FormatCount(evidence.Blocked)},
			{Label: "Clients", Value: insights.FormatCount(evidence.ClientCount)},
			{Label: "First blocked", Time: evidence.FirstBlocked},
			{Label: "Last blocked", Time: evidence.LastBlocked},
			{Label: "Current policy", Value: "Allowed by " + block.Rule, Monospace: true},
		}
		findings = append(findings, insights.Finding{
			Kind:             KindPastBlock,
			Tone:             insights.ToneAttention,
			Title:            "Possible past blocking issue",
			Subject:          evidence.Name,
			SubjectMonospace: true,
			Summary: fmt.Sprintf("Blocked %s %s during the selected period and %s.",
				insights.FormatCount(evidence.Blocked), insights.Plural(evidence.Blocked, "time", "times"), allowedBy),
			Facts:   facts,
			Clients: clients,
			Method: "Sable compares the allowed domains with the blocked queries it retained for this period. " +
				"A name that was blocked and is now allowed usually means somebody ran into a block and corrected it. " +
				"Repeated or retried queries alone are never treated as evidence of a problem.",
			Query:            &insights.QueryFilter{Name: evidence.Name, Blocked: true},
			Destination:      "/blocked?tab=allowed",
			DestinationLabel: "Allowed Domains",
		})
	}
	return findings
}

func updateFindings(input FindingsInput) []insights.Finding {
	interval := input.UpdateInterval
	if interval <= 0 {
		interval = 24 * time.Hour
	}
	findings := make([]insights.Finding, 0)
	for _, list := range input.Health {
		health := list.Health
		if health.Healthy() {
			continue
		}
		stale := health.LastSuccess.IsZero() || input.Now.Sub(health.LastSuccess) >= staleUpdateIntervals*interval
		if !stale {
			continue
		}
		summary := fmt.Sprintf("The last %s %s failed.", insights.FormatCount(uint64(health.ConsecutiveFailures)),
			insights.Plural(health.ConsecutiveFailures, "update", "updates"))
		if health.ConsecutiveFailures == 1 {
			summary = "The last update failed."
		}
		if health.LastSuccess.IsZero() {
			summary += " This list has never downloaded successfully."
		} else {
			summary += " Its newest cached copy is " + insights.FormatDuration(input.Now.Sub(health.LastSuccess)) + " old."
		}
		facts := []insights.Fact{
			{Label: "Failed in a row", Value: insights.FormatCount(uint64(health.ConsecutiveFailures))},
			{Label: "Last success", Time: health.LastSuccess},
			{Label: "Last attempt", Time: health.LastAttempt},
		}
		if health.InBackoff(input.Now) {
			facts = append(facts, insights.Fact{Label: "Next retry", Time: health.RetryAfter})
		}
		if health.LastError != "" {
			facts = append(facts, insights.Fact{Label: "Last error", Value: health.LastError, Monospace: true})
		}
		findings = append(findings, insights.Finding{
			Kind:    KindUpdateFailing,
			Tone:    insights.ToneAttention,
			Title:   "Block list updates are failing",
			Subject: list.Name,
			Summary: summary,
			Facts:   facts,
			Method: fmt.Sprintf("Sable reports a list here once it has gone at least %d update intervals without a successful download. "+
				"Until it recovers, blocking keeps using the last copy that downloaded.", staleUpdateIntervals),
			Destination:      "/blocked?tab=lists",
			DestinationLabel: "Block Lists",
		})
	}
	return findings
}

func unreadableFindings(contribution Contribution) []insights.Finding {
	findings := make([]insights.Finding, 0)
	for _, list := range contribution.Lists {
		if list.Available || list.Skipped || list.Problem == "" {
			continue
		}
		findings = append(findings, insights.Finding{
			Kind:             KindListUnreadable,
			Tone:             insights.ToneNotice,
			Title:            "Block list left out of the comparison",
			Subject:          list.Name,
			Summary:          list.Problem + ", so its coverage could not be compared with the other lists.",
			Method:           "The comparison reads each list's cached copy, the same file blocking is compiled from.",
			Destination:      "/blocked?tab=lists",
			DestinationLabel: "Block Lists",
		})
	}
	return findings
}

func coverageFindings(contribution Contribution) []insights.Finding {
	if contribution.Analyzed < 2 {
		return nil
	}
	lists := make([]ListContribution, 0, len(contribution.Lists))
	for _, list := range contribution.Lists {
		if list.Available && list.Domains >= minimumComparedDomains {
			lists = append(lists, list)
		}
	}

	low := slices.Clone(lists)
	slices.SortFunc(low, func(left, right ListContribution) int {
		if order := cmp.Compare(left.UniqueShare(), right.UniqueShare()); order != 0 {
			return order
		}
		return cmp.Compare(right.Domains, left.Domains)
	})
	findings := make([]insights.Finding, 0)
	for _, list := range low {
		if len(findings) == maximumLowUnique || list.UniqueShare() >= lowUniqueShare {
			break
		}
		covered := insights.FormatShare(uint64(list.Covered), uint64(list.Domains))
		summary := covered + " of this list's domains are also covered by other enabled lists."
		if list.LargestOverlap.Domains == list.Covered {
			summary = covered + " of this list's domains are also covered by " + list.LargestOverlap.Name + "."
		}
		findings = append(findings, insights.Finding{
			Kind:             KindLowUnique,
			Tone:             insights.ToneNotice,
			Title:            "Little unique coverage",
			Subject:          list.Name,
			Summary:          summary,
			Facts:            coverageFacts(list),
			Method:           coverageMethod,
			Destination:      "/blocked?tab=lists",
			DestinationLabel: "Block Lists",
		})
	}

	best := ListContribution{}
	for _, list := range lists {
		if list.Unique > best.Unique {
			best = list
		}
	}
	if best.Unique >= meaningfulUniqueDomains && best.UniqueShare() >= meaningfulUniqueShare {
		findings = append(findings, insights.Finding{
			Kind:    KindUniqueCoverage,
			Tone:    insights.TonePositive,
			Title:   "Meaningful unique coverage",
			Subject: best.Name,
			Summary: fmt.Sprintf("%s of this list's domains (%s) are not covered by any other enabled list.",
				insights.FormatCount(uint64(best.Unique)), insights.FormatShare(uint64(best.Unique), uint64(best.Domains))),
			Facts:            coverageFacts(best),
			Method:           coverageMethod,
			Destination:      "/blocked?tab=lists",
			DestinationLabel: "Block Lists",
		})
	}
	return findings
}

const coverageMethod = "Sable reads every enabled list's cached copy with the same parser and normalization the blocking policy uses. " +
	"A domain counts as covered by another list when that list contains the same name or one of its parent domains, " +
	"because a blocked domain also blocks its subdomains. This describes list contents, not which list answered a query."

func coverageFacts(list ListContribution) []insights.Fact {
	facts := []insights.Fact{
		{Label: "Domains in list", Value: insights.FormatCount(uint64(list.Domains))},
		{Label: "Unique to this list", Value: insights.FormatCount(uint64(list.Unique))},
		{Label: "Also covered elsewhere", Value: insights.FormatCount(uint64(list.Covered))},
		{Label: "Unique share", Value: insights.FormatShare(uint64(list.Unique), uint64(list.Domains))},
	}
	if list.LargestOverlap.Name != "" {
		facts = append(facts, insights.Fact{
			Label: "Largest overlap",
			Value: fmt.Sprintf("%s (%s)", list.LargestOverlap.Name,
				insights.FormatShare(uint64(list.LargestOverlap.Domains), uint64(list.Domains))),
		})
	}
	return facts
}

func rankedCounts(values map[string]uint64, limit int) []insights.Count {
	counts := make([]insights.Count, 0, len(values))
	for name, hits := range values {
		counts = append(counts, insights.Count{Name: name, Hits: hits})
	}
	slices.SortFunc(counts, func(left, right insights.Count) int {
		if order := cmp.Compare(right.Hits, left.Hits); order != 0 {
			return order
		}
		return cmp.Compare(left.Name, right.Name)
	})
	return counts[:min(len(counts), limit)]
}
