package blocking

import (
	"cmp"
	"context"
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
	maximumPastBlocks      = 3
	maximumLowUnique       = 2
	maximumFindings        = 6
	maximumPastClients     = 10
)

// Limits are how long a problem has to last before it is worth reporting. The
// console sets them from each kind of finding's settings, and a limit left at
// zero takes its default.
type Limits struct {
	// MissedUpdates is how many update intervals a list must go without a
	// successful download before its failing updates are worth mentioning.
	// A single failed attempt is already visible on the Blocking page and
	// usually recovers on retry.
	MissedUpdates int
}

// DefaultLimits are the limits Insights uses unless an operator sets others.
func DefaultLimits() Limits { return Limits{MissedUpdates: 2} }

// withDefaults gives every limit left at zero its default.
func (limits Limits) withDefaults() Limits {
	if limits.MissedUpdates == 0 {
		limits.MissedUpdates = DefaultLimits().MissedUpdates
	}
	return limits
}

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
	// Queries holds blocked query counts per list when the operator may read
	// query history. Nil leaves query counts out of the list findings.
	Queries *SourceQueries
	// Limits are how long a problem must last to be reported. Zero ones take
	// their defaults.
	Limits Limits
	// Off lists the kinds of finding an operator turned off. They are not
	// looked for, so they never crowd out the findings that are on.
	Off map[string]bool
}

// SourceQueries is how many blocked queries each list accounted for in the
// window, counted from Since when attribution began partway through it.
type SourceQueries struct {
	Lists map[string]querylog.SourceActivity
	Since time.Time
}

// Findings turns the inputs into a short list of evidence-backed findings,
// most important first. Every sentence states what the data shows and nothing
// it cannot: list findings describe overlap, never advise removing a list, and
// a past block is reported only when a name was blocked and is now explicitly
// allowed.
func Findings(input FindingsInput) []insights.Finding {
	input.Limits = input.Limits.withDefaults()
	findings := make([]insights.Finding, 0, maximumFindings)
	if !input.Off[KindPastBlock] {
		findings = append(findings, pastBlockFindings(input.PastBlocks)...)
	}
	if !input.Off[KindUpdateFailing] {
		findings = append(findings, updateFindings(input)...)
	}
	if input.Contribution != nil {
		if !input.Off[KindListUnreadable] {
			findings = append(findings, unreadableFindings(*input.Contribution)...)
		}
		findings = append(findings, coverageFindings(*input.Contribution, input.Queries, input.Off)...)
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
			Kind:    KindPastBlock,
			Tone:    insights.ToneAttention,
			Title:   "Possible past blocking issue",
			Subject: insights.Subject{Label: evidence.Name, Monospace: true, Domain: evidence.Name},
			Headline: fmt.Sprintf("%s was blocked %s %s before you allowed it", evidence.Name,
				insights.FormatCount(evidence.Blocked), insights.Plural(evidence.Blocked, "time", "times")),
			Summary: fmt.Sprintf("Blocked %s %s during the selected period and %s.",
				insights.FormatCount(evidence.Blocked), insights.Plural(evidence.Blocked, "time", "times"), allowedBy),
			Reasons: pastBlockReasons(block),
			Facts:   facts,
			Clients: clients,
			Explanations: []string{
				"Someone ran into this block and allowed the domain to fix it",
				"A block list included a domain something on this network needs",
			},
			Method: "Sable compares the allowed domains with the blocked queries it retained for the selected period. " +
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
		missed := input.Limits.MissedUpdates
		stale := health.LastSuccess.IsZero() || input.Now.Sub(health.LastSuccess) >= time.Duration(missed)*interval
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
			Kind:     KindUpdateFailing,
			Tone:     insights.ToneAttention,
			Title:    "Block list updates are failing",
			Subject:  insights.Subject{Label: list.Name, BlockList: list.Name},
			Headline: list.Name + " stopped updating",
			Summary:  summary,
			Reasons:  updateReasons(health, input.Now, interval, missed),
			Facts:    facts,
			Explanations: []string{
				"The list's server is down or has moved",
				"Something between Sable and the internet is stopping the download",
			},
			Method: fmt.Sprintf("Sable reports a list once it has gone at least %d %s without a successful download. "+
				"Until it recovers, blocking keeps using the last copy that downloaded.", missed, insights.Plural(missed, "update interval", "update intervals")),
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
			Subject:          insights.Subject{Label: list.Name, BlockList: list.Name},
			Summary:          list.Problem + ", so its coverage could not be compared with the other lists.",
			Reasons:          insights.Reasons(list.Problem, "Its domains are left out of every other list's comparison until it can be read"),
			Explanations:     []string{"The list has not finished its first download", "Its cached file was removed or damaged"},
			Method:           "The comparison reads each list's cached copy, the same file blocking is compiled from.",
			Destination:      "/blocked?tab=lists",
			DestinationLabel: "Block Lists",
		})
	}
	return findings
}

func coverageFindings(contribution Contribution, queries *SourceQueries, off map[string]bool) []insights.Finding {
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
		if off[KindLowUnique] || len(findings) == maximumLowUnique || list.UniqueShare() >= lowUniqueShare {
			break
		}
		covered := insights.FormatShare(uint64(list.Covered), uint64(list.Domains))
		summary := covered + " of this list's domains are also covered by other enabled lists."
		if list.LargestOverlap.Domains == list.Covered {
			summary = covered + " of this list's domains are also covered by " + list.LargestOverlap.Name + "."
		}
		// Only a count over the whole window can support a statement about
		// the whole period.
		if queries != nil && queries.Since.IsZero() && queries.Lists[list.Name].Sole == 0 {
			summary += " No blocked query in this period depended on it alone."
		}
		findings = append(findings, insights.Finding{
			Kind:             KindLowUnique,
			Tone:             insights.ToneNotice,
			Title:            "Little unique coverage",
			Subject:          insights.Subject{Label: list.Name, BlockList: list.Name},
			Summary:          summary,
			Reasons:          coverageReasons(list, queries),
			Facts:            coverageFacts(list, queries),
			Explanations:     []string{"The other lists already carry most of what this one blocks", "Several lists draw on the same upstream sources"},
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
	if !off[KindUniqueCoverage] && best.Unique >= meaningfulUniqueDomains && best.UniqueShare() >= meaningfulUniqueShare {
		findings = append(findings, insights.Finding{
			Kind:    KindUniqueCoverage,
			Tone:    insights.TonePositive,
			Title:   "Meaningful unique coverage",
			Subject: insights.Subject{Label: best.Name, BlockList: best.Name},
			Summary: fmt.Sprintf("%s of this list's domains (%s) are not covered by any other enabled list.",
				insights.FormatCount(uint64(best.Unique)), insights.FormatShare(uint64(best.Unique), uint64(best.Domains))),
			Reasons:          coverageReasons(best, queries),
			Facts:            coverageFacts(best, queries),
			Explanations:     []string{"This list blocks domains the other lists do not know about"},
			Method:           coverageMethod,
			Destination:      "/blocked?tab=lists",
			DestinationLabel: "Block Lists",
		})
	}
	return findings
}

const coverageMethod = "Sable reads every enabled list's cached copy with the same parser the blocking policy uses. " +
	"A domain counts as covered by another list when that list contains the same name or one of its parent domains, " +
	"because a blocked domain also blocks its subdomains."

func coverageFacts(list ListContribution, queries *SourceQueries) []insights.Fact {
	facts := []insights.Fact{
		{Label: "Domains in list", Value: insights.FormatCount(uint64(list.Domains))},
		{Label: "Unique to this list", Value: insights.FormatCount(uint64(list.Unique))},
		{Label: "Also covered elsewhere", Value: insights.FormatCount(uint64(list.Covered))},
		{Label: "Unique share", Value: insights.FormatShare(uint64(list.Unique), uint64(list.Domains))},
	}
	if queries != nil {
		activity := queries.Lists[list.Name]
		facts = append(facts,
			insights.Fact{Label: "Blocked queries it matched", Value: insights.FormatCount(activity.Blocked)},
			insights.Fact{Label: "Blocked by this list alone", Value: insights.FormatCount(activity.Sole)},
		)
		if !queries.Since.IsZero() {
			facts = append(facts, insights.Fact{Label: "Queries counted since", Time: queries.Since})
		}
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

func pastBlockReasons(block PastBlock) []insights.Reason {
	evidence := block.Evidence
	reasons := []insights.Reason{
		{Text: fmt.Sprintf("Blocked %s %s during the selected period", insights.FormatCount(evidence.Blocked), insights.Plural(evidence.Blocked, "time", "times"))},
		{Text: "Now allowed by", Code: block.Rule},
	}
	if evidence.ClientCount > 0 {
		reasons = append(reasons, insights.Reason{Text: fmt.Sprintf("Affected %s %s", insights.FormatCount(evidence.ClientCount), insights.Plural(evidence.ClientCount, "client", "clients"))})
	}
	return reasons
}

func updateReasons(health blockcompiler.SourceHealth, now time.Time, interval time.Duration, missed int) []insights.Reason {
	reasons := insights.Reasons(fmt.Sprintf("%s %s failed in a row", insights.FormatCount(uint64(health.ConsecutiveFailures)),
		insights.Plural(health.ConsecutiveFailures, "update", "updates")))
	if health.LastSuccess.IsZero() {
		reasons = append(reasons, insights.Reasons("Never downloaded successfully")...)
	} else {
		reasons = append(reasons, insights.Reasons("Newest cached copy is "+insights.FormatDuration(now.Sub(health.LastSuccess))+" old",
			fmt.Sprintf("That is more than %d %s of %s", missed, insights.Plural(missed, "update interval", "update intervals"), insights.FormatDuration(interval)))...)
	}
	return reasons
}

func coverageReasons(list ListContribution, queries *SourceQueries) []insights.Reason {
	reasons := insights.Reasons(
		fmt.Sprintf("%s of its %s domains are in no other enabled list",
			insights.FormatCount(uint64(list.Unique)), insights.FormatCount(uint64(list.Domains))),
		insights.FormatShare(uint64(list.Covered), uint64(list.Domains))+" are also covered by other lists",
	)
	if list.LargestOverlap.Name != "" {
		reasons = append(reasons, insights.Reason{Text: fmt.Sprintf("Largest overlap is %s, at %s", list.LargestOverlap.Name,
			insights.FormatShare(uint64(list.LargestOverlap.Domains), uint64(list.Domains)))})
	}
	if queries != nil && queries.Since.IsZero() {
		sole := queries.Lists[list.Name].Sole
		reasons = append(reasons, insights.Reason{Text: fmt.Sprintf("Alone blocked %s %s during the selected period",
			insights.FormatCount(sole), insights.Plural(sole, "query", "queries"))})
	}
	return reasons
}

// Sources is what the blocking analyzer reads. The console implements it over
// its caches and stores, so the analysis never touches HTTP handling or the
// DNS request path. A method returns nil when the operator may not read what
// it needs, and the findings that depend on it are skipped.
type Sources interface {
	Contribution(context.Context) (*Contribution, error)
	ListHealth() ([]ListHealth, time.Duration)
	SourceQueries(context.Context, insights.Window) (*SourceQueries, error)
	PastBlocks(context.Context, insights.Window) ([]PastBlock, error)
}

// Analyzer reports what is worth knowing about blocking.
type Analyzer struct {
	Sources Sources
	// Limits are how long a problem must last to be reported. Zero ones take
	// their defaults.
	Limits Limits
	// Off lists the kinds of finding an operator turned off, which are not
	// looked for.
	Off map[string]bool
}

// Analyze gathers the blocking evidence for a window and turns it into findings.
func (analyzer Analyzer) Analyze(ctx context.Context, window insights.Window) ([]insights.Finding, error) {
	input := FindingsInput{Now: window.End, Limits: analyzer.Limits, Off: analyzer.Off}
	contribution, err := analyzer.Sources.Contribution(ctx)
	if err != nil {
		return nil, err
	}
	input.Contribution = contribution
	input.Health, input.UpdateInterval = analyzer.Sources.ListHealth()
	if input.Queries, err = analyzer.Sources.SourceQueries(ctx, window); err != nil {
		return nil, err
	}
	// Past blocks cost a search of the query history, so they are read only
	// when they are looked for.
	if !analyzer.Off[KindPastBlock] {
		if input.PastBlocks, err = analyzer.Sources.PastBlocks(ctx, window); err != nil {
			return nil, err
		}
	}
	return Findings(input), nil
}
