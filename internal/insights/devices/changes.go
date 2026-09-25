package devices

import (
	"cmp"
	"context"
	"fmt"
	"slices"
	"time"

	"github.com/drudge/sable/internal/insights"
	"github.com/drudge/sable/internal/querylog"
)

// Finding kinds produced by this package.
const (
	KindNewDevice       = "devices.new-device"
	KindNewDestinations = "devices.new-destinations"
	KindTrafficSpike    = "devices.traffic-spike"
	KindWentQuiet       = "devices.went-quiet"
)

// Thresholds for change findings. Each one is conservative on purpose: a
// quiet page is better than a page that cries wolf about normal variation.
const (
	// trackingGrace keeps devices that were already present when first-seen
	// tracking began from being reported as new.
	trackingGrace = time.Hour
	// minimumNewDomains recognizes a device that started talking to a
	// meaningfully different set of places.
	minimumNewDomains = 20
	// baselineDays matches the store's comparison window.
	baselineDays = 7
	// minimumDailyBaseline ignores devices too quiet for a ratio to mean much.
	minimumDailyBaseline = 50
	// spikeFactor and minimumSpikeQueries define a traffic spike.
	spikeFactor         = 3.0
	minimumSpikeQueries = 500
	maximumNewDevices   = 3
	maximumDestinations = 2
	maximumSpikes       = 2
	maximumQuiet        = 2
	maximumListedNames  = 10
)

// ChangesInput is what the change findings are derived from. SeenSince is when
// first-seen tracking began, and NewDomains lists a device's first-time names
// for the devices whose new destinations are reported.
type ChangesInput struct {
	Devices     []Device
	WindowStart time.Time
	Now         time.Time
	SeenSince   time.Time
	NewDomains  func(Device) []insights.DomainEvidence
	// DomainHistory lists every name a device has queried and whether that
	// list is complete; new apps are only claimed from a complete history.
	DomainHistory func(Device) ([]insights.DomainEvidence, bool)
	// Hourly counts a device's queries per hour, keyed by the hour's start,
	// over at least the last fifteen days.
	Hourly func(Device) map[time.Time]uint64
	// RecentDomains lists a device's first-time names from the last 24 hours.
	RecentDomains func(Device) []insights.DomainEvidence
	// Location is the time zone hours of the day are read in.
	Location *time.Location
	// RepeatedLookups are names only one client looked up many times in the
	// last day, with every lookup's time.
	RepeatedLookups []querylog.LookupTimes
}

// Changes reports what changed about devices, most important first. Every
// statement compares a device only with its own history, and a device that
// has no hardware identity is described as an address.
func Changes(input ChangesInput) []insights.Finding {
	findings := make([]insights.Finding, 0)
	findings = append(findings, quietFindings(input)...)
	findings = append(findings, spikeFindings(input)...)
	findings = append(findings, unusualHourFindings(input)...)
	findings = append(findings, checkInFindings(input)...)
	findings = append(findings, newDeviceFindings(input)...)
	// A device already reported for its new destinations needs no second
	// finding that counts the same domains another way.
	reported := make(map[string]bool)
	for _, group := range [][]insights.Finding{applianceFindings(input, reported), newAppFindings(input)} {
		for _, finding := range group {
			if reported[finding.Subject.Device] {
				continue
			}
			reported[finding.Subject.Device] = true
			findings = append(findings, finding)
		}
	}
	findings = append(findings, destinationFindings(input, reported)...)
	return findings
}

// trackedBefore reports whether first-seen tracking covered a moment, so a
// device's first sighting there really is its first.
func (input ChangesInput) trackedBefore(moment time.Time) bool {
	return !input.SeenSince.IsZero() && input.SeenSince.Add(trackingGrace).Before(moment)
}

func newDeviceFindings(input ChangesInput) []insights.Finding {
	candidates := make([]Device, 0)
	for _, device := range input.Devices {
		if device.Queries > 0 && !device.FirstSeen.Before(input.WindowStart) && input.trackedBefore(device.FirstSeen) {
			candidates = append(candidates, device)
		}
	}
	slices.SortFunc(candidates, func(left, right Device) int { return right.FirstSeen.Compare(left.FirstSeen) })
	findings := make([]insights.Finding, 0, min(len(candidates), maximumNewDevices))
	for _, device := range candidates[:min(len(candidates), maximumNewDevices)] {
		title, subject := "New device on the network", deviceSubject(device)
		if !device.Identified() {
			title = "New address on the network"
		}
		findings = append(findings, insights.Finding{
			Kind: KindNewDevice, Tone: insights.ToneNotice, Title: title,
			Subject:  subject,
			Headline: Label(device) + " joined the network",
			Summary: describeDevice(device) + fmt.Sprintf("First seen %s ago and has sent %s %s since.",
				insights.FormatDuration(input.Now.Sub(device.FirstSeen)), insights.FormatCount(device.Queries), insights.Plural(device.Queries, "query", "queries")),
			Reasons:      newDeviceReasons(device, input),
			Facts:        deviceFacts(device, true),
			Explanations: newDeviceExplanations(device),
			Method:       "Sable records when it first sees each client. This one first appeared inside the selected period, while Sable was already watching.",
		})
	}
	return findings
}

func newDeviceExplanations(device Device) []string {
	if !device.Identified() {
		return []string{
			"A known device came back at a new address",
			"Someone connected a new device or a guest joined",
		}
	}
	return []string{"Someone connected a new device", "A guest joined the network"}
}

func destinationFindings(input ChangesInput, skip map[string]bool) []insights.Finding {
	if !input.trackedBefore(input.WindowStart) {
		return nil
	}
	candidates := make([]Device, 0)
	for _, device := range input.Devices {
		if device.NewDomains >= minimumNewDomains && device.FirstSeen.Before(input.WindowStart) && !skip[device.Key] {
			candidates = append(candidates, device)
		}
	}
	slices.SortFunc(candidates, func(left, right Device) int { return cmp.Compare(right.NewDomains, left.NewDomains) })
	findings := make([]insights.Finding, 0, min(len(candidates), maximumDestinations))
	for _, device := range candidates[:min(len(candidates), maximumDestinations)] {
		finding := insights.Finding{
			Kind: KindNewDestinations, Tone: insights.ToneNotice, Title: "Talking to new places",
			Subject:  deviceSubject(device),
			Headline: fmt.Sprintf("%s queried %s new %s", Label(device), insights.FormatCount(device.NewDomains), insights.Plural(device.NewDomains, "domain", "domains")),
			Summary: fmt.Sprintf("Queried %s %s for the first time during the selected period.",
				insights.FormatCount(device.NewDomains), insights.Plural(device.NewDomains, "domain", "domains")),
			Reasons: insights.Reasons(
				fmt.Sprintf("%s %s queried for the first time during the selected period", insights.FormatCount(device.NewDomains), insights.Plural(device.NewDomains, "domain was", "domains were")),
				"Seen on the network for "+insights.FormatDuration(input.Now.Sub(device.FirstSeen))+", so these are new to it",
			),
			Facts:        append(deviceFacts(device, false), insights.Fact{Label: "First-time domains", Value: insights.FormatCount(device.NewDomains)}),
			Explanations: []string{"A software update or a newly installed app", "Someone started using a new service on this device"},
			Method: "Sable remembers every domain each client has queried and reports a " + noun(device) +
				" that queried at least 20 it had never queried before the selected period.",
		}
		if input.NewDomains != nil {
			finding.Domains = input.NewDomains(device)
			if len(finding.Domains) > maximumListedNames {
				finding.Domains = finding.Domains[:maximumListedNames]
			}
		}
		findings = append(findings, finding)
	}
	return findings
}

// baselineReady reports whether a device was around for the whole comparison
// week, so its average is a real average.
func (input ChangesInput) baselineReady(device Device) bool {
	start := input.Now.Add(-(baselineDays + 1) * 24 * time.Hour)
	return !device.FirstSeen.IsZero() && !device.FirstSeen.After(start) && input.trackedBefore(start) &&
		device.Baseline >= minimumDailyBaseline*baselineDays
}

func dailyAverage(device Device) float64 { return float64(device.Baseline) / baselineDays }

func spikeFindings(input ChangesInput) []insights.Finding {
	candidates := make([]Device, 0)
	for _, device := range input.Devices {
		if input.baselineReady(device) && device.Recent >= minimumSpikeQueries && float64(device.Recent) >= spikeFactor*dailyAverage(device) {
			candidates = append(candidates, device)
		}
	}
	slices.SortFunc(candidates, func(left, right Device) int {
		return cmp.Compare(float64(right.Recent)/dailyAverage(right), float64(left.Recent)/dailyAverage(left))
	})
	findings := make([]insights.Finding, 0, min(len(candidates), maximumSpikes))
	for _, device := range candidates[:min(len(candidates), maximumSpikes)] {
		ratio := float64(device.Recent) / dailyAverage(device)
		findings = append(findings, insights.Finding{
			Kind: KindTrafficSpike, Tone: insights.ToneAttention, Title: "Unusually busy",
			Subject:  deviceSubject(device),
			Headline: fmt.Sprintf("%s is %.0f× busier than usual", Label(device), ratio),
			Summary: fmt.Sprintf("Sent %s queries in the last 24 hours, %.1f× its daily average over the week before.",
				insights.FormatCount(device.Recent), ratio),
			Reasons: insights.Reasons(
				fmt.Sprintf("%s queries in the last 24 hours", insights.FormatCount(device.Recent)),
				fmt.Sprintf("%.1f× its daily average of %s over the week before", ratio, insights.FormatCount(uint64(dailyAverage(device)+0.5))),
				"Seen on the network for "+insights.FormatDuration(input.Now.Sub(device.FirstSeen))+", so its week is a real baseline",
			),
			Facts: append(deviceFacts(device, false),
				insights.Fact{Label: "Last 24 hours", Value: insights.FormatCount(device.Recent)},
				insights.Fact{Label: "Daily average before", Value: insights.FormatCount(uint64(dailyAverage(device) + 0.5))},
			),
			Explanations: []string{
				"An app or firmware stuck retrying a lookup",
				"Software trying to reach a service that is not answering",
				"Heavier use than usual, such as streaming or a large backup",
			},
			Method: "Sable compares each " + noun(device) + "'s last 24 hours with its own average over the seven days before, " +
				"and reports only devices that were active the whole week and at least tripled their usual volume.",
			Chart: dayChart(input, device),
		})
	}
	return findings
}

func quietFindings(input ChangesInput) []insights.Finding {
	candidates := make([]Device, 0)
	for _, device := range input.Devices {
		if device.Recent == 0 && input.baselineReady(device) {
			candidates = append(candidates, device)
		}
	}
	slices.SortFunc(candidates, func(left, right Device) int { return cmp.Compare(right.Baseline, left.Baseline) })
	findings := make([]insights.Finding, 0, min(len(candidates), maximumQuiet))
	for _, device := range candidates[:min(len(candidates), maximumQuiet)] {
		findings = append(findings, insights.Finding{
			Kind: KindWentQuiet, Tone: insights.ToneAttention, Title: "Went quiet",
			Subject:  deviceSubject(device),
			Headline: Label(device) + " went quiet",
			Summary: fmt.Sprintf("No queries in the last 24 hours. It averaged %s a day over the week before.",
				insights.FormatCount(uint64(dailyAverage(device)+0.5))),
			Reasons: quietReasons(device, input.Now),
			Facts: append(deviceFacts(device, false),
				insights.Fact{Label: "Daily average before", Value: insights.FormatCount(uint64(dailyAverage(device) + 0.5))},
			),
			Explanations: []string{"Switched off or unplugged", "Moved to another network", "Set to use a different DNS server"},
			Method:       "Sable reports a " + noun(device) + " that was steadily active all of the previous week and has sent nothing for a full day.",
			Chart:        dayChart(input, device),
		})
	}
	return findings
}

// dayChart pictures a device's last 24 hours beside each day of the week
// before. The last day and the average are the finding's own counts; the days
// before are read from the device's hourly activity.
func dayChart(input ChangesInput, device Device) *insights.Chart {
	if input.Hourly == nil {
		return nil
	}
	hourly := input.Hourly(device)
	if hourly == nil {
		return nil
	}
	day := 24 * time.Hour
	start := input.Now.Add(-(baselineDays + 1) * day)
	before := make([]uint64, baselineDays)
	for hour, hits := range hourly {
		if !hour.Before(start) && hour.Before(input.Now.Add(-day)) {
			before[hour.Sub(start)/day] += hits
		}
	}
	return &insights.Chart{Days: &insights.DayChart{Before: before, Average: dailyAverage(device), Last: device.Recent}}
}

func noun(device Device) string {
	if device.Identified() {
		return "device"
	}
	return "address"
}

// Label is how a device is named in a sentence: its name, or its hardware or
// network address when it has none.
func Label(device Device) string {
	switch {
	case device.Name != "":
		return device.Name
	case device.MAC != "":
		return device.MAC
	case len(device.Addresses) > 0:
		return device.Addresses[0].Address
	default:
		return device.Key
	}
}

func deviceFacts(device Device, includeFirstSeen bool) []insights.Fact {
	facts := make([]insights.Fact, 0, 8)
	if device.Guess.Type != "" {
		facts = append(facts, insights.Fact{Label: "Looks like", Value: GuessText(device.Guess)})
	}
	if device.Vendor != "" {
		facts = append(facts, insights.Fact{Label: "Maker", Value: device.Vendor})
	}
	if device.MAC != "" {
		value := device.MAC
		if device.PrivateMAC {
			value += " (private address)"
		}
		facts = append(facts, insights.Fact{Label: "Hardware address", Value: value, Monospace: true})
	}
	for _, address := range device.Addresses {
		facts = append(facts, insights.Fact{Label: "Address", Value: address.Address, Monospace: true})
	}
	if includeFirstSeen {
		facts = append(facts, insights.Fact{Label: "First seen", Time: device.FirstSeen})
	}
	facts = append(facts, insights.Fact{Label: "Queries in period", Value: insights.FormatCount(device.Queries)})
	return facts
}

// deviceSubject identifies a device durably by its identity key, so anything
// later attached to a finding about it follows the device rather than its name.
func deviceSubject(device Device) insights.Subject {
	return insights.Subject{Label: Label(device), LabelSource: device.NameSource, Monospace: device.Name == "", Device: device.Key}
}

func newDeviceReasons(device Device, input ChangesInput) []insights.Reason {
	reasons := insights.Reasons(
		"First seen "+insights.FormatDuration(input.Now.Sub(device.FirstSeen))+" ago",
		"Sable has been watching for "+insights.FormatDuration(input.Now.Sub(input.SeenSince))+", so it was not here before",
	)
	switch {
	case device.Named:
		reasons = append(reasons, insights.Reason{Text: "Identified by the name you gave it"})
	case device.MAC != "":
		reasons = append(reasons, insights.Reason{Text: "Identified by hardware address", Code: device.MAC})
	default:
		reasons = append(reasons, insights.Reason{Text: "Not tied to hardware yet, so it may be a known device at a new address"})
	}
	return reasons
}

func quietReasons(device Device, now time.Time) []insights.Reason {
	reasons := insights.Reasons(
		"No queries in the last 24 hours",
		fmt.Sprintf("Averaged %s a day over the week before", insights.FormatCount(uint64(dailyAverage(device)+0.5))),
	)
	if !device.LastSeen.IsZero() {
		reasons = append(reasons, insights.Reason{Text: "Last query " + insights.FormatDuration(now.Sub(device.LastSeen)) + " ago"})
	}
	return reasons
}

// Report is the devices seen in a window, with when first-seen tracking began.
type Report struct {
	Devices   []Device
	SeenSince time.Time
	Window    insights.Window
}

// Sources is what the device analyzer reads. The console implements it over
// its caches and the query log store.
type Sources interface {
	Devices(context.Context, insights.Window) (Report, error)
	NewDomains(context.Context, Device, insights.Window) ([]insights.DomainEvidence, error)
	// RepeatedLookups lists names only one client looked up many times since
	// a moment, with every lookup's time.
	RepeatedLookups(context.Context, time.Time) ([]querylog.LookupTimes, error)
	// HourlyActivity counts each client address's queries per hour since a
	// moment, keyed by the hour's start.
	HourlyActivity(context.Context, time.Time) (map[string]map[time.Time]uint64, error)
	// DomainHistory lists every name a device has queried, with whether the
	// list is complete.
	DomainHistory(context.Context, Device) ([]insights.DomainEvidence, bool, error)
}

// Analyzer reports what changed about the network's devices.
type Analyzer struct {
	Sources Sources
}

// Analyze compares each device in the window with its own history.
func (analyzer Analyzer) Analyze(ctx context.Context, window insights.Window) ([]insights.Finding, error) {
	report, err := analyzer.Sources.Devices(ctx, window)
	if err != nil {
		return nil, err
	}
	// Routines need two weeks before the last day, whatever window is shown.
	hourly, hourlyErr := analyzer.Sources.HourlyActivity(ctx, report.Window.End.Add(-(routineDays+1)*24*time.Hour))
	// A failed read only leaves check-ins out.
	repeated, _ := analyzer.Sources.RepeatedLookups(ctx, report.Window.End.Add(-24*time.Hour))
	return Changes(ChangesInput{
		Devices: report.Devices, WindowStart: report.Window.Start, Now: report.Window.End, SeenSince: report.SeenSince,
		NewDomains: func(device Device) []insights.DomainEvidence {
			domains, err := analyzer.Sources.NewDomains(ctx, device, report.Window)
			if err != nil {
				return nil
			}
			return domains
		},
		DomainHistory: func(device Device) ([]insights.DomainEvidence, bool) {
			history, complete, err := analyzer.Sources.DomainHistory(ctx, device)
			return history, complete && err == nil
		},
		Hourly: func(device Device) map[time.Time]uint64 {
			if hourlyErr != nil {
				return nil
			}
			merged := make(map[time.Time]uint64)
			for _, address := range device.Addresses {
				for hour, hits := range hourly[address.Address] {
					merged[hour] += hits
				}
			}
			return merged
		},
		RepeatedLookups: repeated,
		RecentDomains: func(device Device) []insights.DomainEvidence {
			domains, err := analyzer.Sources.NewDomains(ctx, device, insights.Window{Start: report.Window.End.Add(-24 * time.Hour), End: report.Window.End})
			if err != nil {
				return nil
			}
			return domains
		},
	}), nil
}
