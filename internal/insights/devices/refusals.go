package devices

import (
	"cmp"
	"context"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/drudge/sable/internal/insights"
	"github.com/drudge/sable/internal/querylog"
)

// KindLookupsRefused reports a local device whose lookups the recursion policy
// keeps refusing.
const KindLookupsRefused = "devices.lookups-refused"

// Fixed rules for refused lookups.
const (
	// RefusalWindow is how far back refused lookups are counted.
	RefusalWindow = 24 * time.Hour
	// minimumRefusals and minimumRefusedHours keep a one-off out. A device
	// that checks in a few times an hour still passes both within a day.
	minimumRefusals     = 10
	minimumRefusedHours = 2
	maximumRefusedNames = 5
)

// refusalMethod is the rule behind every refused-lookup finding.
const refusalMethod = "Sable counts the lookups it refused in the last 24 hours because Recursion Access didn't cover the address. " +
	"It only reports devices that look local: ones Sable has seen on the network by hardware address, or with an address " +
	"on a network Sable is attached to. Lookups from elsewhere on the internet are never reported."

// RefusalInput is what refused-lookup findings are derived from.
type RefusalInput struct {
	// Refused is the lookups the recursion policy refused in the window.
	Refused []querylog.RefusedLookup
	// Devices name the clients and tie their addresses to hardware.
	Devices []Device
	// Allowed reports whether the recursion policy in force now admits an
	// address, so a finding clears as soon as the policy is fixed.
	Allowed func(string) bool
	// Attached reports whether an address is on a network Sable is attached
	// to.
	Attached func(string) bool
	// Now is the end of the window.
	Now time.Time
}

// refusedDevice is what was refused from one device.
type refusedDevice struct {
	device   Device
	known    bool
	count    uint64
	hours    map[time.Time]bool
	last     time.Time
	names    map[string]uint64
	clients  map[string]uint64
	attached bool
}

// RefusalFindings reports each local device refused at least ten times across
// at least two hours of the window, whose address the policy still refuses.
func RefusalFindings(input RefusalInput) []insights.Finding {
	byAddress := make(map[string]Device)
	for _, device := range input.Devices {
		for _, address := range device.Addresses {
			byAddress[addressKey(address.Address)] = device
		}
	}
	groups := make(map[string]*refusedDevice)
	start := input.Now.Add(-RefusalWindow)
	for _, lookup := range input.Refused {
		client := addressKey(lookup.Client)
		if lookup.At.Before(start) || lookup.At.After(input.Now) || client == "" || input.Allowed(client) {
			continue
		}
		device, known := byAddress[client]
		key := device.Key
		if !known {
			key = "ip:" + client
		}
		group := groups[key]
		if group == nil {
			if !known {
				device = Device{Key: key, Addresses: []Address{{Address: client}}}
			}
			group = &refusedDevice{device: device, known: known, hours: make(map[time.Time]bool),
				names: make(map[string]uint64), clients: make(map[string]uint64)}
			groups[key] = group
		}
		group.count++
		group.hours[lookup.At.UTC().Truncate(time.Hour)] = true
		group.last = later(group.last, lookup.At)
		group.names[strings.TrimSuffix(strings.ToLower(lookup.Name), ".")]++
		group.clients[client]++
		group.attached = group.attached || input.Attached(client)
	}
	candidates := make([]*refusedDevice, 0, len(groups))
	for _, group := range groups {
		// A hardware address read out of an IPv6 address says nothing about
		// where the device is, so only one Sable saw on the network counts.
		seen := group.device.MAC != "" && !group.device.MACFromAddress
		if group.count >= minimumRefusals && len(group.hours) >= minimumRefusedHours && (seen || group.attached) {
			candidates = append(candidates, group)
		}
	}
	slices.SortFunc(candidates, func(left, right *refusedDevice) int {
		return cmp.Or(cmp.Compare(right.count, left.count), strings.Compare(left.device.Key, right.device.Key))
	})
	findings := make([]insights.Finding, 0, len(candidates))
	for _, group := range candidates {
		findings = append(findings, refusalFinding(group, input.Now))
	}
	return findings
}

func refusalFinding(group *refusedDevice, now time.Time) insights.Finding {
	subject := deviceSubject(group.device)
	if !group.known {
		subject = insights.Subject{Label: Label(group.device), Monospace: true, Device: group.device.Key}
	}
	clients := rankedCounts(group.clients)
	reasons := make([]insights.Reason, 0, 3)
	if group.attached {
		reasons = append(reasons, insights.Reason{Text: "Its address is on a network Sable is attached to"})
	}
	if group.device.MAC != "" && !group.device.MACFromAddress {
		reasons = append(reasons, insights.Reason{Text: "Sable has seen it on the network by hardware address", Code: group.device.MAC})
	}
	reasons = append(reasons,
		insights.Reason{Text: "Recursion Access doesn't cover its address", Code: clients[0].Name},
		insights.Reason{Text: fmt.Sprintf("Refused in %d different hours of the last day", len(group.hours))},
	)
	facts := []insights.Fact{
		{Label: "Refused lookups", Value: insights.FormatCount(group.count)},
		{Label: "Last refused", Time: group.last},
	}
	if group.device.MAC != "" {
		facts = append(facts, insights.Fact{Label: "Hardware address", Value: group.device.MAC, Monospace: true})
	}
	for _, client := range clients {
		facts = append(facts, insights.Fact{Label: "Address", Value: client.Name, Monospace: true})
	}
	names := rankedCounts(group.names)
	domains := make([]insights.DomainEvidence, 0, min(len(names), maximumRefusedNames))
	for _, name := range names[:min(len(names), maximumRefusedNames)] {
		domains = append(domains, insights.DomainEvidence{Name: name.Name, Query: &insights.QueryFilter{Name: name.Name, ClientIP: clients[0].Name}})
	}
	return insights.Finding{
		ID: insights.NewID(KindLookupsRefused, subject), Kind: KindLookupsRefused, Tone: insights.ToneAttention,
		Title: "Lookups refused", Subject: subject,
		Headline: subject.Label + "'s lookups are refused",
		Summary: fmt.Sprintf("Sable refused %s %s from this device in the last 24 hours because Recursion Access doesn't cover its address.",
			insights.FormatCount(group.count), insights.Plural(group.count, "lookup", "lookups")),
		Reasons: reasons, Facts: facts, Clients: clients, Domains: domains, DomainsTitle: "Refused names",
		Explanations: []string{
			"A VLAN Sable isn't attached to",
			"A Listed clients only policy that leaves the device out",
		},
		Method:      refusalMethod,
		Query:       &insights.QueryFilter{ClientIP: clients[0].Name},
		Destination: "/settings?tab=recursion", DestinationLabel: "Recursion Settings",
		ObservedAt: now,
	}
}

// rankedCounts lists counts busiest first, then by name.
func rankedCounts(counts map[string]uint64) []insights.Count {
	ranked := make([]insights.Count, 0, len(counts))
	for name, hits := range counts {
		ranked = append(ranked, insights.Count{Name: name, Hits: hits})
	}
	slices.SortFunc(ranked, func(left, right insights.Count) int {
		return cmp.Or(cmp.Compare(right.Hits, left.Hits), strings.Compare(left.Name, right.Name))
	})
	return ranked
}

// RefusalSources is what the refused-lookup analyzer reads. The console
// implements it over the query log store, the device report, the recursion
// policy in force, and the networks Sable is attached to.
type RefusalSources interface {
	Refusals(context.Context, time.Time) (RefusalInput, error)
}

// RefusalAnalyzer reports local devices the recursion policy keeps refusing.
// It reads the query log, never the DNS path.
type RefusalAnalyzer struct {
	Sources RefusalSources
	Off     map[string]bool
}

// Analyze counts the last day's refused lookups up to the window's end.
func (analyzer RefusalAnalyzer) Analyze(ctx context.Context, window insights.Window) ([]insights.Finding, error) {
	if analyzer.Off[KindLookupsRefused] {
		return nil, nil
	}
	input, err := analyzer.Sources.Refusals(ctx, window.End)
	if err != nil {
		return nil, err
	}
	return RefusalFindings(input), nil
}
