package devices

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/drudge/sable/internal/insights"
	"github.com/drudge/sable/internal/querylog"
)

// refusedEvery adds a refused lookup from client every step, count times,
// ending at end.
func refusedEvery(lookups []querylog.RefusedLookup, client, name string, end time.Time, step time.Duration, count int) []querylog.RefusedLookup {
	for index := range count {
		lookups = append(lookups, querylog.RefusedLookup{Client: client, Name: name, At: end.Add(-time.Duration(index) * step)})
	}
	return lookups
}

func TestRefusalFindingsReportOnlyLocalDevicesStillRefused(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 9, 30, 15, 0, 0, 0, time.UTC)
	tablet := Device{Key: "mac:aa:00:00:00:00:01", Name: "Remarkable 2", MAC: "aa:00:00:00:00:01",
		Addresses: []Address{{Address: "2001:db8:1234:1600::a"}, {Address: "2001:db8:1234:1600::b"}}}
	derived := Device{Key: "mac:02:00:00:00:00:02", MAC: "02:00:00:00:00:02", MACFromAddress: true,
		Addresses: []Address{{Address: "2001:db8:ffff::200:ff:fe00:2"}}}
	fixed := Device{Key: "mac:aa:00:00:00:00:03", Name: "Dock", MAC: "aa:00:00:00:00:03", Addresses: []Address{{Address: "2001:db8:1234:1700::3"}}}
	var refused []querylog.RefusedLookup
	// The tablet rotates privacy addresses, on a VLAN Sable isn't attached to.
	refused = refusedEvery(refused, "2001:db8:1234:1600::a", "sync.example.", now.Add(-time.Minute), 20*time.Minute, 8)
	refused = refusedEvery(refused, "2001:db8:1234:1600::b", "ping.example.", now.Add(-6*time.Hour), 20*time.Minute, 6)
	// An unknown device on the network Sable is attached to.
	refused = refusedEvery(refused, "2001:db8:1234:1500::77", "cloud.example.", now.Add(-time.Minute), 30*time.Minute, 12)
	// Scanners from the internet, one of them with an EUI-64 address.
	refused = refusedEvery(refused, "198.51.100.9", "example.com.", now.Add(-time.Minute), 5*time.Minute, 200)
	refused = refusedEvery(refused, "2001:db8:ffff::200:ff:fe00:2", "example.com.", now.Add(-time.Minute), 30*time.Minute, 20)
	// Fixed since: the policy covers the dock's network now.
	refused = refusedEvery(refused, "2001:db8:1234:1700::3", "support.example.", now.Add(-time.Minute), 30*time.Minute, 20)
	// A burst within one hour.
	refused = refusedEvery(refused, "2001:db8:1234:1500::88", "burst.example.", now.Add(-time.Minute), time.Second, 50)
	// Outside the window.
	refused = refusedEvery(refused, "2001:db8:1234:1500::99", "old.example.", now.Add(-30*time.Hour), 30*time.Minute, 12)

	findings := RefusalFindings(RefusalInput{
		Refused: refused, Devices: []Device{tablet, derived, fixed}, Now: now,
		Allowed:  func(address string) bool { return strings.HasPrefix(address, "2001:db8:1234:1700:") },
		Attached: func(address string) bool { return strings.HasPrefix(address, "2001:db8:1234:1500:") },
	})
	if len(findings) != 2 {
		t.Fatalf("findings = %d, want the tablet and the unknown device: %+v", len(findings), findings)
	}
	first, second := findings[0], findings[1]
	if first.Subject.Device != "mac:aa:00:00:00:00:01" || first.Subject.Label != "Remarkable 2" || first.Kind != KindLookupsRefused ||
		first.Tone != insights.ToneAttention || len(first.Clients) != 2 || first.Destination != "/settings?tab=recursion" {
		t.Fatalf("tablet finding = %+v", first)
	}
	if first.Facts[0].Value != "14" || first.Summary != "Sable refused 14 lookups from this device in the last 24 hours because Recursion Access doesn't cover its address." {
		t.Fatalf("tablet counted %q: %s", first.Facts[0].Value, first.Summary)
	}
	if first.Reasons[0].Text != "Sable has seen it on the network by hardware address" || first.Reasons[0].Code != "aa:00:00:00:00:01" {
		t.Fatalf("tablet reasons = %+v", first.Reasons)
	}
	if second.Subject.Device != "ip:2001:db8:1234:1500::77" || !second.Subject.Monospace ||
		second.Reasons[0].Text != "Its address is on a network Sable is attached to" || second.Headline != "2001:db8:1234:1500::77's lookups are refused" {
		t.Fatalf("unknown device finding = %+v", second)
	}
	if len(second.Domains) != 1 || second.Domains[0].Name != "cloud.example" || second.Domains[0].Query.ClientIP != "2001:db8:1234:1500::77" {
		t.Fatalf("unknown device names = %+v", second.Domains)
	}
}

type refusalSource struct{ input RefusalInput }

func (source refusalSource) Refusals(context.Context, time.Time) (RefusalInput, error) {
	return source.input, nil
}

// A kind that is off is never looked for.
func TestRefusalAnalyzerSkipsAKindThatIsOff(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 9, 30, 15, 0, 0, 0, time.UTC)
	input := RefusalInput{
		Refused: refusedEvery(nil, "2001:db8:1234:1500::77", "cloud.example.", now, 30*time.Minute, 12), Now: now,
		Allowed: func(string) bool { return false }, Attached: func(string) bool { return true },
	}
	analyzer := RefusalAnalyzer{Sources: refusalSource{input}}
	if findings, err := analyzer.Analyze(context.Background(), insights.Window{End: now}); err != nil || len(findings) != 1 {
		t.Fatalf("findings = %v, %v", findings, err)
	}
	analyzer.Off = map[string]bool{KindLookupsRefused: true}
	if findings, _ := analyzer.Analyze(context.Background(), insights.Window{End: now}); len(findings) != 0 {
		t.Fatalf("an off kind reported %v", findings)
	}
}
