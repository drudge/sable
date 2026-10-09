package dnsserver

import (
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/drudge/sable/internal/querylog"
)

// ruleSetTestConfig blocks names from two lists and the operator's own
// domains, with an exception from the strict list.
func ruleSetTestConfig() RuntimeConfig {
	configuration := testRuntimeConfig()
	configuration.Blocking = true
	configuration.BlockedDomains = []string{"ads.example", "tracker.example", "video.example", "operator.example", "shorts.video.example"}
	configuration.BlockedDomainOwnerSets = [][]string{nil, {"Ads"}, {"Ads", "Strict"}, {"Strict"}, {"Custom"}}
	configuration.BlockedDomainOwners = []uint32{1, 2, 3, 4, 1}
	configuration.ExceptionDomains = []string{"cdn.tracker.example"}
	configuration.ExceptionDomainOwners = []uint32{3}
	configuration.AllowedDomains = []string{"allowed.example"}
	configuration.RuleSets = []RuleSetPolicy{
		{Name: "Kids", Lists: []string{"Ads", "Strict", "Custom"}, Domains: []string{"games.example"}, AllowedDomains: []string{"school.ads.example"}, Clients: []string{"192.0.2.0/24"}},
		{Name: "Work", Lists: []string{"Custom"}, AllowedDomains: []string{"*.tracker.example"}, Clients: []string{"192.0.2.50", "2001:db8::/32"}},
		{Name: "Strict only", Lists: []string{"Strict", "Custom"}, Clients: []string{"198.51.100.7"}},
		{Name: "Ads only", Lists: []string{"Ads"}, Clients: []string{"198.51.100.8"}},
		{Name: "Tablets", Lists: []string{"Strict"}, Clients: []string{"DA:A1:19:00:00:01"}},
		{Name: "No Blocking", Off: true, Clients: []string{"192.0.2.99", "203.0.113.0/24"}},
	}
	return configuration
}

func TestRuleSetsDecidePolicyPerClient(t *testing.T) {
	t.Parallel()
	runtime, err := Compile(ruleSetTestConfig())
	if err != nil {
		t.Fatalf("Compile() error = %v", err)
	}
	tests := []struct {
		name, client, query string
		decision            querylog.PolicyDecision
		rule                string
		sources             []string
	}{
		{"no set uses every list", "10.0.0.1", "ads.example", querylog.PolicyBlocked, "ads.example", []string{"Ads"}},
		{"no set ignores a set's blocks", "10.0.0.1", "games.example", querylog.PolicyNoMatch, "", nil},
		{"set adds its own block", "192.0.2.4", "www.games.example", querylog.PolicyBlocked, "games.example", nil},
		{"set allow beats a list", "192.0.2.4", "school.ads.example", querylog.PolicyAllowed, "school.ads.example", nil},
		{"global allow still applies", "192.0.2.4", "allowed.example", querylog.PolicyAllowed, "allowed.example", nil},
		{"exact address beats network", "192.0.2.50", "ads.example", querylog.PolicyNoMatch, "", nil},
		{"unused list doesn't block", "192.0.2.50", "video.example", querylog.PolicyNoMatch, "", nil},
		{"operator domains still block", "192.0.2.50", "operator.example", querylog.PolicyBlocked, "operator.example", []string{"Custom"}},
		{"set wildcard allow", "2001:db8::5", "cdn.tracker.example", querylog.PolicyAllowed, "*.tracker.example", nil},
		{"sources narrow to the set's lists", "198.51.100.7", "tracker.example", querylog.PolicyBlocked, "tracker.example", []string{"Strict"}},
		{"unused entry falls through to parent", "198.51.100.7", "shorts.video.example", querylog.PolicyBlocked, "video.example", []string{"Strict"}},
		{"used list's exception lifts", "198.51.100.7", "cdn.tracker.example", querylog.PolicyAllowed, "cdn.tracker.example", []string{"Strict"}},
		{"unused list's exception doesn't lift", "198.51.100.8", "cdn.tracker.example", querylog.PolicyBlocked, "tracker.example", []string{"Ads"}},
		{"bypass address beats network", "192.0.2.99", "ads.example", querylog.PolicyClientBypass, "", nil},
		{"bypass network", "203.0.113.8", "operator.example", querylog.PolicyClientBypass, "", nil},
		{"mapped IPv4 client", "::ffff:192.0.2.4", "games.example", querylog.PolicyBlocked, "games.example", nil},
		{"no client", "", "games.example", querylog.PolicyNoMatch, "", nil},
	}
	for _, test := range tests {
		decision, rule, sources := runtime.policyDecision(test.query, test.client, nil, false)
		if decision != test.decision || rule != test.rule || !slices.Equal(sources, test.sources) {
			t.Errorf("%s: policyDecision(%q, %q) = %q %q %v, want %q %q %v", test.name, test.query, test.client,
				decision, rule, sources, test.decision, test.rule, test.sources)
		}
	}
}

func TestDefaultListsNarrowPolicyForClientsWithoutRuleSet(t *testing.T) {
	t.Parallel()
	configuration := ruleSetTestConfig()
	configuration.DefaultLists = []string{"Ads", "Custom"}
	runtime, err := Compile(configuration)
	if err != nil {
		t.Fatalf("Compile() error = %v", err)
	}
	handler := NewHandler(runtime)
	if policy := handler.DomainPolicy("video.example"); policy.Decision != querylog.PolicyNoMatch {
		t.Errorf("DomainPolicy(video.example) = %+v, want no match outside the default lists", policy)
	}
	if decision, rule, sources := runtime.policyDecision("tracker.example", "10.0.0.1", nil, false); decision != querylog.PolicyBlocked ||
		rule != "tracker.example" || !slices.Equal(sources, []string{"Ads"}) {
		t.Errorf("policyDecision(tracker.example) = %q %q %v, want blocked by Ads alone", decision, rule, sources)
	}
	if decision, _, _ := runtime.policyDecision("video.example", "198.51.100.7", nil, false); decision != querylog.PolicyBlocked {
		t.Errorf("policyDecision(video.example) for a rule set = %q, want its own lists to apply", decision)
	}
}

func TestDeviceAddressesPutDevicesInRuleSets(t *testing.T) {
	t.Parallel()
	configuration := ruleSetTestConfig()
	configuration.RuleSets[0].Clients = append(configuration.RuleSets[0].Clients, "da:a1:19:00:00:02")
	runtime, err := Compile(configuration)
	if err != nil {
		t.Fatalf("Compile() error = %v", err)
	}
	devices := DeviceAddresses{
		netip.MustParseAddr("10.0.0.7"):    "da:a1:19:00:00:02",
		netip.MustParseAddr("192.0.2.50"):  "da:a1:19:00:00:02",
		netip.MustParseAddr("2001:db8::9"): "da:a1:19:00:00:02",
		netip.MustParseAddr("10.0.0.8"):    "da:a1:19:00:00:01",
		netip.MustParseAddr("10.0.0.9"):    "da:a1:19:00:00:09",
	}
	for _, test := range []struct {
		client   string
		decision querylog.PolicyDecision
	}{
		{"10.0.0.7", querylog.PolicyBlocked},     // learned address joins Kids
		{"192.0.2.50", querylog.PolicyNoMatch},   // a configured address wins
		{"2001:db8::9", querylog.PolicyBlocked},  // learned beats a configured network
		{"10.0.0.8", querylog.PolicyNoMatch},     // Tablets doesn't block games.example
		{"10.0.0.9", querylog.PolicyNoMatch},     // a device in no rule set
		{"fe80::1%eth0", querylog.PolicyNoMatch}, // zones are ignored
	} {
		if decision, _, _ := runtime.policyDecision("games.example", test.client, devices, false); decision != test.decision {
			t.Errorf("policyDecision(games.example) for %s = %q, want %q", test.client, decision, test.decision)
		}
	}
	if decision, _, sources := runtime.policyDecision("video.example", "10.0.0.8", devices, false); decision != querylog.PolicyBlocked ||
		!slices.Equal(sources, []string{"Strict"}) {
		t.Errorf("policyDecision(video.example) for a tablet = %q %v, want blocked by Strict", decision, sources)
	}
	handler := NewHandler(runtime)
	if handler.DeviceAddressTable() != nil {
		t.Fatal("a new handler has device addresses")
	}
	handler.SetDeviceAddresses(devices)
	if got := handler.DeviceAddressTable(); len(got) != len(devices) {
		t.Fatalf("DeviceAddressTable() = %v", got)
	}
}

func TestRuleSetsRejectInvalidClientsAndDomains(t *testing.T) {
	t.Parallel()
	for _, change := range []struct {
		name  string
		edit  func(*RuntimeConfig)
		error string
	}{
		{"client", func(configuration *RuntimeConfig) { configuration.RuleSets[0].Clients = []string{"not-an-address"} }, `rule set "Kids": invalid client`},
		{"off", func(configuration *RuntimeConfig) { configuration.RuleSets[5].Clients = []string{"fe80::1%eth0"} }, `rule set "No Blocking": invalid client`},
		{"domain", func(configuration *RuntimeConfig) { configuration.RuleSets[1].Domains = []string{"bad..example"} }, `rule set "Work": invalid blocked domain`},
		{"allowed", func(configuration *RuntimeConfig) {
			configuration.RuleSets[1].AllowedDomains = []string{"bad..example"}
		}, `rule set "Work": invalid allowed domain`},
	} {
		configuration := ruleSetTestConfig()
		change.edit(&configuration)
		if _, err := Compile(configuration); err == nil || !strings.Contains(err.Error(), change.error) {
			t.Errorf("%s: Compile() error = %v, want %q", change.name, err, change.error)
		}
	}
}

func TestPolicyDecisionDoesNotAllocateWithRuleSets(t *testing.T) {
	runtime, err := Compile(ruleSetTestConfig())
	if err != nil {
		t.Fatalf("Compile() error = %v", err)
	}
	devices := DeviceAddresses{netip.MustParseAddr("10.0.0.7"): "da:a1:19:00:00:01"}
	for _, client := range []string{"10.0.0.1", "10.0.0.7", "192.0.2.4", "192.0.2.50", "198.51.100.7", "192.0.2.99"} {
		if allocations := testing.AllocsPerRun(100, func() {
			_, _, _ = runtime.policyDecision("pixel.shorts.video.example.", client, devices, false)
		}); allocations != 0 {
			t.Errorf("policyDecision for %s allocated %.0f times, want 0", client, allocations)
		}
	}
}

// BenchmarkPolicyDecision measures the per-query policy check against a large
// block list, for a client with no rule set and for one in a set that uses
// only some of the lists, with holds on other clients.
func BenchmarkPolicyDecision(b *testing.B) {
	const policySize = 100_000
	configuration := testRuntimeConfig()
	configuration.Blocking = true
	configuration.BlockedDomains = make([]string, 0, policySize)
	configuration.BlockedDomainOwners = make([]uint32, 0, policySize)
	configuration.BlockedDomainOwnerSets = [][]string{nil, {"Ads"}, {"Strict"}}
	for index := range policySize {
		configuration.BlockedDomains = append(configuration.BlockedDomains, fmt.Sprintf("host-%d.example", index))
		configuration.BlockedDomainOwners = append(configuration.BlockedDomainOwners, uint32(1+index%2))
	}
	configuration.RuleSets = []RuleSetPolicy{{Name: "No Blocking", Off: true, Clients: []string{"198.51.100.0/24"}}}
	runtime, err := Compile(configuration)
	if err != nil {
		b.Fatal(err)
	}
	withSets := configuration
	withSets.RuleSets = []RuleSetPolicy{
		configuration.RuleSets[0],
		{Name: "Kids", Lists: []string{"Strict"}, Domains: []string{"games.example"}, Clients: []string{"192.0.2.0/24"}},
		{Name: "Work", Lists: []string{"Ads"}, Clients: []string{"192.0.2.50", "2001:db8::/32", "da:a1:19:00:00:01"}},
	}
	withSets.Holds = []HoldPolicy{{Client: "192.0.2.77", Until: time.Now().Add(time.Hour)}, {Client: "da:a1:19:00:00:02"}}
	setRuntime, err := Compile(withSets)
	if err != nil {
		b.Fatal(err)
	}
	devices := DeviceAddresses{netip.MustParseAddr("10.0.0.7"): "da:a1:19:00:00:01"}
	for _, run := range []struct {
		name    string
		runtime *Runtime
		client  string
	}{
		{"NoRuleSets", runtime, "192.0.2.4"},
		{"LearnedDevice", setRuntime, "10.0.0.7"},
		{"OutsideRuleSets", setRuntime, "10.0.0.1"},
		{"InRuleSet", setRuntime, "192.0.2.4"},
	} {
		b.Run(run.name, func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				_, _, _ = run.runtime.policyDecision("pixel.host-99999.example.", run.client, devices, false)
			}
		})
	}
}

func TestMatchClientPicksLikeTheRuleSetTable(t *testing.T) {
	t.Parallel()
	clients := []string{"10.0.0.0/16", "10.0.1.0/24", "3c:22:fb:01:02:03", "10.0.1.9", "not a client"}
	for _, test := range []struct {
		address, mac, want string
	}{
		{"10.0.1.9", "3c:22:fb:01:02:03", "10.0.1.9"},
		{"10.0.1.5", "3c:22:fb:01:02:03", "3c:22:fb:01:02:03"},
		{"10.0.1.5", "", "10.0.1.0/24"},
		{"10.0.2.5", "", "10.0.0.0/16"},
		{"192.0.2.1", "", ""},
	} {
		if got, _ := MatchClient(clients, test.address, test.mac); got != test.want {
			t.Errorf("MatchClient(%s, %q) = %q, want %q", test.address, test.mac, got, test.want)
		}
	}
}
