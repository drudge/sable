package dnsserver

import (
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/drudge/sable/internal/querylog"
)

func holdTestConfig() RuntimeConfig {
	configuration := ruleSetTestConfig()
	configuration.Holds = []HoldPolicy{
		{Client: "192.0.2.4", Until: time.Now().Add(time.Hour)},
		{Client: "da:a1:19:00:00:01"},
		{Client: "203.0.113.0/24"},
		{Client: "198.51.100.7", Until: time.Now().Add(-time.Minute)},
	}
	return configuration
}

func TestHoldsBlockEverythingButAllowedDomains(t *testing.T) {
	t.Parallel()
	runtime, err := Compile(holdTestConfig())
	if err != nil {
		t.Fatalf("Compile() error = %v", err)
	}
	devices := DeviceAddresses{netip.MustParseAddr("10.0.0.8"): "da:a1:19:00:00:01"}
	tests := []struct {
		name, client, query string
		paused              bool
		decision            querylog.PolicyDecision
		rule                string
	}{
		{"held address", "192.0.2.4", "example.com", false, querylog.PolicyHeld, ""},
		{"held device by hardware address", "10.0.0.8", "example.com", false, querylog.PolicyHeld, ""},
		{"rule set allow still works", "192.0.2.4", "school.ads.example", false, querylog.PolicyAllowed, "school.ads.example"},
		{"global allow still works", "10.0.0.8", "allowed.example", false, querylog.PolicyAllowed, "allowed.example"},
		{"hold beats a bypass", "203.0.113.8", "example.com", false, querylog.PolicyHeld, ""},
		{"hold outlasts a pause", "192.0.2.4", "example.com", true, querylog.PolicyHeld, ""},
		{"ended hold", "198.51.100.7", "example.com", false, querylog.PolicyNoMatch, ""},
		{"neighbor in the same network", "192.0.2.5", "example.com", false, querylog.PolicyNoMatch, ""},
		{"no client", "", "example.com", false, querylog.PolicyNoMatch, ""},
	}
	for _, test := range tests {
		decision, rule, _ := runtime.policyDecision(test.query, test.client, devices, test.paused)
		if decision != test.decision || rule != test.rule {
			t.Errorf("%s: policyDecision(%q, %q) = %q %q, want %q %q", test.name, test.query, test.client, decision, rule, test.decision, test.rule)
		}
	}

	configuration := holdTestConfig()
	configuration.Blocking = false
	disabled, err := Compile(configuration)
	if err != nil {
		t.Fatalf("Compile() error = %v", err)
	}
	if decision, _, _ := disabled.policyDecision("example.com", "192.0.2.4", nil, false); decision != querylog.PolicyDisabled {
		t.Errorf("policyDecision with blocking off = %q, want disabled", decision)
	}
}

func TestHoldsRejectInvalidClients(t *testing.T) {
	t.Parallel()
	configuration := ruleSetTestConfig()
	configuration.Holds = []HoldPolicy{{Client: "kids-ipad"}}
	if _, err := Compile(configuration); err == nil || !strings.Contains(err.Error(), "invalid blocking hold client") {
		t.Fatalf("Compile() error = %v", err)
	}
}

func TestResolveAnswersHeldClientsWithTheBlockedResponse(t *testing.T) {
	t.Parallel()
	runtime, err := Compile(holdTestConfig())
	if err != nil {
		t.Fatalf("Compile() error = %v", err)
	}
	handler := NewHandler(runtime)
	request := new(dns.Msg)
	request.SetQuestion("example.com.", dns.TypeA)
	result := handler.resolveForClient(request, runtime, "192.0.2.4")
	if result.source != querylog.SourceBlocked || result.decision.Policy != querylog.PolicyHeld {
		t.Fatalf("resolve() = %s %s, want a blocked answer for a held client", result.source, result.decision.Policy)
	}
}

func TestPolicyDecisionDoesNotAllocateWithHolds(t *testing.T) {
	runtime, err := Compile(holdTestConfig())
	if err != nil {
		t.Fatalf("Compile() error = %v", err)
	}
	devices := DeviceAddresses{netip.MustParseAddr("10.0.0.8"): "da:a1:19:00:00:01"}
	for _, client := range []string{"10.0.0.1", "10.0.0.8", "192.0.2.4", "198.51.100.7", "203.0.113.8"} {
		if allocations := testing.AllocsPerRun(100, func() {
			_, _, _ = runtime.policyDecision("pixel.shorts.video.example.", client, devices, false)
		}); allocations != 0 {
			t.Errorf("policyDecision for %s allocated %.0f times, want 0", client, allocations)
		}
	}
}
