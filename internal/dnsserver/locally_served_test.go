package dnsserver

import (
	"context"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func TestIsLocallyServedZone(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		want bool
	}{
		{"db._dns-sd._udp.0.215.168.192.in-addr.arpa.", true},
		{"1.0.16.172.in-addr.arpa.", true},
		{"1.0.31.172.in-addr.arpa.", true},
		{"1.0.100.100.in-addr.arpa.", true},
		{"_dns.resolver.arpa.", true},
		{"printer.home.arpa.", true},
		{"nas.local.", true},
		{"LOCALHOST.", true},
		{"host.internal", true},
		{"www.test.", true},
		// 172.15 and 172.32 fall outside 172.16.0.0/12, and 63.100 and 128.100
		// fall outside the shared address space, so all four are ordinary names.
		{"1.0.15.172.in-addr.arpa.", false},
		{"1.0.32.172.in-addr.arpa.", false},
		{"1.0.63.100.in-addr.arpa.", false},
		{"1.0.128.100.in-addr.arpa.", false},
		{"1.0.169.192.in-addr.arpa.", false},
		{"api.anthropic.com.", false},
		{"arpa.", false},
		{".", false},
	}
	for _, testCase := range cases {
		if got := isLocallyServedZone(testCase.name); got != testCase.want {
			t.Errorf("isLocallyServedZone(%q) = %v; want %v", testCase.name, got, testCase.want)
		}
	}
}

// TestDNSSECValidatorSkipsLocallyServedZones covers the two shapes a forwarder
// returns for a name with no global delegation: an NXDOMAIN carrying nothing at
// all, and one proven by an ancestor that never delegated the name. Neither can
// be authenticated, so both have to come back insecure rather than bogus. The
// empty query map fails any upstream lookup, proving the exemption short
// circuits before the validator reaches for a DS or DNSKEY record.
func TestDNSSECValidatorSkipsLocallyServedZones(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 8, 10, 12, 0, 0, 0, time.UTC)
	cases := []struct {
		name       string
		recordType uint16
		authority  []dns.RR
	}{
		{"db._dns-sd._udp.0.215.168.192.in-addr.arpa.", dns.TypePTR, nil},
		{"_dns.resolver.arpa.", dns.TypeSVCB, []dns.RR{validatorSOA("arpa.")}},
	}
	for _, testCase := range cases {
		root := newValidatorTestKey(t, ".")
		validator := validatorWithAnchor(t, root, now)
		response := new(dns.Msg)
		response.SetQuestion(testCase.name, testCase.recordType)
		response.SetRcode(response, dns.RcodeNameError)
		response.Ns = testCase.authority
		state, err := validator.validate(context.Background(), response, response.Question[0], mapValidatorQuery(nil))
		if err != nil || state != validationInsecure {
			t.Errorf("validate(%s) = %v, %v; want insecure", testCase.name, state, err)
		}
	}
}
