package forwarding

import (
	"strings"
	"testing"
)

func TestParseUpstream(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		value     string
		canonical string
		dial      string
		url       string
		bootstrap bool
	}{
		{value: "192.0.2.53", canonical: "udp://192.0.2.53:53", dial: "192.0.2.53:53"},
		{value: "tls://1.1.1.1", canonical: "tls://1.1.1.1:853", dial: "1.1.1.1:853"},
		{value: "https://cloudflare-dns.com/dns-query (1.1.1.1)", canonical: "https://cloudflare-dns.com/dns-query (1.1.1.1)",
			dial: "1.1.1.1:443", url: "https://cloudflare-dns.com/dns-query"},
		{value: "HTTPS://DNS.Quad9.net (9.9.9.9)", canonical: "https://dns.quad9.net/dns-query (9.9.9.9)",
			dial: "9.9.9.9:443", url: "https://dns.quad9.net/dns-query"},
		{value: "https://dns.quad9.net:5443/ (2620:fe::fe)", canonical: "https://dns.quad9.net:5443/dns-query (2620:fe::fe)",
			dial: "[2620:fe::fe]:5443", url: "https://dns.quad9.net:5443/dns-query"},
		{value: "https://dns.example/resolve?tenant=a ([2001:db8::1])", canonical: "https://dns.example/resolve?tenant=a (2001:db8::1)",
			dial: "[2001:db8::1]:443", url: "https://dns.example/resolve?tenant=a"},
		{value: "https://[2606:4700:4700::1111]/dns-query", canonical: "https://[2606:4700:4700::1111]/dns-query",
			dial: "[2606:4700:4700::1111]:443", url: "https://[2606:4700:4700::1111]/dns-query"},
		{value: "https://1.1.1.1", canonical: "https://1.1.1.1/dns-query", dial: "1.1.1.1:443", url: "https://1.1.1.1/dns-query"},
		{value: "tls://dns.quad9.net (9.9.9.9)", canonical: "tls://dns.quad9.net:853 (9.9.9.9)", dial: "9.9.9.9:853"},
		{value: "tls://dns.quad9.net:853 (9.9.9.9:853)", canonical: "tls://dns.quad9.net:853 (9.9.9.9)", dial: "9.9.9.9:853"},
		{value: "quic://dns.adguard-dns.com(94.140.14.14)", canonical: "quic://dns.adguard-dns.com:853 (94.140.14.14)", dial: "94.140.14.14:853"},
		{value: "quic://dns.example ([2001:db8::53]:853)", canonical: "quic://dns.example:853 (2001:db8::53)", dial: "[2001:db8::53]:853"},
		{value: "tls://dns.example", canonical: "tls://dns.example:853", dial: "dns.example:853", bootstrap: true},
		{value: "quic://dns.example:8853", canonical: "quic://dns.example:8853", dial: "dns.example:8853", bootstrap: true},
		{value: "https://dns.example/dns-query", canonical: "https://dns.example/dns-query", dial: "dns.example:443",
			url: "https://dns.example/dns-query", bootstrap: true},
		{value: "tcp://dns.example", canonical: "tcp://dns.example:53", dial: "dns.example:53"},
	} {
		upstream, err := Parse(test.value)
		if err != nil {
			t.Errorf("Parse(%q): %v", test.value, err)
			continue
		}
		if upstream.String() != test.canonical || upstream.DialAddress() != test.dial || upstream.NeedsBootstrap() != test.bootstrap {
			t.Errorf("Parse(%q) = %q dial %q needs bootstrap %v", test.value, upstream.String(), upstream.DialAddress(), upstream.NeedsBootstrap())
		}
		if upstream.Protocol == "https" && upstream.URL() != test.url {
			t.Errorf("Parse(%q).URL() = %q, want %q", test.value, upstream.URL(), test.url)
		}
		again, err := Parse(upstream.String())
		if err != nil || again != upstream {
			t.Errorf("Parse(%q) does not round-trip: %+v, %v", upstream.String(), again, err)
		}
		if (CheckBootstrap(test.value) != nil) != test.bootstrap {
			t.Errorf("CheckBootstrap(%q) = %v", test.value, CheckBootstrap(test.value))
		}
	}
}

func TestParseUpstreamRefuses(t *testing.T) {
	t.Parallel()
	for _, test := range []struct{ value, want string }{
		{"https://user:pass@dns.example/dns-query (192.0.2.1)", "credentials"},
		{"https://dns.example/dns-query#frag (192.0.2.1)", "fragment"},
		{"https://dns.example/dns-query{?dns} (192.0.2.1)", "URI template"},
		{"https:// (192.0.2.1)", "required"},
		{"https://", "required"},
		{"https://dns.example:0/ (192.0.2.1)", "port"},
		{"https://dns.example:99999/ (192.0.2.1)", "port"},
		{"http://dns.example/dns-query", "https://"},
		{"h3://dns.example/dns-query", "https://"},
		{"https://dns.example (dns.quad9.net)", "IPv4 or IPv6"},
		{"https://dns.example (192.0.2.1", "parentheses"},
		{"https://dns.example 192.0.2.1)", "invalid forwarder"},
		{"https://dns.example ()", "empty"},
		{"https://dns.example ((192.0.2.1))", "parentheses"},
		{"tls://dns.example (192.0.2.1:8853)", "different port"},
		{"udp://dns.example (192.0.2.1)", "only applies"},
		{"192.0.2.1 (192.0.2.2)", "only applies"},
		{"tls://dns.example/dns-query", "invalid forwarder host"},
		{"ftp://dns.example", "unsupported"},
	} {
		_, err := Parse(test.value)
		if err == nil || !strings.Contains(err.Error(), test.want) {
			t.Errorf("Parse(%q) = %v, want an error containing %q", test.value, err, test.want)
		}
	}
}

func TestRecordWithBootstrap(t *testing.T) {
	t.Parallel()
	for _, test := range []struct{ value, want, endpoint string }{
		{"https 0 https://dns.quad9.net/dns-query (9.9.9.9)", "https 0 https://dns.quad9.net/dns-query (9.9.9.9)",
			"https://dns.quad9.net/dns-query (9.9.9.9)"},
		{"https 5 dns.quad9.net (9.9.9.9)", "https 5 https://dns.quad9.net/dns-query (9.9.9.9)",
			"https://dns.quad9.net/dns-query (9.9.9.9)"},
		{"tls 1 dns.quad9.net (2620:fe::fe)", "tls 1 dns.quad9.net:853 (2620:fe::fe)", "tls://dns.quad9.net:853 (2620:fe::fe)"},
		{"quic 2 quic://dns.example:8853 (192.0.2.1)", "quic 2 dns.example:8853 (192.0.2.1)", "quic://dns.example:8853 (192.0.2.1)"},
	} {
		record, err := ParseRecord(test.value)
		if err != nil || record.String() != test.want || record.Endpoint() != test.endpoint {
			t.Errorf("ParseRecord(%q) = %q %q, %v", test.value, record.String(), record.Endpoint(), err)
			continue
		}
		if again, err := ParseRecord(record.String()); err != nil || again != record {
			t.Errorf("ParseRecord(%q) does not round-trip: %v", record.String(), err)
		}
	}
	for _, value := range []string{"tls 0 https://dns.example (192.0.2.1)", "https 0 this-server", "udp 0 this-server (192.0.2.1)"} {
		if _, err := ParseRecord(value); err == nil {
			t.Errorf("ParseRecord(%q) succeeded", value)
		}
	}
}
