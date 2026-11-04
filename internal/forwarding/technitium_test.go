package forwarding

import (
	"encoding/hex"
	"fmt"
	"testing"
)

func TestParseTechnitiumRecord(t *testing.T) {
	for _, test := range []struct {
		name       string
		protocol   byte
		address    string
		options    []byte
		want       string
		validation bool
	}{
		{"udp", 0, "192.0.2.53", []byte{0, 0, 10}, "udp 10 192.0.2.53:53", false},
		{"tcp", 1, "192.0.2.53:5353", []byte{1, 254, 20}, "tcp 20 192.0.2.53:5353", true},
		{"tls", 2, "dns.example", []byte{1, 0, 0}, "tls 0 dns.example:853", true},
		{"quic ipv6", 5, "2001:db8::53", []byte{1, 0, 2}, "quic 2 [2001:db8::53]:853", true},
		{"legacy", 0, "192.0.2.53", nil, "udp 0 192.0.2.53:53", false},
		{"legacy options", 0, "192.0.2.53", []byte{1, 0}, "udp 0 192.0.2.53:53", true},
		{"https", 3, "https://dns.quad9.net/dns-query (9.9.9.9)", []byte{1, 0, 0}, "https 0 https://dns.quad9.net/dns-query (9.9.9.9)", true},
		{"https json", 4, "https://dns.google/resolve (8.8.8.8)", []byte{0, 0, 3}, "https 3 https://dns.google/resolve (8.8.8.8)", false},
		{"https ipv6", 3, "https://dns.quad9.net/dns-query ([2620:fe::fe])", nil, "https 0 https://dns.quad9.net/dns-query (2620:fe::fe)", false},
		{"tls bootstrap port", 2, "dns.quad9.net:853 (9.9.9.9:853)", nil, "tls 0 dns.quad9.net:853 (9.9.9.9)", false},
		{"http", 3, "http://dns.example/dns-query", nil, "", false},
		{"proxy", 0, "192.0.2.53", []byte{1, 1, 0}, "", false},
		{"unknown options", 0, "192.0.2.53", []byte{1, 0, 0, 0}, "", false},
		{"truncated options", 0, "192.0.2.53", []byte{1}, "", false},
		{"validation flag", 0, "192.0.2.53", []byte{2, 0, 0}, "", false},
		{"recursive", 0, "this-server", nil, "udp 0 this-server", false},
		{"pinned hostname", 2, "dns.example (192.0.2.53)", nil, "tls 0 dns.example:853 (192.0.2.53)", false},
		{"bad bootstrap", 2, "dns.example (dns.other)", nil, "", false},
	} {
		t.Run(test.name, func(t *testing.T) {
			data := append([]byte{test.protocol, byte(len(test.address))}, []byte(test.address)...)
			data = append(data, test.options...)
			record, validation, err := ParseTechnitiumRecord(fmt.Sprintf(`\# %d %s`, len(data), hex.EncodeToString(data)))
			if test.want == "" {
				if err == nil {
					t.Fatal("unsupported settings accepted")
				}
				return
			}
			if err != nil || record.String() != test.want || validation != test.validation {
				t.Fatalf("got %v, %v, %v", record, validation, err)
			}
		})
	}
	for _, value := range []string{"", `\# 1 00`, `\# 2 00ff`, `\# 3 0000`, `\# 2 xxxx`} {
		if _, _, err := ParseTechnitiumRecord(value); err == nil {
			t.Fatalf("accepted malformed data %q", value)
		}
	}
}
