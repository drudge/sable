package forwarding

import "testing"

func TestRecordRoundTrip(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		value    string
		want     string
		endpoint string
	}{
		{value: "udp 10 192.0.2.53", want: "udp 10 192.0.2.53:53", endpoint: "udp://192.0.2.53:53"},
		{value: "tcp 20 dns.example:5353", want: "tcp 20 dns.example:5353", endpoint: "tcp://dns.example:5353"},
		{value: "tls 0 2001:db8::53", want: "tls 0 [2001:db8::53]:853", endpoint: "tls://[2001:db8::53]:853"},
		{value: "quic 5 dns.example", want: "quic 5 dns.example:853", endpoint: "quic://dns.example:853"},
	} {
		record, err := ParseRecord(test.value)
		if err != nil || record.String() != test.want || record.Endpoint() != test.endpoint {
			t.Errorf("ParseRecord(%q) = %+v, %v", test.value, record, err)
		}
	}
}

func TestRecordRejectsUnsupportedProtocolAndInvalidAddress(t *testing.T) {
	t.Parallel()
	for _, value := range []string{"h3 0 dns.example", "udp x dns.example", "tcp 0 [::1", "udp 0 dns.example:0"} {
		if _, err := ParseRecord(value); err == nil {
			t.Errorf("ParseRecord(%q) succeeded", value)
		}
	}
}
