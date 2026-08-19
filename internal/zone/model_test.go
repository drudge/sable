package zone

import (
	"testing"
)

func TestQualifyRecordValue(t *testing.T) {
	cases := []struct {
		name       string
		recordType string
		value      string
		expected   string
	}{
		{"bare cname target", "CNAME", "www", "www.example.com."},
		{"dotted cname target", "CNAME", "www.example.com", "www.example.com"},
		{"absolute cname target", "CNAME", "www.example.com.", "www.example.com."},
		{"external cname target", "CNAME", "target.cdn.example.net", "target.cdn.example.net"},
		{"bare name server", "NS", "ns1", "ns1.example.com."},
		{"bare mail exchange", "MX", "10 mail", "10 mail.example.com."},
		{"external mail exchange", "MX", "10 mail.google.com", "10 mail.google.com"},
		{"null mail exchange", "MX", "0 .", "0 ."},
		{"bare service target", "SRV", "0 5 443 host", "0 5 443 host.example.com."},
		{"unavailable service target", "SRV", "0 5 443 .", "0 5 443 ."},
		{"bare svcb target", "HTTPS", `1 svc alpn="h2,h3"`, `1 svc.example.com. alpn="h2,h3"`},
		{"apex svcb target", "HTTPS", `1 . alpn="h2,h3"`, `1 . alpn="h2,h3"`},
		{
			"bare soa names", "SOA", "ns1 hostmaster 3 3600 600 1209600 300",
			"ns1.example.com. hostmaster.example.com. 3 3600 600 1209600 300",
		},
		{"bare aname target", "ANAME", "origin", "origin.example.com."},
		{"address value", "A", "192.0.2.1", "192.0.2.1"},
		{"text value keeps spacing", "TXT", `"hello there world"`, `"hello there world"`},
		{"forwarder value", "FWD", "tls 10 1.1.1.1", "tls 10 1.1.1.1"},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			actual := QualifyRecordValue("example.com", testCase.recordType, testCase.value)
			if actual != testCase.expected {
				t.Fatalf("QualifyRecordValue(%q, %q) = %q, want %q", testCase.recordType, testCase.value, actual, testCase.expected)
			}
		})
	}
}

func TestQualifyRecordValueWithoutZone(t *testing.T) {
	if actual := QualifyRecordValue("", "CNAME", "www"); actual != "www" {
		t.Fatalf("QualifyRecordValue with no zone = %q, want %q", actual, "www")
	}
}

func TestParseRecordQualifiesBareLabel(t *testing.T) {
	zone := Zone{Name: "example.com", DefaultTTL: 300}
	cases := []struct {
		name     string
		record   Record
		expected string
	}{
		{
			"bare cname target",
			Record{Name: "alias", Type: "CNAME", TTL: 300, Value: "www"},
			"alias.example.com.\t300\tIN\tCNAME\twww.example.com.",
		},
		{
			"bare mail exchange",
			Record{Name: "@", Type: "MX", TTL: 300, Value: "10 mail"},
			"example.com.\t300\tIN\tMX\t10 mail.example.com.",
		},
		{
			"bare aname target",
			Record{Name: "@", Type: "ANAME", TTL: 300, Value: "origin"},
			"example.com.\t300\tIN\tCNAME\torigin.example.com.",
		},
		{
			"absolute target is untouched",
			Record{Name: "alias", Type: "CNAME", TTL: 300, Value: "www.example.net."},
			"alias.example.com.\t300\tIN\tCNAME\twww.example.net.",
		},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			rr, err := ParseRecord(zone, testCase.record)
			if err != nil {
				t.Fatalf("ParseRecord returned %v", err)
			}
			if rr.String() != testCase.expected {
				t.Fatalf("ParseRecord = %q, want %q", rr.String(), testCase.expected)
			}
		})
	}
}
