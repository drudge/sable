package dhcpimport

import "testing"

// dnsmasq 2.91 serves each of these: it allows white space around "=" and
// the commas (the first line gave 02:00:00:00:06:03 the address 192.0.2.13
// in the review), and a --dhcp-hostsfile, which is also how Pi-hole 6 keeps
// dhcp.hosts in pihole.toml, has the same lines without "dhcp-host=". The
// importer has to read them, not pass over them without a note.
func TestReview635DnsmasqLinesDnsmasqAccepts(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name, text string
		want       []Entry
	}{
		{"spaces around = and commas", "domain=lan\ndhcp-host = 02:00:00:00:06:03 , 192.0.2.13 , spaced\n",
			[]Entry{{Line: 2, MAC: "02:00:00:00:06:03", Address: "192.0.2.13", Name: "spaced"}}},
		{"a dhcp-hostsfile", "02:00:00:00:06:01,192.0.2.31,pi-tv\nAA:BB:CC:DD:EE:21,192.0.2.32,Kitchen-Speaker\naa:bb:cc:dd:ee:22,192.0.2.33\n",
			[]Entry{{Line: 1, MAC: "02:00:00:00:06:01", Address: "192.0.2.31", Name: "pi-tv"},
				{Line: 2, MAC: "aa:bb:cc:dd:ee:21", Address: "192.0.2.32", Name: "kitchen-speaker"},
				{Line: 3, MAC: "aa:bb:cc:dd:ee:22", Address: "192.0.2.33"}}},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			result, err := Parse([]byte(test.text))
			if err != nil {
				t.Fatalf("Parse: %v", err)
			}
			if result.Format != FormatDnsmasq || len(result.Entries) != len(test.want) {
				t.Fatalf("format %s, entries %+v, problems %+v; want %d dnsmasq entries", result.Format, result.Entries, result.Problems, len(test.want))
			}
			for i, want := range test.want {
				if result.Entries[i] != want {
					t.Errorf("entry %d = %+v, want %+v", i, result.Entries[i], want)
				}
			}
		})
	}
}
