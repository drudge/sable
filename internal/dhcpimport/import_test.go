package dhcpimport

import (
	"os"
	"reflect"
	"testing"
)

func TestParseReadsEachServersReservations(t *testing.T) {
	cases := []struct {
		file     string
		format   string
		entries  []Entry
		problems []int
	}{
		{
			file:   "dnsmasq.conf",
			format: FormatDnsmasq,
			entries: []Entry{
				{Line: 4, MAC: "00:11:22:33:44:55", Address: "10.0.7.10", Name: "nas"},
				{Line: 5, MAC: "aa:bb:cc:dd:ee:01", Address: "10.0.7.11", Name: "printer"},
				{Line: 6, MAC: "aa:bb:cc:dd:ee:02", Address: "10.0.7.12"},
				{Line: 7, MAC: "aa:bb:cc:dd:ee:03", Address: "10.0.7.13"},
				{Line: 10, MAC: "aa:bb:cc:dd:ee:05", Address: "10.0.7.15", Name: "dock"},
				{Line: 11, MAC: "aa:bb:cc:dd:ee:07", Address: "10.0.7.16"},
			},
			// ignore, no MAC, and the second MAC on line 10.
			problems: []int{8, 9, 10},
		},
		{
			file:   "adguard-leases.json",
			format: FormatAdGuard,
			entries: []Entry{
				{Line: 1, MAC: "00:11:22:33:44:20", Address: "10.0.7.20", Name: "tv"},
				{Line: 3, MAC: "00:11:22:33:44:22", Address: "10.0.7.22"},
			},
		},
		{
			file:    "adguard-status.json",
			format:  FormatAdGuard,
			entries: []Entry{{Line: 1, MAC: "00:11:22:33:44:30", Address: "10.0.7.30", Name: "camera"}},
		},
		{
			file:   "technitium-scope.json",
			format: FormatTechnitium,
			entries: []Entry{
				{Line: 1, MAC: "00:11:22:33:44:40", Address: "10.0.7.40", Name: "server", Comment: "rack"},
				{Line: 2, MAC: "00:11:22:33:44:41", Address: "10.0.7.41"},
			},
		},
		{
			file:   "unifi-users.json",
			format: FormatUniFi,
			entries: []Entry{
				{Line: 1, MAC: "00:11:22:33:44:50", Address: "10.0.7.50", Name: "uap", Comment: "closet"},
				{Line: 3, MAC: "00:11:22:33:44:52", Address: "10.0.7.52", Name: "sensor"},
			},
		},
	}
	for _, test := range cases {
		t.Run(test.file, func(t *testing.T) {
			data, err := os.ReadFile("testdata/" + test.file)
			if err != nil {
				t.Fatal(err)
			}
			result, err := Parse(data)
			if err != nil {
				t.Fatalf("Parse: %v", err)
			}
			if result.Format != test.format {
				t.Errorf("format = %q, want %q", result.Format, test.format)
			}
			if !reflect.DeepEqual(result.Entries, test.entries) {
				t.Errorf("entries =\n%+v\nwant\n%+v", result.Entries, test.entries)
			}
			var lines []int
			for _, problem := range result.Problems {
				lines = append(lines, problem.Line)
			}
			if !reflect.DeepEqual(lines, test.problems) {
				t.Errorf("problem lines = %v, want %v (%+v)", lines, test.problems, result.Problems)
			}
		})
	}
}

func TestParseRefusesWhatItCannotRead(t *testing.T) {
	for name, data := range map[string]string{
		"empty":        "",
		"no hosts":     "domain=lan\ndhcp-range=10.0.7.100,10.0.7.199\n",
		"unknown json": `{"zones":[]}`,
		"broken json":  `{"leases":[`,
	} {
		if _, err := Parse([]byte(data)); err == nil {
			t.Errorf("%s: Parse succeeded, want an error", name)
		}
	}
}
