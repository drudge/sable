package zone

import (
	"slices"
	"strings"
	"testing"
	"time"
)

func TestCheckCNAMEExclusivity(t *testing.T) {
	t.Parallel()
	now := time.Now()
	expired := now.Add(-time.Hour)
	active := now.Add(time.Hour)

	tests := []struct {
		name    string
		records []Record
		check   string
		wantErr string
	}{
		{
			name: "cname added where an address exists",
			records: []Record{
				{Name: "www", Type: "A", Value: "192.0.2.10"},
				{Name: "www", Type: "CNAME", Value: "target.example.test."},
			},
			check:   "www",
			wantErr: "cannot share the name \"www.example.test\"",
		},
		{
			name: "address added where a cname exists",
			records: []Record{
				{Name: "alias", Type: "CNAME", Value: "target.example.test."},
				{Name: "alias", Type: "AAAA", Value: "2001:db8::1"},
			},
			check:   "alias",
			wantErr: "cannot share the name \"alias.example.test\"",
		},
		{
			name: "second cname at the same name",
			records: []Record{
				{Name: "alias", Type: "CNAME", Value: "one.example.test."},
				{Name: "alias", Type: "CNAME", Value: "two.example.test."},
			},
			check:   "alias",
			wantErr: "a name can hold only one",
		},
		{
			name:    "cname alone",
			records: []Record{{Name: "alias", Type: "CNAME", Value: "target.example.test."}},
			check:   "alias",
		},
		{
			name: "cname with dnssec material",
			records: []Record{
				{Name: "alias", Type: "CNAME", Value: "target.example.test."},
				{Name: "alias", Type: "RRSIG", Value: "CNAME 15 3 300 20260901000000 20260801000000 12345 example.test. dGVzdA=="},
				{Name: "alias", Type: "NSEC", Value: "next.example.test. CNAME RRSIG NSEC"},
				{Name: "alias", Type: "NSEC3", Value: "1 0 0 - NEXTHASH CNAME"},
			},
			check: "alias",
		},
		{
			name: "cname with a disabled address",
			records: []Record{
				{Name: "alias", Type: "CNAME", Value: "target.example.test."},
				{Name: "alias", Type: "A", Value: "192.0.2.10", Disabled: true},
			},
			check: "alias",
		},
		{
			name: "cname with an expired address",
			records: []Record{
				{Name: "alias", Type: "CNAME", Value: "target.example.test."},
				{Name: "alias", Type: "A", Value: "192.0.2.10", ExpiresAt: expired},
			},
			check: "alias",
		},
		{
			name: "disabled cname with an address",
			records: []Record{
				{Name: "alias", Type: "CNAME", Value: "target.example.test.", Disabled: true},
				{Name: "alias", Type: "A", Value: "192.0.2.10"},
			},
			check: "alias",
		},
		{
			name: "cname with an expiring address still active",
			records: []Record{
				{Name: "alias", Type: "CNAME", Value: "target.example.test."},
				{Name: "alias", Type: "A", Value: "192.0.2.10", ExpiresAt: active},
			},
			check:   "alias",
			wantErr: "cannot share the name",
		},
		{
			name: "aname coexists with other data",
			records: []Record{
				{Name: "@", Type: "ANAME", Value: "target.example.test."},
				{Name: "@", Type: "MX", Value: "10 mail.example.test."},
				{Name: "@", Type: "TXT", Value: "\"v=spf1 -all\""},
			},
			check: "@",
		},
		{
			name: "aname does not coexist with a cname",
			records: []Record{
				{Name: "alias", Type: "ANAME", Value: "target.example.test."},
				{Name: "alias", Type: "CNAME", Value: "target.example.test."},
			},
			check:   "alias",
			wantErr: "cannot share the name",
		},
		{
			name: "fully qualified and relative names are the same owner",
			records: []Record{
				{Name: "www.example.test.", Type: "CNAME", Value: "target.example.test."},
				{Name: "WWW", Type: "A", Value: "192.0.2.10"},
			},
			check:   "www",
			wantErr: "cannot share the name",
		},
		{
			name: "records at other names do not conflict",
			records: []Record{
				{Name: "www", Type: "CNAME", Value: "target.example.test."},
				{Name: "api", Type: "A", Value: "192.0.2.10"},
			},
			check: "www",
		},
		{
			name: "apex cname conflicts with zone authority",
			records: []Record{
				{Name: "@", Type: "SOA", Value: "ns1.example.test. dns.example.test. 1 3600 900 1209600 300"},
				{Name: "@", Type: "NS", Value: "ns1.example.test."},
				{Name: "@", Type: "CNAME", Value: "target.example.test."},
			},
			check:   "@",
			wantErr: "cannot share the name \"example.test\"",
		},
		{
			name:    "unparseable owner is left to record validation",
			records: []Record{{Name: "www", Type: "CNAME", Value: "target.example.test."}},
			check:   strings.Repeat("a", 300),
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			current := Zone{Name: "example.test", DefaultTTL: 300, Records: test.records}
			err := CheckCNAMEExclusivity(current, test.check, now)
			if test.wantErr == "" {
				if err != nil {
					t.Fatalf("CheckCNAMEExclusivity() error = %v, want nil", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), test.wantErr) {
				t.Fatalf("CheckCNAMEExclusivity() error = %v, want substring %q", err, test.wantErr)
			}
		})
	}
}

func TestCNAMEConflictsListsOnlyServedViolations(t *testing.T) {
	t.Parallel()
	now := time.Now()
	current := Zone{Name: "example.test", DefaultTTL: 300, Records: []Record{
		{Name: "@", Type: "SOA", Value: "ns1.example.test. dns.example.test. 1 3600 900 1209600 300"},
		{Name: "@", Type: "NS", Value: "ns1.example.test."},
		{Name: "www", Type: "CNAME", Value: "target.example.test."},
		{Name: "www", Type: "AAAA", Value: "2001:db8::1"},
		{Name: "two", Type: "CNAME", Value: "one.example.test."},
		{Name: "two", Type: "CNAME", Value: "other.example.test."},
		{Name: "api", Type: "A", Value: "192.0.2.10"},
		{Name: "off", Type: "CNAME", Value: "target.example.test.", Disabled: true},
		{Name: "off", Type: "A", Value: "192.0.2.11"},
		{Name: "gone", Type: "CNAME", Value: "target.example.test."},
		{Name: "gone", Type: "A", Value: "192.0.2.12", ExpiresAt: now.Add(-time.Minute)},
	}}
	want := []string{"two.example.test", "www.example.test"}
	if got := CNAMEConflicts(current, now); !slices.Equal(got, want) {
		t.Fatalf("CNAMEConflicts() = %v, want %v", got, want)
	}
}
