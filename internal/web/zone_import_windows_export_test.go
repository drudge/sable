package web

import (
	"slices"
	"strings"
	"testing"

	zonemodel "github.com/drudge/sable/internal/zone"
)

const windowsExportFixture = `;
;  Database file example.test.dns for example.test zone.
;      Zone version:  98765
;

@                       IN  SOA dc1.example.test.  hostmaster.example.test. (
                                98765        ; serial number
                                900          ; refresh
                                600          ; retry
                                86400        ; expire
                                3600       ) ; default TTL

@                       NS	dc1.example.test.
@                       [AGE:3794565]	600	A	192.0.2.10
@                       WINS	L1 C900 ( 192.0.2.40
                                192.0.2.41 )
_msdcs                  NS	dc1.example.test.
_kerberos._tcp          [AGE:3794565]	600	SRV	0 100 88	dc1.example.test.
dc1                     A	192.0.2.10
wins                    CNAME	dc1
alias                   CNAME	wins
`

func TestCleanWindowsZoneExport(t *testing.T) {
	t.Parallel()

	cleaned, skipped := cleanWindowsZoneExport(windowsExportFixture)
	if strings.Contains(cleaned, "[AGE:") || strings.Contains(cleaned, "WINS") || strings.Contains(cleaned, "192.0.2.41") {
		t.Fatalf("cleaned export still holds Windows-only text:\n%s", cleaned)
	}
	if !slices.Equal(skipped, []string{"@"}) {
		t.Fatalf("skipped = %v", skipped)
	}
	if strings.Count(cleaned, "\n") != strings.Count(windowsExportFixture, "\n") {
		t.Fatal("cleanup changed line numbers, so parse errors would point at the wrong line")
	}
	zone := zonemodel.Zone{Name: "example.test", Type: "primary", DefaultTTL: 300}
	records, _, err := parseZoneFile(zone, strings.NewReader(cleaned))
	if err != nil {
		t.Fatal(err)
	}
	for _, expected := range []zonemodel.Record{
		{Name: "@", Type: "A", Value: "192.0.2.10", TTL: 600},
		{Name: "_kerberos._tcp", Type: "SRV", Value: "0 100 88 dc1.example.test.", TTL: 600},
		{Name: "dc1", Type: "A", Value: "192.0.2.10", TTL: 3600},
		{Name: "wins", Type: "CNAME", Value: "dc1.example.test.", TTL: 3600},
		{Name: "alias", Type: "CNAME", Value: "wins.example.test.", TTL: 3600},
	} {
		if !slices.Contains(records, expected) {
			t.Errorf("records do not contain %#v: %#v", expected, records)
		}
	}
}

func TestCleanWindowsZoneExportLeavesOtherFilesAlone(t *testing.T) {
	t.Parallel()

	contents := "$ORIGIN example.test.\nwins 300 IN TXT \"WINS [AGE:1]\" ; WINS\n\t300 IN A 192.0.2.1\n"
	cleaned, skipped := cleanWindowsZoneExport(contents)
	if cleaned != contents || len(skipped) != 0 {
		t.Fatalf("cleanup changed a file without Windows records: %q skipped %v", cleaned, skipped)
	}
}

func TestImportedZoneNameFromWindowsHeader(t *testing.T) {
	t.Parallel()

	name, err := importedZoneName("", windowsExportFixture)
	if err != nil || name != "example.test" {
		t.Fatalf("importedZoneName() = %q, %v", name, err)
	}
	if name, err := importedZoneName("other.test", windowsExportFixture); err != nil || name != "other.test" {
		t.Fatalf("a typed zone name lost to the Windows header: %q, %v", name, err)
	}
}
