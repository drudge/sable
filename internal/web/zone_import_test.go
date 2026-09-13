package web

import (
	"strings"
	"testing"
	"time"

	zonemodel "github.com/drudge/sable/internal/zone"
)

func TestImportSOAOwnerWithoutTrailingDot(t *testing.T) {
	for _, owner := range []string{"example.test", "EXAMPLE.TEST", "example.test.", "@"} {
		t.Run(owner, func(t *testing.T) {
			zone := zonemodel.Zone{Name: "example.test", Type: "primary", DefaultTTL: 300}
			contents := owner + "\t3600\tIN\tSOA\tns.example.test. hostmaster.example.test. 1 3600 600 86400 300\n" +
				"example.test. 3600 IN NS ns.example.test.\n" +
				"www 300 IN A 192.0.2.1\n" +
				"alias 300 IN CNAME www\n"
			records, _, err := parseZoneFile(zone, strings.NewReader(contents))
			if err != nil {
				t.Fatal(err)
			}
			if records[0].Name != "@" || records[2].Name != "www" || records[3].Value != "www.example.test." {
				t.Fatalf("unexpected imported records: %#v", records)
			}
			if err := mergeImportedRecords(&zone, records, true, true, true, time.Now()); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestImportStillRequiresApexSOA(t *testing.T) {
	zone := zonemodel.Zone{Name: "example.test", Type: "primary", DefaultTTL: 300}
	records, _, err := parseZoneFile(zone, strings.NewReader("child 300 IN SOA ns.example.test. hostmaster.example.test. 1 3600 600 86400 300\n@ 300 IN NS ns.example.test.\n"))
	if err != nil {
		t.Fatal(err)
	}
	if err := mergeImportedRecords(&zone, records, true, true, true, time.Now()); err == nil {
		t.Fatal("replacement accepted a non-apex SOA")
	}
}
