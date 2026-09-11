package zone

import (
	"reflect"
	"testing"
	"time"
)

func TestConvertPrimaryPreservesIdentityRecordsAndPolicy(t *testing.T) {
	current := validManagerZone()
	current.ID = "stable-zone-id"
	current.Type = "secondary"
	current.Revision = 17
	current.PrimaryServers = []string{"192.0.2.1:53"}
	current.PrimaryProtocol = "tcp"
	current.TSIGKey = "transfer-key."
	current.ZoneTransfer = "acl"
	current.TransferACL = []string{"192.0.2.2"}
	current.Notify = []string{"192.0.2.2:53"}
	current.Records[2].Comments = "keep this"
	before := Clone([]Zone{current})[0]
	if err := ConvertToPrimary(&current, time.Now()); err != nil {
		t.Fatal(err)
	}
	if current.Type != "primary" || current.PrimaryServers != nil || current.PrimaryProtocol != "" {
		t.Fatalf("conversion = %+v", current)
	}
	if current.Records[0].Value == before.Records[0].Value {
		t.Fatal("serial did not advance")
	}
	current.Type = before.Type
	current.PrimaryServers = before.PrimaryServers
	current.PrimaryProtocol = before.PrimaryProtocol
	current.Records[0].Value = before.Records[0].Value
	if !reflect.DeepEqual(current, before) {
		t.Fatalf("conversion altered retained fields: %+v", current)
	}
}

func TestPrimaryConversionRejectsUnsupportedZonesWithoutMutation(t *testing.T) {
	tests := map[string]func(*Zone){
		"primary":          func(z *Zone) { z.Type = "primary" },
		"catalog member":   func(z *Zone) { z.CatalogZone = "catalog.test" },
		"catalog identity": func(z *Zone) { z.CatalogMemberID = "member" },
		"signing enabled":  func(z *Zone) { z.DNSSEC = true },
		"no SOA":           func(z *Zone) { z.Records = z.Records[1:] },
	}
	for _, kind := range []string{"DNSKEY", "RRSIG", "NSEC", "NSEC3", "NSEC3PARAM", "CDNSKEY", "CDS"} {
		tests[kind] = func(z *Zone) { z.Records = append(z.Records, Record{Type: kind, Disabled: true}) }
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			current := validManagerZone()
			current.Type = "secondary"
			mutate(&current)
			before := Clone([]Zone{current})[0]
			if err := ConvertToPrimary(&current, time.Now()); err == nil {
				t.Fatal("unsupported conversion succeeded")
			}
			if !reflect.DeepEqual(current, before) {
				t.Fatal("rejected conversion changed zone")
			}
		})
	}
	// Child delegation DS records do not make an unsigned parent signed.
	current := validManagerZone()
	current.Type = "secondary"
	current.Records = append(current.Records, Record{Name: "child", Type: "DS"})
	if err := CheckPrimaryConversion(current); err != nil {
		t.Fatal(err)
	}
}

func TestConversionFingerprintDetectsSameSerialChanges(t *testing.T) {
	current := validManagerZone()
	original := ConversionFingerprint(current)
	current.Records[2].Value = "192.0.2.42"
	if ConversionFingerprint(current) == original {
		t.Fatal("record change did not invalidate review")
	}
	current = validManagerZone()
	current.ID = "replacement"
	if ConversionFingerprint(current) == original {
		t.Fatal("identity change did not invalidate review")
	}
}
