package zone

import "testing"

func serialZone(kind, serial string) Zone {
	return Zone{Name: "example.com", Type: kind, Records: []Record{
		{Name: "@", Type: "SOA", TTL: 300, Value: "ns1.example.com. hostmaster.example.com. " + serial + " 3600 600 604800 300"},
	}}
}

func TestAdvanceSerialByWrapsInSerialArithmetic(t *testing.T) {
	for _, test := range []struct{ from, want string }{
		{"2026110804", "2026110904"},
		{"4294967290", "94"},
	} {
		current := serialZone("primary", test.from)
		AdvanceSerialBy(&current, 100)
		want := serialZone("primary", test.want).Records[0].Value
		if current.Records[0].Value != want {
			t.Fatalf("AdvanceSerialBy(%s) = %q, want %q", test.from, current.Records[0].Value, want)
		}
	}
}

func TestOwnsSerialExcludesTransferredZones(t *testing.T) {
	for kind, want := range map[string]bool{
		"primary": true, "forwarder": true, "alias": true, "catalog": true,
		"secondary": false, TypeSecondaryForwarder: false, "stub": false,
	} {
		if got := OwnsSerial(Zone{Type: kind}); got != want {
			t.Fatalf("OwnsSerial(%s) = %t, want %t", kind, got, want)
		}
	}
	consumer := Zone{Type: "catalog", PrimaryServers: []string{"192.0.2.1"}}
	if OwnsSerial(consumer) {
		t.Fatal("OwnsSerial(consumer catalog) = true, want false")
	}
}
