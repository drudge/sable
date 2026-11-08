package zone

import (
	"testing"
	"time"
)

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

func TestAdvanceSerialPastClearsTheDisplacedSerial(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	for _, test := range []struct {
		from  string
		floor uint32
		want  string
	}{
		{"2026110805", 2026110807, "2026110808"},
		{"2026110809", 2026110807, "2026110810"},
		// 5 is past 4294967290 once the serial wraps, so the date serial
		// follows it rather than 4294967291.
		{"4294967290", 5, "2026010101"},
		{"5", 4294967290, "2026010101"},
	} {
		current := serialZone("primary", test.from)
		AdvanceSerialPast(&current, test.floor, now)
		want := serialZone("primary", test.want).Records[0].Value
		if current.Records[0].Value != want {
			t.Fatalf("AdvanceSerialPast(%s, %d) = %q, want %q", test.from, test.floor, current.Records[0].Value, want)
		}
	}
}

func TestSerialReadsTheApexSOA(t *testing.T) {
	if serial, ok := Serial(serialZone("primary", "2026110807")); !ok || serial != 2026110807 {
		t.Fatalf("Serial() = %d, %t, want 2026110807, true", serial, ok)
	}
	if _, ok := Serial(Zone{Name: "example.com"}); ok {
		t.Fatal("Serial(no SOA) ok = true, want false")
	}
}
