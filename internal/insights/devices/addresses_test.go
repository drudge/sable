package devices

import (
	"testing"
	"time"

	"github.com/drudge/sable/internal/insights/vendors"
	"github.com/drudge/sable/internal/querylog"
)

func TestIPv6AddressesBuiltFromHardwareNameIt(t *testing.T) {
	t.Parallel()
	for address, want := range map[string]string{
		"2001:db8::6652:99ff:fe14:1b32": "64:52:99:14:1b:32",
		"fe80::be24:11ff:fe5c:59c5":     "bc:24:11:5c:59:c5",
		"fd00::a6f8:ffff:fe7e:1faa":     "a4:f8:ff:7e:1f:aa",
		"2001:db8::c992:3721:76e3:c526": "",
		"2001:db8::1a":                  "",
		"10.0.0.5":                      "",
		"::ffff:10.0.0.5":               "",
		"ff02::1:ff14:1b32":             "",
		"not an address":                "",
		"2001:db8::0300:00ff:fe00:0001": "",
	} {
		mac, found := hardwareFromAddress(address)
		if mac != want || found != (want != "") {
			t.Errorf("hardwareFromAddress(%q) = %q, %v; want %q", address, mac, found, want)
		}
	}
}

func TestPrivacyAddressesAreTheRandomOnes(t *testing.T) {
	t.Parallel()
	for address, want := range map[string]bool{
		// Temporary and stable random identifiers, global and unique local.
		"2603:7083:af01:1500:c992:3721:76e3:c526": true,
		"2001:db8::599:a8b3:fec2:7fbf":            true,
		"fd3f:70cd:8865:4e13:1c28:7d75:9538:aa3c": true,
		// Built from hardware, assigned by hand or DHCPv6, or not global.
		"2001:db8::6652:99ff:fe14:1b32": false,
		"2001:db8::1a":                  false,
		"2001:db8::1:2":                 false,
		"fd00::5":                       false,
		"fe80::1095:e1e7:66d:fcbc":      false,
		"10.0.0.5":                      false,
		"::ffff:10.0.0.5":               false,
	} {
		if got := privacyAddress(address); got != want {
			t.Errorf("privacyAddress(%q) = %v, want %v", address, got, want)
		}
	}
}

// A device that builds its IPv6 address from its hardware address is tied to
// it with no sighting at all, joining whatever else was seen with that
// hardware. A sighting still outranks the address's own bits.
func TestBuildTiesIPv6AddressesToTheHardwareTheyAreBuiltFrom(t *testing.T) {
	t.Parallel()
	built := Build(Input{
		Activity: querylog.ClientActivityReport{Clients: []querylog.ClientActivity{
			{Client: "10.0.0.40", Queries: 60},
			{Client: "2001:db8::6652:99ff:fe14:1b32", Queries: 30},
			{Client: "2001:db8::2a39:5eff:fe4b:17c0", Queries: 20},
			{Client: "2001:db8::3252:53ff:fe04:951e", Queries: 10},
		}},
		Identities: []querylog.ClientIdentity{
			{Address: "10.0.0.40", MAC: "64:52:99:14:1b:32", Source: "unifi", Hostname: "Garage Opener", LastSeen: testNow},
			// The neighbor table knows better than the address's bits.
			{Address: "2001:db8::3252:53ff:fe04:951e", MAC: "aa:00:00:00:00:09", Source: "neighbor", LastSeen: testNow},
		},
	})
	byKey := map[string]Device{}
	for _, device := range built {
		byKey[device.Key] = device
	}
	if len(built) != 3 {
		t.Fatalf("devices = %+v", built)
	}
	opener := byKey["mac:64:52:99:14:1b:32"]
	if opener.Name != "Garage Opener" || len(opener.Addresses) != 2 || opener.Queries != 90 || opener.MACFromAddress {
		t.Fatalf("opener = %+v", opener)
	}
	tv := byKey["mac:28:39:5e:4b:17:c0"]
	wantVendor, _ := vendors.Lookup("28:39:5e:4b:17:c0")
	if !tv.Identified() || !tv.MACFromAddress || tv.Vendor != wantVendor || tv.PrivateMAC {
		t.Fatalf("tv = %+v", tv)
	}
	if sighted := byKey["mac:aa:00:00:00:00:09"]; sighted.MACFromAddress || len(sighted.Addresses) != 1 {
		t.Fatalf("sighted = %+v", sighted)
	}
	given := NewGivenNames([]querylog.ClientIdentity{
		{Address: "10.0.0.40", MAC: "64:52:99:14:1b:32", Source: "unifi", Hostname: "Garage Opener", LastSeen: testNow},
	}, nil)
	if name := given.Address("2001:db8::6652:99ff:fe14:1b32"); name != "Garage Opener" {
		t.Fatalf("given name of the built address = %q", name)
	}
}

// Phones and computers replace their IPv6 privacy addresses about once a day.
// When Sable cannot tie one to a device, its arrival and its silence are that
// routine, so neither is reported; the device shows up by its other addresses.
func TestChangesLeaveOutPrivacyAddressesNothingTies(t *testing.T) {
	t.Parallel()
	day := 24 * time.Hour
	old := testNow.Add(-30 * day)
	device := func(address string, firstSeen time.Time, queries, recent, baseline uint64) Device {
		return Device{Key: "ip:" + address, Queries: queries, Recent: recent, Baseline: baseline, FirstSeen: firstSeen,
			Addresses: []Address{{Address: address, Queries: queries}}}
	}
	findings := Changes(ChangesInput{
		Now: testNow, WindowStart: testNow.Add(-7 * day), SeenSince: testNow.Add(-60 * day),
		Devices: []Device{
			device("2001:db8::715d:2004:187e:18a2", testNow.Add(-2*day), 54, 20, 0),
			device("2001:db8::c992:3721:76e3:c526", testNow.Add(-8*day-time.Hour), 0, 0, 7*233),
			// An assigned address is no privacy address.
			device("2001:db8::1a", testNow.Add(-3*time.Hour), 12, 12, 0),
			// A name the operator gave an address makes it worth reporting.
			{Key: "ip:2001:db8::50e1:a2b5:d331:b01e", Named: true, Name: "Office printer", Queries: 44, FirstSeen: testNow.Add(-2 * day),
				Addresses: []Address{{Address: "2001:db8::50e1:a2b5:d331:b01e", Queries: 44}}},
			// A device tied to hardware still goes quiet by its privacy addresses.
			{Key: "mac:aa:00:00:00:00:02", MAC: "aa:00:00:00:00:02", Name: "Apple TV", FirstSeen: old, Recent: 0, Baseline: 7 * 1_240,
				Addresses: []Address{{Address: "2001:db8::8c99:8b11:366a:acfe"}}},
		},
	})
	reported := map[string]string{}
	for _, finding := range findings {
		reported[finding.Subject.Label] = finding.Kind
	}
	want := map[string]string{"2001:db8::1a": KindNewDevice, "Office printer": KindNewDevice, "Apple TV": KindWentQuiet}
	if len(reported) != len(want) {
		t.Fatalf("findings = %+v", findings)
	}
	for label, kind := range want {
		if reported[label] != kind {
			t.Errorf("finding for %s = %q, want %q", label, reported[label], kind)
		}
	}
}
