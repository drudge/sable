package config

import (
	"slices"
	"strings"
	"testing"
	"time"
)

// A watch written by hand loads tidied: domains in the form blocking rules
// use, devices in one spelling each, the default result and quiet time, and
// an ID that stays the same on every load.
func TestAWatchWrittenByHandLoadsTidied(t *testing.T) {
	t.Parallel()
	text := `
[[alerts.watches]]
name = " Kids' games "
domains = ["Roblox.COM.", "discord.com", "roblox.com", "bücher.example"]
devices = ["MAC:AA:BB:CC:DD:EE:FF", "ip:::ffff:10.0.7.20", " 10.0.8.0/24 ", "10.0.8.9/24", "::ffff:10.0.9.0/120"]
result = "ANY"
enabled = true
`
	loaded, err := Decode(strings.NewReader(text))
	if err != nil {
		t.Fatal(err)
	}
	if len(loaded.Alerts.Watches) != 1 {
		t.Fatalf("watches = %+v", loaded.Alerts.Watches)
	}
	watch := loaded.Alerts.Watches[0]
	if watch.Name != "Kids' games" || !watch.Enabled || watch.Result != "" || watch.Quiet.Duration != time.Hour {
		t.Fatalf("watch = %+v", watch)
	}
	if want := []string{"roblox.com", "discord.com", "xn--bcher-kva.example"}; !slices.Equal(watch.Domains, want) {
		t.Fatalf("domains = %v, want %v", watch.Domains, want)
	}
	if want := []string{"mac:aa:bb:cc:dd:ee:ff", "ip:10.0.7.20", "10.0.8.0/24", "10.0.9.0/24"}; !slices.Equal(watch.Devices, want) {
		t.Fatalf("devices = %v, want %v", watch.Devices, want)
	}
	if watch.ID == "" {
		t.Fatal("no ID")
	}
	again, err := Decode(strings.NewReader(text))
	if err != nil || again.Alerts.Watches[0].ID != watch.ID {
		t.Fatalf("reloaded ID = %q, want %q (%v)", again.Alerts.Watches[0].ID, watch.ID, err)
	}
	if !loaded.Alerts.Send.Watches {
		t.Fatal("the watches alert type is off by default")
	}
}

func TestWatchesThatCannotWorkAreRefused(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name  string
		watch string
		want  string
	}{
		{"no domains", `domains = []`, "needs at least one domain"},
		{"a bad domain", `domains = ["not a domain"]`, "is not a domain name"},
		{"an address for a domain", `domains = ["10.0.7.1"]`, "is not a domain name"},
		{"a bad device", `domains = ["example.com"]
devices = ["the kitchen"]`, "is not a device"},
		{"a bad hardware address", `domains = ["example.com"]
devices = ["mac:zz"]`, "is not a device"},
		{"a bad result", `domains = ["example.com"]
result = "sometimes"`, "result must be"},
		{"too short a quiet time", `domains = ["example.com"]
quiet = "30s"`, "between 1 minute and 24 hours"},
		{"too long a quiet time", `domains = ["example.com"]
quiet = "48h"`, "between 1 minute and 24 hours"},
		{"a bad ID", `id = "not/ok"
domains = ["example.com"]`, "letters, digits"},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			_, err := Decode(strings.NewReader("[[alerts.watches]]\n" + test.watch + "\n"))
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("error = %v, want %q", err, test.want)
			}
		})
	}
	var duplicate strings.Builder
	for range 2 {
		duplicate.WriteString("[[alerts.watches]]\nid = \"same\"\ndomains = [\"example.com\"]\n")
	}
	if _, err := Decode(strings.NewReader(duplicate.String())); err == nil || !strings.Contains(err.Error(), "used by another watch") {
		t.Fatalf("duplicate IDs: %v", err)
	}
	if err := validateAlertWatches(make([]AlertWatch, MaximumAlertWatches+1)); err == nil {
		t.Fatal("more watches than the limit were accepted")
	}
}

func TestAWatchCoversItsDevices(t *testing.T) {
	t.Parallel()
	watch := AlertWatch{Devices: []string{"mac:aa:bb:cc:dd:ee:ff", "ip:10.0.7.20", "10.0.7.30", "10.0.8.0/24", "fe80::1"}}
	for _, test := range []struct {
		device, address string
		want            bool
	}{
		{"mac:aa:bb:cc:dd:ee:ff", "10.0.7.99", true},
		{"mac:11:22:33:44:55:66", "10.0.7.99", false},
		{"ip:10.0.7.20", "10.0.7.20", true},
		{"mac:11:22:33:44:55:66", "10.0.7.20", true},
		{"ip:10.0.7.30", "10.0.7.30", true},
		{"ip:10.0.8.44", "10.0.8.44", true},
		{"ip:10.0.9.44", "10.0.9.44", false},
		{"ip:fe80::1%eth0", "fe80::1%eth0", true},
	} {
		if got := watch.Covers(test.device, test.address); got != test.want {
			t.Errorf("Covers(%q, %q) = %v, want %v", test.device, test.address, got, test.want)
		}
	}
	if !(AlertWatch{}).Covers("ip:10.0.7.1", "10.0.7.1") {
		t.Error("a watch with no devices does not cover every device")
	}
}

func TestAWatchAlertsOnTheResultsItAsksFor(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		result           string
		allowed, blocked bool
	}{
		{"", true, true},
		{AlertWatchAllowed, true, false},
		{AlertWatchBlocked, false, true},
	} {
		watch := AlertWatch{Result: test.result}
		if watch.Allows(false) != test.allowed || watch.Allows(true) != test.blocked {
			t.Errorf("result %q: allowed %v, blocked %v", test.result, watch.Allows(false), watch.Allows(true))
		}
	}
}
