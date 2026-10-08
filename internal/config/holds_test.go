package config

import (
	"strings"
	"testing"
	"time"
)

func TestHoldsValidateAndNormalize(t *testing.T) {
	t.Parallel()
	until := time.Date(2026, 10, 8, 20, 0, 0, 0, time.FixedZone("EDT", -4*3600))
	configuration := Defaults()
	configuration.Blocking.Holds = []Hold{
		{Address: "::ffff:10.0.0.7", Until: until},
		{MAC: "DA-A1-19-00-00-01"},
	}
	configuration.normalize()
	if err := configuration.Validate(); err != nil {
		t.Fatal(err)
	}
	holds := configuration.Blocking.Holds
	if holds[0].Address != "10.0.0.7" || !holds[0].Until.Equal(until) || holds[1].MAC != "da:a1:19:00:00:01" || !holds[1].Until.IsZero() {
		t.Fatalf("normalized holds = %+v", holds)
	}

	for _, test := range []struct {
		change func(*Config)
		want   string
	}{
		{func(c *Config) { c.Blocking.Holds = append(c.Blocking.Holds, Hold{}) }, "blocking.holds[2] must set mac or address"},
		{func(c *Config) { c.Blocking.Holds[0].MAC = "da:a1:19:00:00:02" }, "not both"},
		{func(c *Config) { c.Blocking.Holds[1].MAC = "tablet" }, "blocking.holds[1].mac must be a hardware address"},
		{func(c *Config) { c.Blocking.Holds = append(c.Blocking.Holds, Hold{Address: "10.0.0.7"}) }, "holds the same device as blocking.holds[0]"},
	} {
		candidate := cloneConfig(configuration)
		test.change(&candidate)
		if err := candidate.Validate(); err == nil || !strings.Contains(err.Error(), test.want) {
			t.Errorf("Validate() error = %v, want %q", err, test.want)
		}
	}
}

func TestSetHoldReplacesHoldsAndDropsEndedOnes(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 10, 8, 18, 0, 0, 0, time.UTC)
	holds := []Hold{
		{MAC: "da:a1:19:00:00:01", Until: now.Add(30 * time.Minute)},
		{Address: "10.0.0.9", Until: now.Add(-time.Minute)},
	}
	updated, err := SetHold(holds, Client{MAC: "DA:A1:19:00:00:01"}, now.Add(time.Hour), now)
	if err != nil {
		t.Fatal(err)
	}
	if len(updated) != 1 || !updated[0].Until.Equal(now.Add(time.Hour)) {
		t.Fatalf("SetHold() = %+v, want one hold for an hour", updated)
	}
	if holds[0].Until != now.Add(30*time.Minute) {
		t.Fatal("SetHold changed the holds it was given")
	}
	if hold, found := HoldFor(updated, Client{MAC: "da:a1:19:00:00:01"}, now); !found || !hold.Until.Equal(now.Add(time.Hour)) {
		t.Fatalf("HoldFor() = %+v %v", hold, found)
	}
	if _, found := HoldFor(holds, Client{Address: "10.0.0.9"}, now); found {
		t.Fatal("HoldFor() found a hold that ended")
	}
	updated, err = SetHold(updated, Client{Address: "::ffff:10.0.0.8"}, time.Time{}, now)
	if err != nil || len(updated) != 2 || updated[1].Address != "10.0.0.8" {
		t.Fatalf("SetHold() until removed = %+v, %v", updated, err)
	}
	for _, test := range []struct {
		device Client
		until  time.Time
		want   string
	}{
		{Client{}, time.Time{}, "must set mac or address"},
		{Client{MAC: "tablet"}, time.Time{}, "hardware address"},
		{Client{Address: "10.0.0.8"}, now, "must end in the future"},
	} {
		if _, err := SetHold(nil, test.device, test.until, now); err == nil || !strings.Contains(err.Error(), test.want) {
			t.Errorf("SetHold(%+v) error = %v, want %q", test.device, err, test.want)
		}
	}

	remaining, ended := EndHold(updated, Client{MAC: "da:a1:19:00:00:01"}, now)
	if !ended || len(remaining) != 1 || remaining[0].Address != "10.0.0.8" {
		t.Fatalf("EndHold() = %+v %v", remaining, ended)
	}
	if _, ended := EndHold(remaining, Client{MAC: "da:a1:19:00:00:01"}, now); ended {
		t.Fatal("EndHold() ended a hold that was already gone")
	}
}
