package weekly

import (
	"testing"
	"time"
)

func TestWindowAt(t *testing.T) {
	t.Parallel()
	newYork, err := time.LoadLocation("America/New_York")
	if err != nil {
		t.Fatal(err)
	}
	at := func(month time.Month, day, hour, minute int) time.Time {
		return time.Date(2026, month, day, hour, minute, 0, 0, newYork)
	}
	bedtime := Window{Days: [7]bool{true, true, true, true, true}, Start: 21 * 60, End: 7 * 60, Location: newYork}
	everyNight := Window{Days: [7]bool{true, true, true, true, true, true, true}, Start: 21 * 60, End: 7 * 60, Location: newYork}
	homework := Window{Days: [7]bool{time.Monday: true}, Start: 15*60 + 30, End: 17*60 + 30, Location: newYork}
	for _, test := range []struct {
		name        string
		window      Window
		now         time.Time
		on          bool
		from, until time.Time
	}{
		{"Monday night", bedtime, at(10, 12, 22, 0), true, at(10, 12, 21, 0), at(10, 13, 7, 0)},
		{"the start counts", bedtime, at(10, 12, 21, 0), true, at(10, 12, 21, 0), at(10, 13, 7, 0)},
		{"the end doesn't", bedtime, at(10, 13, 7, 0), false, at(10, 13, 7, 0), at(10, 13, 21, 0)},
		{"Thursday night runs into Friday", bedtime, at(10, 16, 6, 59), true, at(10, 15, 21, 0), at(10, 16, 7, 0)},
		{"Friday night is off", bedtime, at(10, 16, 22, 0), false, at(10, 16, 7, 0), at(10, 18, 21, 0)},
		{"Saturday is off", bedtime, at(10, 17, 3, 0), false, at(10, 16, 7, 0), at(10, 18, 21, 0)},
		{"same-day window", homework, at(10, 12, 16, 0), true, at(10, 12, 15, 30), at(10, 12, 17, 30)},
		{"a week until the next one", homework, at(10, 12, 18, 0), false, at(10, 12, 17, 30), at(10, 19, 15, 30)},
		// Clocks fall back at 2:00 on November 1, so that night is an hour longer.
		{"daylight saving ends", everyNight, at(11, 1, 1, 30), true, at(10, 31, 21, 0), at(11, 1, 7, 0)},
		// And spring forward at 2:00 on March 8, an hour shorter.
		{"daylight saving starts", everyNight, at(3, 8, 4, 0), true, at(3, 7, 21, 0), at(3, 8, 7, 0)},
	} {
		on, from, until := test.window.At(test.now)
		if on != test.on || !from.Equal(test.from) || !until.Equal(test.until) {
			t.Errorf("%s: At(%s) = %t from %s until %s, want %t from %s until %s", test.name, test.now, on, from, until, test.on, test.from, test.until)
		}
	}
	if on, from, until := everyNight.At(at(11, 1, 1, 30)); !on || until.Sub(from) != 11*time.Hour {
		t.Errorf("the night clocks fall back lasts %s, want 11h", until.Sub(from))
	}
	if on, from, until := everyNight.At(at(3, 8, 4, 0)); !on || until.Sub(from) != 9*time.Hour {
		t.Errorf("the night clocks spring forward lasts %s, want 9h", until.Sub(from))
	}
}
