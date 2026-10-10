// Package weekly works out whether a window that repeats each week, such as
// a bedtime, is on.
package weekly

import "time"

// Window starts at Start on each of its Days and ends at End: the same day,
// or the next one when End is at or before Start. Start and End are minutes
// past midnight, read in Location, so a window keeps its clock times across
// daylight saving changes.
type Window struct {
	Days       [7]bool
	Start, End int
	Location   *time.Location
}

// At works out whether the window is on at now, and the span around now
// that answer holds for: the window now is in, or the gap between the window
// before and the one after. A window with no days is off for the two weeks
// around now.
func (window Window) At(now time.Time) (on bool, from, until time.Time) {
	local := now.In(window.Location)
	today := time.Date(local.Year(), local.Month(), local.Day(), 0, 0, 0, 0, window.Location)
	from = now.Add(-7 * 24 * time.Hour)
	until = now.Add(8 * 24 * time.Hour)
	// A window that crosses midnight started the day before, so the search
	// starts a week back to find the end of the last one.
	for offset := -7; offset <= 7; offset++ {
		day := today.AddDate(0, 0, offset)
		if !window.Days[day.Weekday()] {
			continue
		}
		start, end := window.span(day)
		switch {
		case !now.Before(start) && now.Before(end):
			return true, start, end
		case !end.After(now) && end.After(from):
			from = end
		case start.After(now) && start.Before(until):
			until = start
		}
	}
	return false, from, until
}

// span is the window that starts on day.
func (window Window) span(day time.Time) (start, end time.Time) {
	start = window.at(day, window.Start)
	if window.End <= window.Start {
		day = day.AddDate(0, 0, 1)
	}
	return start, window.at(day, window.End)
}

func (window Window) at(day time.Time, minutes int) time.Time {
	return time.Date(day.Year(), day.Month(), day.Day(), minutes/60, minutes%60, 0, 0, window.Location)
}
