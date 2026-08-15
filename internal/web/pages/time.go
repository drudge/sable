package pages

import "time"

const (
	TimeFormat12 = "12"
	TimeFormat24 = "24"
)

// TimeDisplay carries the console preferences used to render timestamps. The
// location comes from the browser so times match the operator's clock even when
// the server runs in UTC.
type TimeDisplay struct {
	Format   string
	Location *time.Location
}

func (display TimeDisplay) In(value time.Time) time.Time {
	if display.Location == nil {
		return value.Local()
	}
	return value.In(display.Location)
}

func (display TimeDisplay) TwentyFourHour() bool {
	return display.Format == TimeFormat24
}

// Zone names the timezone timestamps are rendered in, e.g. "America/New_York".
func (display TimeDisplay) Zone() string {
	if display.Location == nil {
		return time.Local.String()
	}
	return display.Location.String()
}

func FormatClock(value time.Time, display TimeDisplay, seconds bool) string {
	if display.TwentyFourHour() {
		if seconds {
			return display.In(value).Format("15:04:05")
		}
		return display.In(value).Format("15:04")
	}
	if seconds {
		return display.In(value).Format("3:04:05 PM")
	}
	return display.In(value).Format("3:04 PM")
}

func FormatDateTime(value time.Time, display TimeDisplay) string {
	if value.IsZero() {
		return "Never"
	}
	if display.TwentyFourHour() {
		return display.In(value).Format("Jan 2, 2006 15:04")
	}
	return display.In(value).Format("Jan 2, 2006 3:04 PM")
}

func FormatDateTimeZoned(value time.Time, display TimeDisplay) string {
	if display.TwentyFourHour() {
		return display.In(value).Format("Jan 2, 2006 15:04 MST")
	}
	return display.In(value).Format("Jan 2, 2006 3:04 PM MST")
}

func FormatShortDateTime(value time.Time, display TimeDisplay, seconds bool) string {
	if display.TwentyFourHour() {
		if seconds {
			return display.In(value).Format("1/2 15:04:05")
		}
		return display.In(value).Format("Jan 2, 15:04")
	}
	if seconds {
		return display.In(value).Format("1/2 3:04:05 PM")
	}
	return display.In(value).Format("Jan 2, 3:04 PM")
}

func FormatRuntimeLogTime(value time.Time, display TimeDisplay) string {
	if display.TwentyFourHour() {
		return display.In(value).Format("2006-01-02 15:04:05.000")
	}
	return display.In(value).Format("2006-01-02 3:04:05.000 PM")
}
