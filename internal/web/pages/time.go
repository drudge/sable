package pages

import "time"

const (
	TimeFormat12 = "12"
	TimeFormat24 = "24"
)

func FormatClock(value time.Time, preference string, seconds bool) string {
	if preference == TimeFormat24 {
		if seconds {
			return value.Local().Format("15:04:05")
		}
		return value.Local().Format("15:04")
	}
	if seconds {
		return value.Local().Format("3:04:05 PM")
	}
	return value.Local().Format("3:04 PM")
}

func FormatDateTime(value time.Time, preference string) string {
	if value.IsZero() {
		return "Never"
	}
	if preference == TimeFormat24 {
		return value.Local().Format("Jan 2, 2006 15:04")
	}
	return value.Local().Format("Jan 2, 2006 3:04 PM")
}

func FormatDateTimeZoned(value time.Time, preference string) string {
	if preference == TimeFormat24 {
		return value.Local().Format("Jan 2, 2006 15:04 MST")
	}
	return value.Local().Format("Jan 2, 2006 3:04 PM MST")
}

func FormatShortDateTime(value time.Time, preference string, seconds bool) string {
	if preference == TimeFormat24 {
		if seconds {
			return value.Local().Format("1/2 15:04:05")
		}
		return value.Local().Format("Jan 2, 15:04")
	}
	if seconds {
		return value.Local().Format("1/2 3:04:05 PM")
	}
	return value.Local().Format("Jan 2, 3:04 PM")
}

func FormatRuntimeLogTime(value time.Time, preference string) string {
	if preference == TimeFormat24 {
		return value.Local().Format("2006-01-02 15:04:05.000")
	}
	return value.Local().Format("2006-01-02 3:04:05.000 PM")
}
