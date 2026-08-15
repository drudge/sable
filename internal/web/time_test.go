package web

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/drudge/sable/internal/web/pages"
)

func TestRequestTimeFormatDefaultsToTwelveHourAndAcceptsTwentyFourHour(t *testing.T) {
	t.Parallel()

	request := httptest.NewRequest("GET", "http://sable.test/", nil)
	if got := requestTimeFormat(request); got != pages.TimeFormat12 {
		t.Fatalf("default time format = %q, want 12", got)
	}
	request.AddCookie(&http.Cookie{Name: timeFormatCookie, Value: pages.TimeFormat24})
	if got := requestTimeFormat(request); got != pages.TimeFormat24 {
		t.Fatalf("cookie time format = %q, want 24", got)
	}
}

func TestRequestTimeLocationUsesBrowserZoneAndFallsBackToServerZone(t *testing.T) {
	t.Parallel()

	request := httptest.NewRequest("GET", "http://sable.test/", nil)
	if got := requestTimeLocation(request); got != time.Local {
		t.Fatalf("default location = %v, want the server zone", got)
	}
	request.AddCookie(&http.Cookie{Name: timeZoneCookie, Value: "America/New_York"})
	if got := requestTimeLocation(request); got.String() != "America/New_York" {
		t.Fatalf("cookie location = %v, want America/New_York", got)
	}
}

func TestRequestTimeLocationRejectsUnusableZoneNames(t *testing.T) {
	t.Parallel()

	for _, name := range []string{"", "Local", "../../etc/passwd", "/etc/localtime", "Mars/Olympus", "America/New York"} {
		request := httptest.NewRequest("GET", "http://sable.test/", nil)
		request.AddCookie(&http.Cookie{Name: timeZoneCookie, Value: name})
		if got := requestTimeLocation(request); got != time.Local {
			t.Fatalf("location for %q = %v, want the server zone", name, got)
		}
	}
}

func TestDisplayTimeHelpersHonorPreference(t *testing.T) {
	t.Parallel()

	value := time.Date(2026, time.August, 12, 21, 7, 6, 0, time.Local)
	if got := pages.FormatClock(value, pages.TimeDisplay{Format: pages.TimeFormat12}, true); got != "9:07:06 PM" {
		t.Fatalf("12-hour clock = %q", got)
	}
	if got := pages.FormatClock(value, pages.TimeDisplay{Format: pages.TimeFormat24}, true); got != "21:07:06" {
		t.Fatalf("24-hour clock = %q", got)
	}
}

func TestDisplayTimeHelpersRenderInTheBrowserZone(t *testing.T) {
	t.Parallel()

	eastern, err := time.LoadLocation("America/New_York")
	if err != nil {
		t.Fatalf("load America/New_York: %v", err)
	}
	display := pages.TimeDisplay{Format: pages.TimeFormat24, Location: eastern}
	value := time.Date(2026, time.August, 13, 1, 7, 6, 0, time.UTC)
	if got := pages.FormatClock(value, display, true); got != "21:07:06" {
		t.Fatalf("eastern clock = %q, want 21:07:06", got)
	}
	if got := pages.FormatDateTimeZoned(value, display); got != "Aug 12, 2026 21:07 EDT" {
		t.Fatalf("eastern timestamp = %q", got)
	}
	if got := display.Zone(); got != "America/New_York" {
		t.Fatalf("zone = %q", got)
	}
}
