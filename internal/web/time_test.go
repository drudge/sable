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

func TestDisplayTimeHelpersHonorPreference(t *testing.T) {
	t.Parallel()

	value := time.Date(2026, time.August, 12, 21, 7, 6, 0, time.Local)
	if got := pages.FormatClock(value, pages.TimeFormat12, true); got != "9:07:06 PM" {
		t.Fatalf("12-hour clock = %q", got)
	}
	if got := pages.FormatClock(value, pages.TimeFormat24, true); got != "21:07:06" {
		t.Fatalf("24-hour clock = %q", got)
	}
}
