package web

import (
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"
)

func TestDashboardChartRangeUsesRememberedPreference(t *testing.T) {
	t.Run("preset", func(t *testing.T) {
		request := httptest.NewRequest(http.MethodGet, "/", nil)
		request.AddCookie(&http.Cookie{Name: dashboardChartRangeCookie, Value: "week"})

		selected := dashboardChartRangeFromRequest(request)
		if selected.Name != "week" {
			t.Fatalf("remembered range = %q, want week", selected.Name)
		}
	})

	t.Run("custom", func(t *testing.T) {
		start := time.Date(2026, time.August, 1, 14, 30, 0, 0, time.UTC)
		end := start.Add(90 * time.Minute)
		request := httptest.NewRequest(http.MethodGet, "/", nil)
		request.AddCookie(&http.Cookie{
			Name:  dashboardChartRangeCookie,
			Value: "custom:" + formatUnix(start) + ":" + formatUnix(end),
		})

		selected := dashboardChartRangeFromRequest(request)
		if selected.Name != "custom" || !selected.Start.Equal(start) || !selected.End.Equal(end) {
			t.Fatalf("remembered custom range = %+v, want %s through %s", selected, start, end)
		}
	})

	for _, value := range []string{"forever", "custom:nope:still-nope", "custom:2:1"} {
		t.Run("invalid_"+value, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodGet, "/", nil)
			request.AddCookie(&http.Cookie{Name: dashboardChartRangeCookie, Value: value})
			if selected := dashboardChartRangeFromRequest(request); selected.Name != "hour" {
				t.Fatalf("invalid preference %q restored %q, want hour", value, selected.Name)
			}
		})
	}
}

func TestRememberDashboardChartRangeSetsSecurePreferenceCookie(t *testing.T) {
	server := &Server{secureCookies: true}
	request := httptest.NewRequest(http.MethodGet, "/ui/stats/chart?range=custom", nil)
	response := httptest.NewRecorder()
	start := time.Date(2026, time.August, 1, 14, 30, 0, 0, time.UTC)
	end := start.Add(90 * time.Minute)

	server.rememberDashboardChartRange(response, request, dashboardChartRange{Name: "custom", Start: start, End: end})
	cookies := response.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatalf("preference cookie count = %d, want 1", len(cookies))
	}
	cookie := cookies[0]
	if cookie.Name != dashboardChartRangeCookie || cookie.Value != "custom:"+formatUnix(start)+":"+formatUnix(end) {
		t.Fatalf("preference cookie = %s=%q", cookie.Name, cookie.Value)
	}
	if !cookie.HttpOnly || !cookie.Secure || cookie.SameSite != http.SameSiteStrictMode || cookie.MaxAge <= 0 {
		t.Fatalf("preference cookie attributes = %+v", cookie)
	}
}

func formatUnix(value time.Time) string {
	return strconv.FormatInt(value.Unix(), 10)
}
