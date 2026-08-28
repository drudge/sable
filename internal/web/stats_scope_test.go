package web

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/drudge/sable/internal/web/pages"
)

func TestDashboardStatsScopeUsesQueryThenRememberedPreference(t *testing.T) {
	request := httptest.NewRequest(http.MethodGet, "/?stats_scope="+pages.StatsScopeRange, nil)
	request.AddCookie(&http.Cookie{Name: dashboardStatsScopeCookie, Value: pages.StatsScopeAll})
	if got := dashboardStatsScope(request); got != pages.StatsScopeRange {
		t.Fatalf("query scope = %q, want %q", got, pages.StatsScopeRange)
	}

	request = httptest.NewRequest(http.MethodGet, "/", nil)
	request.AddCookie(&http.Cookie{Name: dashboardStatsScopeCookie, Value: pages.StatsScopeRange})
	if got := dashboardStatsScope(request); got != pages.StatsScopeRange {
		t.Fatalf("remembered scope = %q, want %q", got, pages.StatsScopeRange)
	}

	request = httptest.NewRequest(http.MethodGet, "/?stats_scope=unexpected", nil)
	if got := dashboardStatsScope(request); got != pages.StatsScopeAll {
		t.Fatalf("invalid scope = %q, want default %q", got, pages.StatsScopeAll)
	}
}

func TestRememberDashboardStatsScopeSetsSecurePreferenceCookie(t *testing.T) {
	server := &Server{secureCookies: true}
	request := httptest.NewRequest(http.MethodGet, "/ui/stats/chart?range=day&stats_scope=range&remember_scope=1", nil)
	response := httptest.NewRecorder()

	server.rememberDashboardStatsScope(response, request)
	cookies := response.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatalf("preference cookie count = %d, want 1", len(cookies))
	}
	cookie := cookies[0]
	if cookie.Name != dashboardStatsScopeCookie || cookie.Value != pages.StatsScopeRange {
		t.Fatalf("preference cookie = %s=%q", cookie.Name, cookie.Value)
	}
	if !cookie.HttpOnly || !cookie.Secure || cookie.SameSite != http.SameSiteStrictMode || cookie.MaxAge <= 0 {
		t.Fatalf("preference cookie attributes = %+v", cookie)
	}
}
