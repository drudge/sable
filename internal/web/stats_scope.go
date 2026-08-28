package web

import (
	"net/http"
	"time"

	"github.com/drudge/sable/internal/web/pages"
)

const (
	dashboardStatsScopeCookie = "sable_dashboard_stats_scope"
	dashboardStatsScopeMaxAge = 365 * 24 * time.Hour
)

func dashboardStatsScope(request *http.Request) string {
	if scope := request.URL.Query().Get("stats_scope"); validDashboardStatsScope(scope) {
		return scope
	}
	cookie, err := request.Cookie(dashboardStatsScopeCookie)
	if err == nil && validDashboardStatsScope(cookie.Value) {
		return cookie.Value
	}
	return pages.StatsScopeAll
}

func (server *Server) rememberDashboardStatsScope(writer http.ResponseWriter, request *http.Request) {
	if request.URL.Query().Get("remember_scope") != "1" {
		return
	}
	scope := request.URL.Query().Get("stats_scope")
	if !validDashboardStatsScope(scope) {
		return
	}
	http.SetCookie(writer, &http.Cookie{
		Name: dashboardStatsScopeCookie, Value: scope, Path: "/",
		Expires: time.Now().Add(dashboardStatsScopeMaxAge), MaxAge: int(dashboardStatsScopeMaxAge / time.Second),
		HttpOnly: true, Secure: server.secureCookies || request.TLS != nil, SameSite: http.SameSiteStrictMode,
	})
}

func validDashboardStatsScope(scope string) bool {
	return scope == pages.StatsScopeAll || scope == pages.StatsScopeRange
}
