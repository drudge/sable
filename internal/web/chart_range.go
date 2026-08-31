package web

import (
	"net/http"
	"strconv"
	"strings"
	"time"
)

const (
	dashboardChartRangeCookie = "sable_dashboard_chart_range"
	dashboardChartRangeMaxAge = 365 * 24 * time.Hour
)

type dashboardChartRange struct {
	Name       string
	Start, End time.Time
}

func dashboardChartRangeFromRequest(request *http.Request) dashboardChartRange {
	cookie, err := request.Cookie(dashboardChartRangeCookie)
	if err != nil {
		return dashboardChartRange{Name: "hour"}
	}
	if _, valid := chartDuration(cookie.Value); valid {
		return dashboardChartRange{Name: cookie.Value}
	}
	parts := strings.Split(cookie.Value, ":")
	if len(parts) != 3 || parts[0] != "custom" {
		return dashboardChartRange{Name: "hour"}
	}
	startUnix, startErr := strconv.ParseInt(parts[1], 10, 64)
	endUnix, endErr := strconv.ParseInt(parts[2], 10, 64)
	start := time.Unix(startUnix, 0)
	end := time.Unix(endUnix, 0)
	if startErr != nil || endErr != nil || !start.Before(end) {
		return dashboardChartRange{Name: "hour"}
	}
	return dashboardChartRange{Name: "custom", Start: start, End: end}
}

func (server *Server) rememberDashboardChartRange(
	writer http.ResponseWriter,
	request *http.Request,
	selected dashboardChartRange,
) {
	value := selected.Name
	if selected.Name == "custom" {
		value = "custom:" + strconv.FormatInt(selected.Start.Unix(), 10) + ":" + strconv.FormatInt(selected.End.Unix(), 10)
	}
	http.SetCookie(writer, &http.Cookie{
		Name: dashboardChartRangeCookie, Value: value, Path: "/",
		Expires: time.Now().Add(dashboardChartRangeMaxAge), MaxAge: int(dashboardChartRangeMaxAge / time.Second),
		HttpOnly: true, Secure: server.secureCookies || request.TLS != nil, SameSite: http.SameSiteStrictMode,
	})
}
