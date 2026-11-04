package web

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/drudge/sable/internal/dnsserver"
	"github.com/drudge/sable/internal/web/pages"
)

// forwarderReporter is the part of the DNS handler that reports on and tests
// the forwarders. Each node answers for itself.
type forwarderReporter interface {
	ForwarderStats() []dnsserver.ForwarderStats
	TestForwarders(context.Context) []dnsserver.ForwarderTest
}

func (server *Server) forwarders() (forwarderReporter, bool) {
	reporter, ok := server.stats.(forwarderReporter)
	return reporter, ok
}

func (server *Server) forwardersCardView() pages.ForwardersCardView {
	reporter, ok := server.forwarders()
	if !ok {
		return pages.ForwardersCardView{}
	}
	view := pages.ForwardersCardView{Available: true}
	now := time.Now()
	for _, stats := range reporter.ForwarderStats() {
		view.Stats = append(view.Stats, forwarderStatView(stats, now))
	}
	return view
}

func forwarderStatView(stats dnsserver.ForwarderStats, now time.Time) pages.ForwarderStatView {
	view := pages.ForwarderStatView{
		Forwarder: stats.Forwarder, Route: stats.Route,
		Answered: stats.Answers, Timeouts: stats.Timeouts, Errors: stats.Errors,
		Median: "—", P95: "—", Status: "ok",
	}
	if stats.Samples > 0 {
		view.Median, view.P95 = formatResponseTime(stats.Median), formatResponseTime(stats.P95)
	}
	switch {
	case stats.Attempts == 0:
		view.Status = "idle"
	case !stats.CoolingUntil.IsZero() && stats.CoolingUntil.After(now):
		view.Status = "cooling"
	case stats.Answers == 0:
		view.Status = "failing"
	}
	if stats.LastError != "" {
		view.LastError = stats.LastError + " (" + formatApproximateDuration(now.Sub(stats.LastErrorAt)) + " ago)"
	}
	return view
}

// testForwarders asks every forwarder the test names from this node and
// shows how each answered.
func (server *Server) testForwarders(writer http.ResponseWriter, request *http.Request) {
	writer.Header().Set("Cache-Control", "no-store")
	reporter, ok := server.forwarders()
	if !ok {
		http.Error(writer, "forwarder tests are unavailable", http.StatusServiceUnavailable)
		return
	}
	var views []pages.ForwarderTestView
	for _, result := range reporter.TestForwarders(request.Context()) {
		view := pages.ForwarderTestView{
			Forwarder: result.Forwarder, Route: result.Route, OK: result.OK,
			ResponseCode: result.ResponseCode, Validates: result.Validates, Error: result.Error,
		}
		if result.Error == "" {
			view.ResponseTime = formatResponseTime(result.ResponseTime)
		}
		views = append(views, view)
	}
	server.render(writer, request, pages.ForwarderTestResults(views))
}

// formatResponseTime shows a response time to the precision that matters:
// tenths of a millisecond under 10 ms, whole milliseconds above.
func formatResponseTime(duration time.Duration) string {
	milliseconds := float64(duration) / float64(time.Millisecond)
	if milliseconds < 10 {
		return fmt.Sprintf("%.1f ms", milliseconds)
	}
	return fmt.Sprintf("%.0f ms", milliseconds)
}
