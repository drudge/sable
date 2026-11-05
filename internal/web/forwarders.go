package web

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/drudge/sable/internal/config"
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

// forwarderEditorView builds the DNS Forwarders list from the saved
// forwarders, joined with this node's stats and any test results, keyed by
// route and forwarder.
func (server *Server) forwarderEditorView(saved []string, tests map[[2]string]pages.ForwarderTestView) pages.ForwarderEditorView {
	view := pages.ForwarderEditorView{Text: strings.Join(saved, "\n"), Tested: tests != nil}
	now := time.Now()
	stats := make(map[[2]string]pages.ForwarderStatView)
	if reporter, ok := server.forwarders(); ok {
		view.Stats = true
		for _, entry := range reporter.ForwarderStats() {
			stat := forwarderStatView(entry, now)
			if test, found := tests[[2]string{entry.Route, entry.Forwarder}]; found {
				stat.Test = &test
			}
			if entry.Route != "" {
				view.Routes = append(view.Routes, stat)
				continue
			}
			stats[[2]string{"", entry.Forwarder}] = stat
		}
	}
	for _, forwarder := range saved {
		stat, found := stats[[2]string{"", forwarder}]
		if !found {
			// Saved but not running yet, such as on a node whose
			// configuration has not been applied.
			stat = pages.ForwarderStatView{Forwarder: forwarder, Status: "idle"}
		}
		view.Forwarders = append(view.Forwarders, stat)
	}
	return view
}

func forwarderStatView(stats dnsserver.ForwarderStats, now time.Time) pages.ForwarderStatView {
	view := pages.ForwarderStatView{
		Forwarder: stats.Forwarder, Route: stats.Route,
		Answered: stats.Answers, Timeouts: stats.Timeouts, Errors: stats.Errors,
		Status: "ok",
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
		view.LastError = "Last error " + formatApproximateDuration(now.Sub(stats.LastErrorAt)) + " ago: " + stats.LastError
	}
	return view
}

// testForwarders asks every forwarder the test names from this node and
// redraws the forwarder list with fresh numbers and each one's result.
func (server *Server) testForwarders(writer http.ResponseWriter, request *http.Request) {
	writer.Header().Set("Cache-Control", "no-store")
	reporter, ok := server.forwarders()
	if !ok {
		http.Error(writer, "forwarder tests are unavailable", http.StatusServiceUnavailable)
		return
	}
	results := make(map[[2]string]pages.ForwarderTestView)
	for _, result := range reporter.TestForwarders(request.Context()) {
		test := pages.ForwarderTestView{OK: result.OK, ResponseCode: result.ResponseCode, Validates: result.Validates, Error: result.Error}
		if result.Error == "" {
			test.ResponseTime = formatResponseTime(result.ResponseTime)
		}
		results[[2]string{result.Route, result.Forwarder}] = test
	}
	view := server.forwarderEditorView(server.config.Current().Config.Resolver.Forwarders, results)
	server.render(writer, request, pages.SettingsForwarderEditorBody(view))
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

// forwarderCheck is the answer to checkForwarders: the forwarders to keep,
// one per line as given, or why one can't be saved.
type forwarderCheck struct {
	Forwarders []string `json:"forwarders"`
	Error      string   `json:"error,omitempty"`
}

// checkForwarders tells the forwarder editor whether the forwarders it holds
// would save, before the operator saves: the rules a saved forwarder meets,
// and a bootstrap address for a new encrypted one named by host name.
func (server *Server) checkForwarders(writer http.ResponseWriter, request *http.Request) {
	writer.Header().Set("Cache-Control", "no-store")
	saved := make(map[string]bool)
	for _, forwarder := range server.config.Current().Config.Resolver.Forwarders {
		saved[forwarder] = true
	}
	result := forwarderCheck{Forwarders: []string{}}
	seen := make(map[string]bool)
	for _, forwarder := range formLines(request.FormValue("forwarders")) {
		if seen[forwarder] {
			continue
		}
		seen[forwarder] = true
		check := config.CheckNewForwarder
		if saved[forwarder] {
			check = func(string) error { return nil }
		}
		if err := check(forwarder); err != nil {
			result.Error = fmt.Sprintf("%s: %s", forwarder, strings.TrimPrefix(err.Error(), "forwarder: "))
			break
		}
		result.Forwarders = append(result.Forwarders, forwarder)
	}
	writer.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(writer).Encode(result)
}
