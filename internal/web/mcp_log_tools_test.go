package web

import (
	"context"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/drudge/sable/internal/dnsprovider"
	"github.com/drudge/sable/internal/serverlog"
)

// mcpServerLogQueries answers from a saved runtime log and remembers what it
// was asked.
type mcpServerLogQueries struct {
	*mcpTestQueries
	asked serverlog.Query
}

func (queries *mcpServerLogQueries) ServerLogEntries(_ context.Context, query serverlog.Query) (serverlog.Page, error) {
	queries.asked = query
	return serverlog.Page{TotalEntries: 1, Entries: []serverlog.Entry{
		{OccurredAt: time.Now(), Level: slog.LevelWarn, Message: "dns query failed", Attributes: map[string]string{"name": "auth.remarkable.com"}},
	}}, nil
}

func TestMCPSearchServerLogs(t *testing.T) {
	t.Parallel()
	server, configuration := newMCPTestServer(t)
	addMCPTools(configuration, "search_server_logs")
	const token = "cf-token-8f3kq92LmZ"
	server.SetDynamicDNSController(&testDynamicDNSController{configured: true, credentials: dnsprovider.Credentials{APIToken: token}})
	configuration.snapshot.Config.DynamicDNS.Provider = "cloudflare"
	buffer := serverlog.New(100)
	now := time.Now()
	for _, entry := range []serverlog.Entry{
		{OccurredAt: now.Add(-3 * time.Hour), Level: slog.LevelError, Message: "too old"},
		{OccurredAt: now.Add(-time.Minute), Level: slog.LevelInfo, Message: "zone operation completed"},
		{OccurredAt: now.Add(-time.Minute), Level: slog.LevelWarn, Message: "dns query failed",
			Attributes: map[string]string{"name": "auth.remarkable.com", "error": "iterative resolution encountered a referral loop at eu.auth0.com."}},
		{OccurredAt: now, Level: slog.LevelError, Message: "dynamic DNS publication failed",
			Attributes: map[string]string{"error": "Cloudflare said " + token + " is invalid", "authorization": "Bearer abc", "url": "https://admin:hunter22@backup.example/"}},
	} {
		buffer.Append(entry)
	}
	server.SetRuntimeLogs(buffer)

	if _, failure := callMCPToolForTest(t, server, "sable_pat_metrics", "search_server_logs", map[string]any{}); !strings.Contains(failure, "logs.read") {
		t.Fatalf("without logs.read = %q", failure)
	}
	live, failure := callMCPToolForTest(t, server, "sable_pat_logs", "search_server_logs", map[string]any{})
	entries, _ := live["entries"].([]any)
	if failure != "" || live["source"] != "live" || live["total"] != float64(2) || len(entries) != 2 {
		t.Fatalf("warn and worse in the last hour = %v %q", live, failure)
	}
	newest := entries[0].(map[string]any)
	attributes := newest["attributes"].(map[string]any)
	if newest["level"] != "ERROR" || strings.Contains(attributes["error"].(string), token) || attributes["authorization"] != "[redacted]" ||
		strings.Contains(attributes["url"].(string), "hunter22") {
		t.Fatalf("secrets reached the assistant: %v", newest)
	}
	found, _ := callMCPToolForTest(t, server, "sable_pat_logs", "search_server_logs", map[string]any{"search": "REFERRAL", "since": "6h", "limit": 5})
	if found["total"] != float64(1) {
		t.Fatalf("search = %v", found)
	}
	if everything, _ := callMCPToolForTest(t, server, "sable_pat_logs", "search_server_logs", map[string]any{"level": "debug", "since": "6h"}); everything["total"] != float64(4) {
		t.Fatalf("debug and worse over 6 hours = %v", everything)
	}
	for _, arguments := range []map[string]any{{"level": "loud"}, {"since": "yesterday"}, {"since": "-1h"}, {"until": "now"}} {
		if _, failure := callMCPToolForTest(t, server, "sable_pat_logs", "search_server_logs", arguments); failure == "" {
			t.Fatalf("%v was accepted", arguments)
		}
	}

	// With history kept, the store answers with the same shape.
	queries := &mcpServerLogQueries{mcpTestQueries: &mcpTestQueries{}}
	server.queries = queries
	configuration.snapshot.Config.ServerLog.Enabled = true
	saved, failure := callMCPToolForTest(t, server, "sable_pat_logs", "search_server_logs", map[string]any{"level": "info", "limit": 500})
	if failure != "" || saved["source"] != "persisted" || saved["total"] != float64(1) || saved["note"] != nil {
		t.Fatalf("persisted = %v %q", saved, failure)
	}
	if asked := queries.asked; asked.Level != "info" || !asked.AtLeast || asked.PageSize != mcpMaximumLogLimit || asked.Since.IsZero() || asked.Until.IsZero() {
		t.Fatalf("store asked %+v", asked)
	}
}
