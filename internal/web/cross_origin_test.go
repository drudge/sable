package web

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/drudge/sable/internal/config"
	"github.com/drudge/sable/internal/dnsserver"
)

// With security off there is no session or CSRF token, so the browser's
// origin is the only thing telling a console form from another site's.
func TestUnsafeConsoleRequestsRefuseCrossSiteWithSecurityOff(t *testing.T) {
	t.Parallel()

	server, err := New(
		slog.New(slog.NewTextHandler(io.Discard, nil)),
		testStats{snapshot: dnsserver.Stats{StartedAt: time.Now()}},
		testConfiguration{snapshot: config.Snapshot{Config: config.Defaults()}},
		testZones{},
		"sqlite",
		testQueryLog{},
		testQueryLog{},
		func(context.Context) error { return nil },
		testAuthenticator{},
		false,
		false,
		false,
	)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	post := func(headers map[string]string) int {
		request := httptest.NewRequest(http.MethodPost, "http://sable.test/ui/cache/purge", nil)
		for name, value := range headers {
			request.Header.Set(name, value)
		}
		response := httptest.NewRecorder()
		server.httpServer.Handler.ServeHTTP(response, request)
		return response.Code
	}

	for name, headers := range map[string]map[string]string{
		"fetch metadata": {"Sec-Fetch-Site": "cross-site", "Origin": "https://evil.example"},
		"origin only":    {"Origin": "https://evil.example"},
	} {
		if code := post(headers); code != http.StatusForbidden {
			t.Errorf("cross-site POST (%s) = %d, want 403", name, code)
		}
	}
	for name, headers := range map[string]map[string]string{
		"same origin":   {"Sec-Fetch-Site": "same-origin", "Origin": "http://sable.test"},
		"origin only":   {"Origin": "http://sable.test"},
		"not a browser": {},
	} {
		if code := post(headers); code == http.StatusForbidden {
			t.Errorf("POST (%s) = 403, want it allowed", name)
		}
	}
}
