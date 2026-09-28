package web

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/drudge/sable/internal/config"
	"github.com/drudge/sable/internal/dnsserver"
)

func newDetailsPanelTestServer(t *testing.T, configuration *editableTestConfiguration) *Server {
	t.Helper()
	server, err := New(
		slog.New(slog.NewTextHandler(io.Discard, nil)),
		testStats{snapshot: dnsserver.Stats{StartedAt: time.Now()}},
		configuration,
		configuration.zoneStore(),
		"sqlite",
		testQueryLog{},
		testQueryLog{},
		func(context.Context) error { return nil },
		nil,
		false,
		false,
		false,
	)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	return server
}

func postDetailsPanelForm(server *Server, path string, form url.Values) *httptest.ResponseRecorder {
	request := httptest.NewRequest(http.MethodPost, path, strings.NewReader(form.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.Header.Set("HX-Request", "true")
	response := httptest.NewRecorder()
	server.httpServer.Handler.ServeHTTP(response, request)
	return response
}

func expectContains(t *testing.T, label, body string, expected ...string) {
	t.Helper()
	for _, value := range expected {
		if !strings.Contains(body, value) {
			t.Errorf("%s is missing %s", label, value)
		}
	}
}

// A block list's address opens the Blocking page with its panel, which shows
// the list's source and update history and can refresh just that list.
func TestBlockListPanel(t *testing.T) {
	t.Parallel()

	var failing atomic.Bool
	remote := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		if failing.Load() {
			writer.WriteHeader(http.StatusBadGateway)
			return
		}
		_, _ = writer.Write([]byte("0.0.0.0 fresh.example\n"))
	}))
	defer remote.Close()

	configuration := &editableTestConfiguration{snapshot: config.Snapshot{Config: config.Defaults(), Revision: 1}, baseDirectory: t.TempDir()}
	configuration.snapshot.Config.Blocking.Lists = []config.BlockList{
		{Name: "Test Feed", URL: remote.URL + "/hosts", Path: "blocklists/test-feed.txt", Format: "auto"},
		{Name: "Local Rules", Path: "local-rules.txt", Format: "domains"},
	}
	for _, name := range []string{"blocklists/test-feed.txt", "local-rules.txt"} {
		path := filepath.Join(configuration.baseDirectory, name)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte("cached.example\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	server := newDetailsPanelTestServer(t, configuration)

	page := serveRequest(server, http.MethodGet, "/blocked/lists/Test%20Feed")
	if page.Code != http.StatusOK {
		t.Fatalf("list address = %d", page.Code)
	}
	expectContains(t, "list address", page.Body.String(),
		`id="block-list-dialog"`, `data-drawer-content="/ui/blocking/list" data-drawer-param="name" data-drawer-route="/blocked/lists/"`,
		`data-dialog-base-url="/blocked"`, `data-dialog-url="/blocked/lists/Test%20Feed"`, `data-row-opener`,
	)

	panel := serveRequest(server, http.MethodGet, "/ui/blocking/list?name=Test+Feed")
	expectContains(t, "remote list panel", panel.Body.String(),
		"Test Feed", remote.URL+"/hosts", "Source URL", "Detected automatically", "Last update", "Next update",
		`data-copy-url="/blocked/lists/Test%20Feed"`, "Refresh This List", `hx-post="/ui/blocking/lists/refresh"`,
	)
	local := serveRequest(server, http.MethodGet, "/ui/blocking/list?name=Local+Rules").Body.String()
	expectContains(t, "local list panel", local, "local-rules.txt", "One domain per line", "File changed", "Local file, never downloaded")
	if strings.Contains(local, "Refresh This List") {
		t.Error("a local file offers Refresh This List")
	}
	if missing := serveRequest(server, http.MethodGet, "/ui/blocking/list?name=Gone").Body.String(); !strings.Contains(missing, "Block list not found") || strings.Contains(missing, "Copy Link") {
		t.Errorf("missing list panel = %s", missing)
	}

	refreshed := postDetailsPanelForm(server, "/ui/blocking/lists/refresh", url.Values{"name": {"Test Feed"}})
	if refreshed.Code != http.StatusOK {
		t.Fatalf("refresh = %d %s", refreshed.Code, refreshed.Body.String())
	}
	// The panel and the page beneath it come back together.
	expectContains(t, "refresh response", refreshed.Body.String(), "Test Feed downloaded and compiled", `id="blocking-content"`, `hx-swap-oob="outerHTML"`)
	if contents, _ := os.ReadFile(filepath.Join(configuration.baseDirectory, "blocklists/test-feed.txt")); string(contents) != "0.0.0.0 fresh.example\n" {
		t.Fatalf("refreshed list = %q", contents)
	}

	failing.Store(true)
	failed := postDetailsPanelForm(server, "/ui/blocking/lists/refresh", url.Values{"name": {"Test Feed"}})
	if failed.Code != http.StatusUnprocessableEntity || failed.Header().Get(consoleFragmentHeader) != "true" {
		t.Fatalf("failed refresh = %d", failed.Code)
	}
	expectContains(t, "failed refresh", failed.Body.String(), "502 Bad Gateway", "1 failed update", "Failures in a row", "Next retry")
	if contents, _ := os.ReadFile(filepath.Join(configuration.baseDirectory, "blocklists/test-feed.txt")); string(contents) != "0.0.0.0 fresh.example\n" {
		t.Fatalf("list after a failed refresh = %q, want the last good copy", contents)
	}
	if response := postDetailsPanelForm(server, "/ui/blocking/lists/refresh", url.Values{"name": {"Local Rules"}}); response.Code != http.StatusNotFound {
		t.Fatalf("refreshing a local file = %d", response.Code)
	}
}
