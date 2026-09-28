package web

import (
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"

	"github.com/drudge/sable/internal/config"
)

func getDetailsPanel(server *Server, path string, fragment bool) *httptest.ResponseRecorder {
	request := httptest.NewRequest(http.MethodGet, path, nil)
	if fragment {
		request.Header.Set("HX-Request", "true")
	}
	response := httptest.NewRecorder()
	server.httpServer.Handler.ServeHTTP(response, request)
	return response
}

// A query's address opens Query Logs with its details panel, which loads the
// query by its ID. One that has aged out gets a stand-in that searches for
// its domain.
func TestQueryLinkOpensItsDetails(t *testing.T) {
	t.Parallel()
	configuration := &editableTestConfiguration{snapshot: config.Snapshot{Config: config.Defaults(), Revision: 1}, baseDirectory: t.TempDir()}
	server := newDetailsPanelTestServer(t, configuration)

	page := getDetailsPanel(server, "/logs/queries/1?name=example.com", false)
	if page.Code != http.StatusOK {
		t.Fatalf("query page status = %d", page.Code)
	}
	expectContains(t, "query page", page.Body.String(),
		`data-active-tab="queries"`, `id="query-detail-dialog"`, `data-drawer-route="/logs/queries/"`,
		`data-drawer-content="/ui/logs/query"`, `data-query-detail-link="/logs/queries/1?name=example.com"`)

	found := getDetailsPanel(server, "/ui/logs/query?id=1&name=example.com", true).Body.String()
	expectContains(t, "loaded query", found,
		`data-query-detail-value="name">example.com</h2>`, `<code data-query-detail-value="client">192.0.2.1</code>`,
		`class="source-pill source-cache" data-query-detail-source>Cached</span>`, "Cache hit",
		`data-copy-url="/logs/queries/1?name=example.com"`, `data-query-detail-policy="block"`)
	// Only a blocked query asks why it was blocked.
	if !strings.Contains(found, `href="/blocked/check/example.com" data-query-detail-why hidden`) {
		t.Error("a cached query shows Why is this blocked?, or links it to the wrong check")
	}
	if strings.Contains(found, "no longer in the log") {
		t.Error("a query still in the log opened as aged out")
	}

	missing := getDetailsPanel(server, "/ui/logs/query?id=99&name=example.com", true).Body.String()
	expectContains(t, "aged-out query", missing,
		"This query is no longer in the log", "Newer queries for example.com may still be there.",
		`href="/logs?name=example.com&amp;tab=queries"`, "Search Query Logs")
	if strings.Contains(missing, "data-query-detail-source") {
		t.Error("the aged-out stand-in shows query facts")
	}
	// Without a domain in its address there is nothing to search for.
	if bare := getDetailsPanel(server, "/ui/logs/query?id=99", true).Body.String(); strings.Contains(bare, "Search Query Logs") {
		t.Error("the stand-in offers a search with no domain to search for")
	}
}

// Every Settings card has its own id, made from its title, so a link can
// open it; no two share one.
func TestSettingsCardsHaveLinkableIDs(t *testing.T) {
	t.Parallel()
	server := newAlertsTestServer(t)
	page := server.get(t, "everything", "/settings?tab=alerts", false).Body.String()
	ids := regexp.MustCompile(`id="([^"]+)" data-settings-card`).FindAllStringSubmatch(page, -1)
	seen := make(map[string]bool, len(ids))
	for _, match := range ids {
		if seen[match[1]] {
			t.Errorf("two Settings cards are #%s", match[1])
		}
		seen[match[1]] = true
	}
	for _, id := range []string{"block-list-updates", "bypass-clients", "public-tls-certificate", "destinations", "alert-types", "watches"} {
		if !seen[id] {
			t.Errorf("no Settings card is #%s; have %v", id, seen)
		}
	}
	if count := strings.Count(page, `id="watches"`); count != 1 {
		t.Errorf("#watches appears %d times on the page", count)
	}
}
