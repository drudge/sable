package web

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/drudge/sable/internal/config"
	"github.com/drudge/sable/internal/dnsserver"
	zonemodel "github.com/drudge/sable/internal/zone"
)

func newCheckDomainTestServer(t *testing.T) (*Server, *editableTestConfiguration) {
	t.Helper()
	configuration := &editableTestConfiguration{snapshot: config.Snapshot{Config: config.Defaults(), Revision: 1}, baseDirectory: t.TempDir()}
	configuration.zoneSnapshot.Zones = []zonemodel.Zone{mcpTestZone("zone-example", "example.test", "primary")}
	server, err := New(
		slog.New(slog.NewTextHandler(io.Discard, nil)),
		mcpTestStats{testStats: testStats{snapshot: dnsserver.Stats{StartedAt: time.Now()}}},
		configuration, configuration.zoneStore(), "sqlite",
		testQueryLog{}, testQueryLog{}, func(context.Context) error { return nil },
		nil, false, false, false,
	)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	return server, configuration
}

// A domain's check has its own address on the Blocking page. The panel says
// what blocking does with the domain and why, the same answer MCP's
// check_domain gives.
func TestCheckDomainPanel(t *testing.T) {
	t.Parallel()
	server, configuration := newCheckDomainTestServer(t)

	page := getDetailsPanel(server, "/blocked/check/cdn.tracker.example", false)
	if page.Code != http.StatusOK {
		t.Fatalf("check page status = %d", page.Code)
	}
	expectContains(t, "Blocking page", page.Body.String(),
		`id="check-domain-dialog"`, `data-drawer-route="/blocked/check/"`, `data-drawer-content="/ui/blocking/check"`,
		`data-drawer-param="domain"`, `data-drawer-dialog="check-domain-dialog"`, `aria-label="Check a domain"`)

	blank := getDetailsPanel(server, "/ui/blocking/check", true).Body.String()
	expectContains(t, "blank panel", blank, "Which domain?", `data-drawer-navigate="domain"`, `data-drawer-focus`)
	if strings.Contains(blank, "check-domain-verdict") {
		t.Error("the blank panel shows a verdict")
	}

	blocked := getDetailsPanel(server, "/ui/blocking/check?domain=CDN.Tracker.Example.", true).Body.String()
	expectContains(t, "blocked domain", blocked,
		`>cdn.tracker.example</h2>`, `class="source-pill source-blocked">Blocked</span>`,
		"Blocked because tracker.example is on Hagezi Pro.", "<code>tracker.example</code>",
		`data-dialog-url="/blocked/lists/Hagezi%20Pro"`, `data-copy-url="/blocked/check/cdn.tracker.example"`,
		`name="action" value="allow"`)
	if strings.Contains(blocked, `name="action" value="block"`) {
		t.Error("a blocked domain offers Block")
	}

	open := getDetailsPanel(server, "/ui/blocking/check?domain=example.org", true).Body.String()
	expectContains(t, "open domain", open, ">Not blocked</span>", "Nothing blocks this domain.", `name="action" value="block"`)

	zoned := getDetailsPanel(server, "/ui/blocking/check?domain=www.example.test", true).Body.String()
	expectContains(t, "zone domain", zoned, ">Answered by your zone</span>", `href="/zones/example.test"`)
	if strings.Contains(zoned, `name="action"`) {
		t.Error("a name Sable answers from its zone offers Allow or Block")
	}

	invalid := getDetailsPanel(server, "/ui/blocking/check?domain=*.example.org", true).Body.String()
	expectContains(t, "wildcard", invalid, "Could not check that", "single name")

	// Allowing from the panel checks again, and the page beneath turns to the
	// allow list.
	allowed := postDetailsPanelForm(server, "/ui/blocking/check/rule", url.Values{"domain": {"cdn.tracker.example"}, "action": {"allow"}})
	if allowed.Code != http.StatusOK {
		t.Fatalf("allow status = %d: %s", allowed.Code, allowed.Body.String())
	}
	if !slices.Contains(configuration.snapshot.Config.Blocking.AllowedDomains, "cdn.tracker.example") {
		t.Fatalf("allowed domains = %v", configuration.snapshot.Config.Blocking.AllowedDomains)
	}
	expectContains(t, "allow response", allowed.Body.String(),
		"cdn.tracker.example is now allowed.", `id="blocking-content"`, `hx-swap-oob="outerHTML"`, "<dd>Yes</dd>")
}
