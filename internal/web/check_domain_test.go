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
	"github.com/drudge/sable/internal/querylog"
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

	// The custom blocked domains have no panel of their own, so they link to
	// the Blocking page's Blocked tab beside the lists.
	custom := getDetailsPanel(server, "/ui/blocking/check?domain=pixel.custom.example", true).Body.String()
	expectContains(t, "custom blocked domain", custom,
		`href="/blocked?tab=domains"`, "<span>Custom blocked domains</span>", `data-dialog-url="/blocked/lists/Hagezi%20Pro"`)
	if strings.Contains(custom, "/blocked/lists/Custom") {
		t.Error("the custom blocked domains open a block list panel")
	}

	open := getDetailsPanel(server, "/ui/blocking/check?domain=example.org", true).Body.String()
	expectContains(t, "open domain", open, ">Not blocked</span>", "Nothing blocks this domain.", `name="action" value="block"`)
	if strings.Contains(open, "query-detail-grid") {
		t.Error("a domain nothing matches shows an empty set of facts")
	}

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
		"cdn.tracker.example is now allowed.", `id="blocking-content"`, `hx-swap-oob="outerHTML"`, `id="check-domain-verdict"`)
}

// Once devices are in rule sets, the panel asks which device to check for,
// and names the rule set that decided.
func TestCheckDomainPanelChecksADevice(t *testing.T) {
	t.Parallel()
	server, configuration := newCheckDomainTestServer(t)
	blank := getDetailsPanel(server, "/ui/blocking/check", true).Body.String()
	if strings.Contains(blank, `id="check-domain-device"`) {
		t.Error("the panel asks for a device with no rule sets")
	}

	configuration.snapshot.Config.Blocking.RuleSets = []config.RuleSet{{Name: "Kids", Apps: []string{"tiktok"}}}
	configuration.snapshot.Config.Clients = []config.Client{{Name: "Kid's iPad", Address: "192.0.2.4", RuleSet: "Kids"}}
	page := getDetailsPanel(server, "/blocked/check/tiktokcdn.com?device=Kid%27s+iPad", false).Body.String()
	expectContains(t, "Blocking page", page, `data-drawer-forward="device"`)

	blocked := getDetailsPanel(server, "/ui/blocking/check?domain=tiktokcdn.com&device=Kid%27s+iPad", true).Body.String()
	expectContains(t, "device check", blocked,
		`id="check-domain-device"`, `value="Kid&#39;s iPad"`, `<option value="192.0.2.4" label="Kid&#39;s iPad">`,
		`class="source-pill source-blocked">Blocked</span>`,
		"Blocked because the Kids rule set blocks TikTok, and tiktokcdn.com is one of its domains.",
		`data-dialog-url="/blocked/rule-sets/Kids"`, "This is the answer for Kid&#39;s iPad, which uses the Kids rule set.",
		`data-copy-url="/blocked/check/tiktokcdn.com?device=Kid%27s+iPad"`)
	// Allowing it everywhere wouldn't beat the rule set's own block.
	if strings.Contains(blocked, `name="action"`) {
		t.Error("a rule set's own block offers Allow")
	}

	typical := getDetailsPanel(server, "/ui/blocking/check?domain=tiktokcdn.com", true).Body.String()
	expectContains(t, "typical check", typical, `id="check-domain-device"`, ">Not blocked</span>", "This is the answer for a device on the Default rules.")

	unknown := getDetailsPanel(server, "/ui/blocking/check?domain=tiktokcdn.com&device=nobody", true).Body.String()
	expectContains(t, "unknown device", unknown, "Could not check that", "device must be")
}

func TestCheckDomainExplainsSchedules(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		policy dnsserver.DomainPolicy
		want   string
	}{
		{dnsserver.DomainPolicy{Decision: querylog.PolicyHeld, RuleSet: "Kids", Schedule: "Bedtime"},
			"Everything is blocked for devices in the Kids rule set until its Bedtime schedule ends, apart from their allowed domains."},
		{dnsserver.DomainPolicy{Decision: querylog.PolicyBlocked, Rule: "tiktokcdn.com", RuleSet: "Kids", OwnRule: true, Schedule: "Homework"},
			"Blocked because the Kids rule set's Homework schedule blocks TikTok, and tiktokcdn.com is one of its domains."},
		{dnsserver.DomainPolicy{Decision: querylog.PolicyBlocked, Rule: "games.example", RuleSet: "Kids", OwnRule: true},
			"Blocked because the Kids rule set blocks games.example."},
	} {
		check := domainCheck{Domain: test.policy.Rule, Policy: test.policy}
		if got := check.Explanation(func(time.Time) string { return "" }); got != test.want {
			t.Errorf("Explanation() = %q, want %q", got, test.want)
		}
		if !check.Blocked() {
			t.Errorf("Blocked() = false for %+v", test.policy)
		}
	}
}
