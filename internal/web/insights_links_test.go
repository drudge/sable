package web

import (
	"html"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"

	"github.com/drudge/sable/internal/insights"
)

// A device's, an app's, and a finding's addresses open the Insights page with
// that drawer ready to open, on the tab it belongs to.
func TestInsightsLinksOpenThePageBehindTheirDrawers(t *testing.T) {
	t.Parallel()
	server := newInsightsTestServer(t)
	for _, test := range []struct {
		path, tab string
		expected  []string
	}{
		{"/insights/devices/" + insightsTestLaptop + "?range=day", "devices", []string{
			`data-drawer-content="/ui/insights/device" data-drawer-param="key" data-drawer-route="/insights/devices/"`,
			`data-dialog-base-url="/insights?range=day&amp;tab=devices"`,
		}},
		{"/insights/apps/youtube?range=week", "overview", []string{
			`data-drawer-content="/ui/insights/app" data-drawer-param="id" data-drawer-route="/insights/apps/"`,
			`data-dialog-base-url="/insights?range=week"`,
		}},
		// A finding's drawer comes with the Overview, which the page waits for.
		{"/insights/findings/0123456789ab?range=day", "overview", []string{"data-drawer-pending"}},
	} {
		response := server.get(t, "everything", test.path, false)
		if response.Code != http.StatusOK {
			t.Fatalf("%s = %d", test.path, response.Code)
		}
		body := response.Body.String()
		for _, expected := range append(test.expected, `data-active-tab="`+test.tab+`"`) {
			if !strings.Contains(body, expected) {
				t.Errorf("%s is missing %s", test.path, expected)
			}
		}
	}
	if response := server.get(t, "zones-only", "/insights/devices/"+insightsTestLaptop, false); response.Code != http.StatusForbidden {
		t.Fatalf("device address without Insights access = %d", response.Code)
	}
}

// The Overview loaded behind a drawer's address leaves that address alone,
// and each finding opens at its own.
func TestInsightsOverviewKeepsADrawersAddress(t *testing.T) {
	t.Parallel()
	server := newInsightsTestServer(t)
	request := httptest.NewRequest(http.MethodGet, "/ui/insights/overview?range=day", nil)
	request.AddCookie(&http.Cookie{Name: server.sessionCookieName(), Value: "everything"})
	request.Header.Set("HX-Request", "true")
	request.Header.Set("HX-Current-URL", "http://sable.test/insights/findings/0123456789ab?range=day")
	response := httptest.NewRecorder()
	server.httpServer.Handler.ServeHTTP(response, request)
	if got := response.Header().Get("HX-Replace-Url"); got != "" {
		t.Fatalf("overview behind a finding's address replaced it with %q", got)
	}
	body := response.Body.String()
	details := regexp.MustCompile(`data-dialog-open="(insight-finding-\d+)" aria-label="View details for [^"]*" data-dialog-url="(/insights/findings/[0-9a-f]{12}\?range=day)"`).FindAllStringSubmatch(body, -1)
	if len(details) == 0 {
		t.Fatal("no finding opens at its own address")
	}
	for _, detail := range details {
		dialog := `id="` + detail[1] + `" aria-labelledby="` + detail[1] + `-title" data-dialog-base-url="/insights?range=day" data-dialog-url="` + detail[2] + `"`
		if !strings.Contains(html.UnescapeString(body), dialog) {
			t.Errorf("finding drawer %s does not carry its address", detail[1])
		}
		if !strings.Contains(html.UnescapeString(body), `data-copy-url="`+detail[2]+`"`) {
			t.Errorf("finding drawer %s cannot copy its link", detail[1])
		}
	}
}

// A finding's link the page cannot open says why: the range does not reach
// it, with the next longer range to try, or the operator hid it, with the way
// to show it again.
func TestInsightsExplainAFindingLinkTheyCannotOpen(t *testing.T) {
	t.Parallel()
	server := newInsightsTestServer(t)
	overview := func(current string) string {
		request := httptest.NewRequest(http.MethodGet, "/ui/insights/overview?range=day", nil)
		request.AddCookie(&http.Cookie{Name: server.sessionCookieName(), Value: "everything"})
		request.Header.Set("HX-Request", "true")
		request.Header.Set("HX-Current-URL", "http://sable.test"+current)
		response := httptest.NewRecorder()
		server.httpServer.Handler.ServeHTTP(response, request)
		return html.UnescapeString(response.Body.String())
	}
	if plain := overview("/insights?range=day"); strings.Contains(plain, "insight-finding-missing") {
		t.Fatal("the Overview offered a stand-in without a finding's link")
	}
	gone := overview("/insights/findings/0123456789ab?range=day")
	for _, expected := range []string{
		`id="insight-finding-missing"`, `data-drawer-fallback="true" data-drawer-route="/insights/findings/"`,
		"Not in the last 24 hours", `href="/insights/findings/0123456789ab?range=week"><span>Try Last 7 Days</span></a>`, `href="/insights?range=day"><span>Open Insights</span></a>`,
	} {
		if !strings.Contains(gone, expected) {
			t.Errorf("a gone finding's stand-in is missing %s", expected)
		}
	}

	id := regexp.MustCompile(`<input type="hidden" name="id" value="([^"]+)"`).FindStringSubmatch(overview("/insights?range=day"))
	if id == nil {
		t.Fatal("no finding to hide")
	}
	link := "/insights/findings/" + insights.LinkID(id[1]) + "?range=day"
	if shown := overview(link); strings.Contains(shown, `id="insight-finding-missing"`) || !strings.Contains(shown, `data-dialog-url="`+link+`"`) {
		t.Fatal("a finding on the page did not open as itself")
	}
	if response := server.post(t, "everything", "/ui/insights/feedback", url.Values{"id": {id[1]}, "action": {"snooze"}, "label": {"Hidden finding"}}); response.Code >= 300 {
		t.Fatalf("hide = %d", response.Code)
	}
	hidden := overview(link)
	for _, expected := range []string{"Hidden finding", "You hid this finding", "Hidden until ", "It comes back then if it still applies.", "Show Again", `value="` + id[1] + `"`} {
		if !strings.Contains(hidden, expected) {
			t.Errorf("a hidden finding's stand-in is missing %s", expected)
		}
	}
	if strings.Contains(hidden, "Try Last") {
		t.Error("a hidden finding offered a longer range")
	}
}

func TestLinkedFindingReadsTheFindingsAddress(t *testing.T) {
	t.Parallel()
	for current, want := range map[string]string{
		"http://sable.test/insights/findings/0123456789ab?range=day": "0123456789ab",
		"http://sable.test/insights/devices/mac:aa:bb":               "",
		"http://sable.test/insights/findings/a/b":                    "",
		"http://sable.test/insights?range=day":                       "",
		"":                                                           "",
	} {
		request := httptest.NewRequest(http.MethodGet, "/ui/insights/overview", nil)
		request.Header.Set("HX-Current-URL", current)
		if got := linkedFinding(request); got != want {
			t.Errorf("linkedFinding(%q) = %q, want %q", current, got, want)
		}
	}
}

// A device drawer can copy its link, and an older link by address finds the
// device the address has joined since.
func TestInsightsDeviceDrawerLinks(t *testing.T) {
	t.Parallel()
	server := newInsightsTestServer(t)
	link := `data-copy-url="/insights/devices/` + insightsTestLaptop + `?range=day"`
	for _, key := range []string{insightsTestLaptop, "ip:10.0.0.5"} {
		body := server.get(t, "everything", "/ui/insights/device?range=day&key="+key, true).Body.String()
		if !strings.Contains(body, "george-laptop.corp.example") || !strings.Contains(body, link) {
			t.Errorf("drawer for %s does not show the laptop and its link", key)
		}
	}
	if missing := server.get(t, "everything", "/ui/insights/device?range=day&key=ip:10.255.0.1", true).Body.String(); strings.Contains(missing, "data-copy-url") {
		t.Fatal("a device that was not found offered a link to itself")
	}
}

func TestInsightAlertsOpenTheirFinding(t *testing.T) {
	t.Parallel()
	finding := insights.Finding{ID: "devices.new-app/device:mac:3c:22:fb:01:02:03", Kind: "devices.new-app"}
	alert := insightAlert(finding)
	if want := "/insights/findings/" + insights.LinkID(finding.ID) + "?range=day"; alert.Path != want || alert.PathLabel != "Open Finding" {
		t.Fatalf("alert path = %q %q, want %q", alert.Path, alert.PathLabel, want)
	}
}
