package web

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/drudge/sable/internal/config"
	"github.com/drudge/sable/internal/store"
)

// saveWatch posts the Add or Edit Watch form.
func (server alertsTestServer) saveWatch(t *testing.T, form url.Values) *httptest.ResponseRecorder {
	t.Helper()
	return server.post(t, "everything", "/ui/settings/alerts/watches/save", form)
}

func (server alertsTestServer) onlyWatch(t *testing.T) config.AlertWatch {
	t.Helper()
	watches := server.alertsConfig().Watches
	if len(watches) != 1 {
		t.Fatalf("watches = %+v, want one", watches)
	}
	return watches[0]
}

func TestAddingAWatchSavesItTidied(t *testing.T) {
	t.Parallel()
	server := newAlertsTestServer(t)
	page := server.get(t, "everything", "/settings?tab=alerts", false).Body.String()
	for _, want := range []string{
		`id="alert-watch-add"`, `id="alert-watch-dialog"`, "No watches yet", `id="alerts-group-watches"`,
		`name="watches" value="true" checked`,
		// The picker lists the devices Insights knows.
		`name="device" value="mac:3c:22:fb:01:02:03"`, "george-laptop.corp.example",
	} {
		if !strings.Contains(page, want) {
			t.Errorf("the Alerts tab lacks %q", want)
		}
	}

	response := server.saveWatch(t, url.Values{
		"name": {" Kids' games "}, "domains": {"Roblox.com\ndiscord.com, roblox.com"},
		"any_device": {"false"}, "device": {insightsTestLaptop}, "addresses": {"10.0.9.0/24\n10.0.0.77"},
		"result": {"blocked"}, "quiet": {"6h"},
	})
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), "Added Kids&#39; games.") {
		t.Fatalf("adding = %d %s", response.Code, response.Body.String())
	}
	watch := server.onlyWatch(t)
	if watch.Name != "Kids' games" || !slices.Equal(watch.Domains, []string{"roblox.com", "discord.com"}) ||
		!slices.Equal(watch.Devices, []string{insightsTestLaptop, "10.0.9.0/24", "10.0.0.77"}) ||
		watch.Result != config.AlertWatchBlocked || watch.Quiet.Duration != 6*time.Hour || !watch.Enabled || len(watch.ID) != 16 {
		t.Fatalf("watch = %+v", watch)
	}
	body := response.Body.String()
	for _, want := range []string{
		`id="alert-watch-` + watch.ID + `"`, "roblox.com, discord.com", "george-laptop.corp.example, 10.0.9.0/24, and 1 more",
		"Only when blocked", "Never triggered",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("the watch row lacks %q", want)
		}
	}
	if action, details := server.lastAudit(t); action != "alerts" || details != "added domain watch Kids' games" {
		t.Fatalf("audit = %q %q", action, details)
	}

	// Editing keeps the ID and whether the watch is on.
	server.post(t, "everything", "/ui/settings/alerts/watches/enabled", url.Values{"id": {watch.ID}})
	if server.onlyWatch(t).Enabled {
		t.Fatal("switching the watch off left it on")
	}
	form := server.get(t, "everything", "/ui/settings/alerts/watches/form?id="+watch.ID, true).Body.String()
	for _, want := range []string{
		`name="id" value="` + watch.ID + `"`, "Edit Watch", `value="Kids&#39; games"`, "roblox.com\ndiscord.com",
		`name="device" value="mac:3c:22:fb:01:02:03" checked`, "10.0.9.0/24\n10.0.0.77",
		`name="result" value="blocked" checked`, `<option value="6h" selected>6 hours</option>`,
	} {
		if !strings.Contains(form, want) {
			t.Errorf("the edit form lacks %q", want)
		}
	}
	response = server.saveWatch(t, url.Values{"id": {watch.ID}, "domains": {"discord.com"}, "any_device": {"true"}, "result": {"any"}, "quiet": {"1h"}})
	edited := server.onlyWatch(t)
	if response.Code != http.StatusOK || edited.ID != watch.ID || edited.Enabled || edited.Name != "" || edited.Devices != nil ||
		edited.Result != "" || edited.Label() != "discord.com" {
		t.Fatalf("editing = %d %+v", response.Code, edited)
	}

	removed := server.post(t, "everything", "/ui/settings/alerts/watches/remove", url.Values{"id": {watch.ID}})
	if removed.Code != http.StatusOK || !strings.Contains(removed.Body.String(), "Removed discord.com.") || server.alertsConfig().Watches != nil {
		t.Fatalf("removing = %d %+v", removed.Code, server.alertsConfig().Watches)
	}
	if again := server.post(t, "everything", "/ui/settings/alerts/watches/remove", url.Values{"id": {watch.ID}}); again.Code != http.StatusNotFound {
		t.Fatalf("removing twice = %d", again.Code)
	}
}

func TestWatchProblemsShowInTheDialog(t *testing.T) {
	t.Parallel()
	server := newAlertsTestServer(t)
	for _, test := range []struct {
		name string
		form url.Values
		want string
	}{
		{"no domains", url.Values{"any_device": {"true"}}, "Enter at least one domain."},
		{"a bad domain", url.Values{"domains": {"not_a domain!"}, "any_device": {"true"}}, "Enter domain names such as discord.com"},
		{"no devices", url.Values{"domains": {"discord.com"}, "any_device": {"false"}}, "Pick at least one device, or choose Any Device."},
		{"a bad address", url.Values{"domains": {"discord.com"}, "any_device": {"false"}, "addresses": {"kitchen"}}, "Enter addresses such as 10.0.7.20"},
		{"a long name", url.Values{"domains": {"discord.com"}, "any_device": {"true"}, "name": {strings.Repeat("x", 65)}}, "Keep the name to 64 characters."},
	} {
		t.Run(test.name, func(t *testing.T) {
			response := server.saveWatch(t, test.form)
			if response.Code != http.StatusUnprocessableEntity || response.Header().Get("HX-Retarget") != "#alert-watch-notice" ||
				!strings.Contains(response.Body.String(), test.want) {
				t.Fatalf("saving = %d %q %s", response.Code, response.Header().Get("HX-Retarget"), response.Body.String())
			}
		})
	}
	if watches := server.alertsConfig().Watches; watches != nil {
		t.Fatalf("a rejected form saved %+v", watches)
	}
}

// A Watch link from Query Logs names a client address; the dialog opens on
// its domain with the device that address belongs to.
func TestAWatchLinkOpensTheDialogOnTheDomainAndDevice(t *testing.T) {
	t.Parallel()
	server := newAlertsTestServer(t)
	page := server.get(t, "everything", "/settings?tab=alerts&watch_domain=discord.com&watch_client=fd00::5", false).Body.String()
	if !strings.Contains(page, `hx-get="/ui/settings/alerts/watches/form?client=fd00%3A%3A5&amp;domain=discord.com"`) ||
		!strings.Contains(page, `data-alert-watch-open`) {
		t.Fatal("the page does not open the Add Watch dialog")
	}
	form := server.get(t, "everything", "/ui/settings/alerts/watches/form?client=fd00::5&domain=discord.com", true).Body.String()
	if !strings.Contains(form, ">discord.com</textarea>") || !strings.Contains(form, `name="device" value="mac:3c:22:fb:01:02:03" checked`) ||
		!strings.Contains(form, `name="any_device" value="false" checked`) || strings.Contains(form, `name="id"`) {
		t.Fatalf("the form = %s", form)
	}
	// An operator who cannot change settings gets no dialog to open.
	if readOnly := server.get(t, "logs-reader", "/settings?tab=alerts&watch_domain=discord.com", false).Body.String(); strings.Contains(readOnly, "data-alert-watch-open") {
		t.Fatal("a read-only operator's page opens the Add Watch dialog")
	}

	// Query Logs offers the link, and the device drawer offers one on each
	// domain.
	logs := server.get(t, "everything", "/logs?tab=queries", false).Body.String()
	if !strings.Contains(logs, "data-query-detail-watch") {
		t.Error("Query Logs offers no Watch")
	}
	drawer := server.get(t, "everything", "/ui/insights/device?key="+url.QueryEscape(insightsTestLaptop)+"&range=day", true).Body.String()
	if !strings.Contains(drawer, `class="insight-row-watch" href="/settings?tab=alerts&amp;watch_device=mac%3A3c%3A22%3Afb%3A01%3A02%3A03&amp;watch_domain=`) {
		t.Error("the device drawer offers no Watch on its domains")
	}
	if drawer := server.get(t, "logs-reader", "/ui/insights/device?key="+url.QueryEscape(insightsTestLaptop)+"&range=day", true).Body.String(); strings.Contains(drawer, "insight-row-watch") {
		t.Error("the device drawer offers a Watch to an operator who cannot add one")
	}
}

func TestChangingWatchesNeedsSettingsWrite(t *testing.T) {
	t.Parallel()
	server := newAlertsTestServer(t)
	server.saveWatch(t, url.Values{"domains": {"discord.com"}, "any_device": {"true"}})
	id := server.onlyWatch(t).ID
	for _, route := range []struct {
		method, path string
		form         url.Values
	}{
		{http.MethodGet, "/ui/settings/alerts/watches/form", nil},
		{http.MethodPost, "/ui/settings/alerts/watches/save", url.Values{"domains": {"example.com"}, "any_device": {"true"}}},
		{http.MethodPost, "/ui/settings/alerts/watches/remove", url.Values{"id": {id}}},
		{http.MethodPost, "/ui/settings/alerts/watches/enabled", url.Values{"id": {id}}},
	} {
		for _, session := range []string{"logs-reader", "zones-only"} {
			var response *httptest.ResponseRecorder
			if route.method == http.MethodGet {
				response = server.get(t, session, route.path, true)
			} else {
				response = server.post(t, session, route.path, route.form)
			}
			if response.Code != http.StatusForbidden {
				t.Errorf("%s %s %s = %d, want %d", session, route.method, route.path, response.Code, http.StatusForbidden)
			}
		}
	}
	if watch := server.onlyWatch(t); !watch.Enabled || watch.Domains[0] != "discord.com" {
		t.Fatalf("an operator without settings write changed the watch to %+v", watch)
	}
}

// With Insights off Sable keeps no devices, so a watch picks devices by
// address and network, and a Watch link keeps the client's address.
func TestWithInsightsOffWatchesPickByAddress(t *testing.T) {
	t.Parallel()
	server := newAlertsTestServer(t)
	server.setInsights(t, false)
	form := server.get(t, "everything", "/ui/settings/alerts/watches/form?client=fd00::5&domain=discord.com", true).Body.String()
	if strings.Contains(form, `name="device"`) || !strings.Contains(form, "Insights is off, so watches pick devices by address or network.") ||
		!strings.Contains(form, ">fd00::5</textarea>") {
		t.Fatalf("the form = %s", form)
	}
	response := server.saveWatch(t, url.Values{"domains": {"discord.com"}, "any_device": {"false"}, "addresses": {"fd00::5"}})
	if response.Code != http.StatusOK || !slices.Equal(server.onlyWatch(t).Devices, []string{"fd00::5"}) {
		t.Fatalf("saving = %d %+v", response.Code, server.alertsConfig().Watches)
	}
}

// newDomainCounter counts the per-device first-time name queries, which only
// the Insights pages need.
type newDomainCounter struct {
	*store.Store
	calls *atomic.Int64
}

func (counter newDomainCounter) ClientNewDomainCount(ctx context.Context, clients []string, since, until time.Time) (uint64, error) {
	counter.calls.Add(1)
	return counter.Store.ClientNewDomainCount(ctx, clients, since, until)
}

// Settings lists the devices Insights knows in the watch picker, but must not
// count each device's first-time names: one query per device with more than
// one address made every Settings page wait on a busy network.
func TestSettingsWatchPickerSkipsNewDomainCounts(t *testing.T) {
	t.Parallel()
	server := newAlertsTestServer(t)
	calls := new(atomic.Int64)
	server.Server.queries = newDomainCounter{Store: server.store, calls: calls}
	page := server.get(t, "everything", "/settings?tab=alerts", false).Body.String()
	if !strings.Contains(page, `name="device" value="mac:3c:22:fb:01:02:03"`) {
		t.Fatal("the watch picker lost the devices Insights knows")
	}
	if got := calls.Load(); got != 0 {
		t.Fatalf("rendering Settings ran %d first-time name counts, want none", got)
	}
	// The Devices tab still counts them, for its "new names" column, and
	// keeps the counts, so the next visit doesn't wait for them again.
	server.get(t, "everything", "/ui/insights/overview?range=day&tab=devices", true)
	counted := calls.Load()
	if counted == 0 {
		t.Fatal("the Insights devices tab stopped counting first-time names")
	}
	server.get(t, "everything", "/ui/insights/overview?range=day&tab=devices", true)
	if calls.Load() != counted {
		t.Fatalf("a second visit to the Devices tab ran %d more counts, want it served from the kept counts", calls.Load()-counted)
	}
}

// Settings says where its time goes, so a slow page on a real deployment can
// be read from the browser's network panel.
func TestSettingsReportsServerTiming(t *testing.T) {
	t.Parallel()
	server := newAlertsTestServer(t)
	response := server.get(t, "everything", "/settings?tab=alerts", false)
	timing := response.Header().Get("Server-Timing")
	for _, part := range []string{"console;dur=", "backups;dur=", "forwarders;dur=", "alerts;dur=", "watch-devices;dur=", "insights;dur=", "total;dur="} {
		if !strings.Contains(timing, part) {
			t.Errorf("Server-Timing = %q, want %q", timing, part)
		}
	}
}

// A reverse zone that never answers must not hold up Settings: the watch
// picker takes names already looked up rather than waiting for new ones.
func TestSettingsDoesNotWaitForReverseLookups(t *testing.T) {
	t.Parallel()
	server := newAlertsTestServer(t)
	resolver := &stubReverseResolver{block: make(chan struct{}), blockAll: true}
	t.Cleanup(func() { close(resolver.block) })
	server.Server.reverseNames = newTestNameCache(resolver)
	started := time.Now()
	server.get(t, "everything", "/settings?tab=alerts", false)
	if elapsed := time.Since(started); elapsed >= reverseNameBudget/2 {
		t.Fatalf("Settings took %v with reverse lookups hanging, want it not to wait for them", elapsed)
	}
	if resolver.calls.Load() == 0 {
		t.Fatal("no reverse lookups were started for the unnamed clients")
	}
}
