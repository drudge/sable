package web

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/drudge/sable/internal/config"
	"github.com/drudge/sable/internal/web/pages"
)

// withConfig changes the test server's configuration.
func (server insightsTestServer) withConfig(t *testing.T, change func(*config.Config)) {
	t.Helper()
	editor := server.config.(*editableTestConfiguration)
	if err := editor.Update(context.Background(), func(configuration *config.Config) error {
		change(configuration)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func TestDeviceDrawerPutsTheDeviceInARuleSet(t *testing.T) {
	t.Parallel()
	server := newInsightsTestServer(t)
	server.withConfig(t, func(configuration *config.Config) {
		configuration.Blocking.RuleSets = []config.RuleSet{{Name: "Kids", Lists: []string{"Alpha"}}, {Name: "Guests"}}
		configuration.Clients = []config.Client{{Address: "10.0.0.0/24", RuleSet: "Guests"}}
	})
	drawer := server.get(t, "everything", "/ui/insights/device?range=day&key="+url.QueryEscape(insightsTestLaptop), true).Body.String()
	for _, want := range []string{"Guests rule set", "From the network 10.0.0.0/24.", "Block Everything", "Change the rule set of"} {
		if !strings.Contains(drawer, want) {
			t.Fatalf("drawer is missing %q", want)
		}
	}
	editor := server.get(t, "everything", "/ui/insights/device?range=day&edit=rule-set&key="+url.QueryEscape(insightsTestLaptop), true).Body.String()
	if !strings.Contains(editor, `<option value="" selected>Guests (from the network 10.0.0.0/24)</option>`) {
		t.Fatalf("the rule set picker does not offer what the device falls back to:\n%s", editor)
	}

	form := url.Values{"key": {insightsTestLaptop}, "range": {"day"}, "rule_set": {"Kids"}}
	if response := server.post(t, "logs-reader", "/ui/insights/devices/rule-set", form); response.Code != http.StatusForbidden {
		t.Fatalf("a rule set without blocking.write = %d", response.Code)
	}
	response := server.post(t, "everything", "/ui/insights/devices/rule-set", form)
	body := response.Body.String()
	if response.Code != http.StatusOK || !strings.Contains(body, "Kids rule set") || !strings.Contains(body, "Set by its hardware address.") || !strings.Contains(body, "3c:22:fb:01:02:03 uses the Kids rule set") {
		t.Fatalf("rule set = %d %s", response.Code, body)
	}
	clients := server.config.Current().Config.Clients
	if len(clients) != 2 || !containsClient(clients, config.Client{MAC: "3c:22:fb:01:02:03", RuleSet: "Kids"}) {
		t.Fatalf("clients = %+v", clients)
	}

	response = server.post(t, "everything", "/ui/insights/devices/rule-set", url.Values{"key": {insightsTestLaptop}, "range": {"day"}, "rule_set": {""}})
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), "Guests rule set") {
		t.Fatalf("back to the network's rule set = %d %s", response.Code, response.Body.String())
	}
	if clients := server.config.Current().Config.Clients; len(clients) != 1 {
		t.Fatalf("the device's own entry was kept: %+v", clients)
	}

	missing := server.post(t, "everything", "/ui/insights/devices/rule-set", url.Values{"key": {insightsTestLaptop}, "range": {"day"}, "rule_set": {"Nope"}})
	if missing.Code != http.StatusUnprocessableEntity || !strings.Contains(missing.Body.String(), "Nope") || !strings.Contains(missing.Body.String(), `name="rule_set"`) {
		t.Fatalf("an unknown rule set = %d %s", missing.Code, missing.Body.String())
	}
}

func TestDeviceDrawerShowsBypassedDevicesAsUnblocked(t *testing.T) {
	t.Parallel()
	server := newInsightsTestServer(t)
	server.withConfig(t, func(configuration *config.Config) {
		configuration.Blocking.BypassClients = []string{"10.0.0.5"}
	})
	drawer := server.get(t, "everything", "/ui/insights/device?range=day&key="+url.QueryEscape(insightsTestLaptop), true).Body.String()
	if !strings.Contains(drawer, "Blocking off") || !strings.Contains(drawer, "Bypass Clients names the address 10.0.0.5.") || strings.Contains(drawer, "Change the rule set of") {
		t.Fatalf("bypassed device:\n%s", drawer)
	}
}

func TestDeviceDrawerHoldsBlockEverything(t *testing.T) {
	t.Parallel()
	server := newInsightsTestServer(t)
	post := func(values url.Values) (int, string) {
		t.Helper()
		values.Set("key", insightsTestLaptop)
		values.Set("range", "day")
		response := server.post(t, "everything", "/ui/insights/devices/hold", values)
		return response.Code, response.Body.String()
	}
	if response := server.post(t, "logs-reader", "/ui/insights/devices/hold", url.Values{"key": {insightsTestLaptop}, "hold": {"30m"}}); response.Code != http.StatusForbidden {
		t.Fatalf("a hold without blocking.write = %d", response.Code)
	}
	form := server.get(t, "everything", "/ui/insights/device?range=day&edit=hold&key="+url.QueryEscape(insightsTestLaptop), true).Body.String()
	if !strings.Contains(form, `name="hold" value="30m" checked`) || !strings.Contains(form, `type="time" name="until"`) {
		t.Fatalf("hold form:\n%s", form)
	}

	before := time.Now()
	code, body := post(url.Values{"hold": {"30m"}})
	if code != http.StatusOK || !strings.Contains(body, "Everything is blocked") || !strings.Contains(body, "data-countdown-until=") || !strings.Contains(body, "Add 30 Minutes") || !strings.Contains(body, "End Now") {
		t.Fatalf("hold = %d %s", code, body)
	}
	holds := server.config.Current().Config.Blocking.Holds
	if len(holds) != 1 || holds[0].MAC != "3c:22:fb:01:02:03" || holds[0].Until.Before(before.Add(29*time.Minute)) || holds[0].Until.After(time.Now().Add(31*time.Minute)) {
		t.Fatalf("holds = %+v", holds)
	}
	first := holds[0].Until

	code, body = post(url.Values{"action": {"extend"}, "entry": {"3c:22:fb:01:02:03"}})
	if code != http.StatusOK || !strings.Contains(body, "Added 30 minutes.") {
		t.Fatalf("extend = %d %s", code, body)
	}
	if until := server.config.Current().Config.Blocking.Holds[0].Until; !until.Equal(first.Add(holdExtension)) {
		t.Fatalf("extended to %v, want %v", until, first.Add(holdExtension))
	}

	code, body = post(url.Values{"action": {"end"}, "entry": {"3c:22:fb:01:02:03"}})
	if code != http.StatusOK || !strings.Contains(body, "back to normal") || !strings.Contains(body, "Block Everything") || len(server.config.Current().Config.Blocking.Holds) != 0 {
		t.Fatalf("end = %d %s", code, body)
	}

	code, body = post(url.Values{"hold": {"off"}})
	if code != http.StatusOK || !strings.Contains(body, "Until you turn it off.") || strings.Contains(body, "Add 30 Minutes") {
		t.Fatalf("hold until turned off = %d %s", code, body)
	}
	if code, body = post(url.Values{"action": {"extend"}, "entry": {"3c:22:fb:01:02:03"}}); code != http.StatusConflict {
		t.Fatalf("extending a hold with no end = %d %s", code, body)
	}

	code, body = post(url.Values{"hold": {"until"}, "until": {"later"}})
	if code != http.StatusUnprocessableEntity || !strings.Contains(body, "Pick a time to block everything until.") {
		t.Fatalf("a bad time = %d %s", code, body)
	}
}

func TestDeviceDrawerShowsANetworksHold(t *testing.T) {
	t.Parallel()
	server := newInsightsTestServer(t)
	server.withConfig(t, func(configuration *config.Config) {
		configuration.Blocking.Holds = []config.Hold{{Address: "10.0.0.0/24", Until: time.Now().Add(time.Hour)}}
	})
	drawer := server.get(t, "everything", "/ui/insights/device?range=day&key="+url.QueryEscape(insightsTestLaptop), true).Body.String()
	if !strings.Contains(drawer, "The hold is on the network 10.0.0.0/24") || !strings.Contains(drawer, `&#34;entry&#34;:&#34;10.0.0.0/24&#34;`) {
		t.Fatalf("network hold:\n%s", drawer)
	}
}

func TestHoldUntilReadsTheForm(t *testing.T) {
	t.Parallel()
	zone := time.FixedZone("EDT", -4*60*60)
	display := pages.TimeDisplay{Location: zone}
	now := time.Date(2026, 10, 8, 22, 15, 0, 0, zone)
	for _, test := range []struct {
		choice, clock string
		want          time.Time
	}{
		{"30m", "", now.Add(30 * time.Minute)},
		{"1h", "", now.Add(time.Hour)},
		{"off", "", time.Time{}},
		{"until", "23:00", time.Date(2026, 10, 8, 23, 0, 0, 0, zone)},
		// A time already gone today is tomorrow's.
		{"until", "07:30", time.Date(2026, 10, 9, 7, 30, 0, 0, zone)},
	} {
		got, err := holdUntil(test.choice, test.clock, display, now)
		if err != nil || !got.Equal(test.want) {
			t.Errorf("holdUntil(%q, %q) = %v, %v; want %v", test.choice, test.clock, got, err, test.want)
		}
	}
	if _, err := holdUntil("forever", "", display, now); err == nil {
		t.Error("an unknown choice was accepted")
	}
}

func TestTimeLeft(t *testing.T) {
	t.Parallel()
	for remaining, want := range map[time.Duration]string{
		20 * time.Second:              "under a minute left",
		time.Minute:                   "1 minute left",
		25 * time.Minute:              "25 minutes left",
		65 * time.Minute:              "1 hour 5 minutes left",
		2 * time.Hour:                 "2 hours left",
		26*time.Hour + 10*time.Minute: "1 day 2 hours left",
		7 * 24 * time.Hour:            "7 days left",
	} {
		if got := timeLeft(remaining); got != want {
			t.Errorf("timeLeft(%v) = %q, want %q", remaining, got, want)
		}
	}
}

func containsClient(clients []config.Client, want config.Client) bool {
	for _, client := range clients {
		if client == want {
			return true
		}
	}
	return false
}
