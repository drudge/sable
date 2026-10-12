package web

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/drudge/sable/internal/config"
	"github.com/drudge/sable/internal/dnsserver"
)

func newRuleSetTestServer(t *testing.T) (*Server, *editableTestConfiguration) {
	t.Helper()
	configuration := &editableTestConfiguration{snapshot: config.Snapshot{Config: config.Defaults(), Revision: 1}}
	configuration.snapshot.Config.Blocking.Lists = []config.BlockList{{Name: "Ads", Path: "ads.txt"}, {Name: "Strict", Path: "strict.txt"}}
	configuration.snapshot.Config.Blocking.RuleSets = []config.RuleSet{{Name: "Kids", Lists: []string{"Strict"}, Domains: []string{"games.example"}}}
	configuration.snapshot.Config.Clients = []config.Client{
		{Name: "Leo's Switch", Address: "192.0.2.20", RuleSet: "Kids"},
		{Address: "10.20.40.0/24", RuleSet: "Kids"},
	}
	server, err := New(
		slog.New(slog.NewTextHandler(io.Discard, nil)),
		testStats{snapshot: dnsserver.Stats{StartedAt: time.Now()}},
		configuration, configuration.zoneStore(), "sqlite",
		testQueryLog{}, testQueryLog{}, func(context.Context) error { return nil },
		nil, false, false, false,
	)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	return server, configuration
}

func serveRuleSetRequest(server *Server, method, target string, form url.Values) *httptest.ResponseRecorder {
	var body io.Reader
	if form != nil {
		body = strings.NewReader(form.Encode())
	}
	request := httptest.NewRequest(method, target, body)
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.Header.Set("HX-Request", "true")
	response := httptest.NewRecorder()
	server.httpServer.Handler.ServeHTTP(response, request)
	return response
}

func TestRuleSetsTabListsRuleSetsAndTheirDevices(t *testing.T) {
	t.Parallel()
	server, _ := newRuleSetTestServer(t)
	response := serveRuleSetRequest(server, http.MethodGet, "/blocked?tab=rule-sets", nil)
	body := response.Body.String()
	for _, want := range []string{
		`id="blocking-tab-rule-sets"`, `data-blocking-panel="rule-sets"`, `data-rule-set="Default"`, "All your block lists",
		`data-rule-set="Kids"`, "Lists: Strict · 1 blocked domain", "Devices: Leo&#39;s Switch, 10.20.40.0/24",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("Rule Sets tab is missing %q", want)
		}
	}
	if strings.Contains(body, `id="blocking-panel-rule-sets" role="tabpanel" aria-labelledby="blocking-tab-rule-sets" data-blocking-panel="rule-sets" hidden`) {
		t.Error("the Rule Sets tab is hidden although it was asked for")
	}

	// Rule sets are changed in their panels, so the rows have no Edit, and
	// Default keeps a delete button it can't use.
	if strings.Contains(body, ">Edit<") || !strings.Contains(body, `disabled aria-label="Can't delete Default"`) {
		t.Error("the Rule Sets tab still has Edit, or Default has no locked delete button")
	}

	panel := serveRuleSetRequest(server, http.MethodGet, "/ui/blocking/rule-set?name=Kids", nil).Body.String()
	for _, want := range []string{`aria-label="Rename Kids"`, `name="blocking" value="on" checked`, `value="Strict" checked`, `hx-post="/ui/blocking/rule-sets/lists"`} {
		if !strings.Contains(panel, want) {
			t.Errorf("rule set panel is missing %q", want)
		}
	}
	if strings.Contains(panel, `value="Ads" checked`) || strings.Contains(panel, "Edit Rule Set") {
		t.Error("rule set panel checks a list the rule set doesn't use, or still opens the dialog")
	}
}

func TestRuleSetPanelAddsRenamesAndDeletes(t *testing.T) {
	t.Parallel()
	server, configuration := newRuleSetTestServer(t)

	// Adding takes only a name, then opens the new rule set's panel.
	added := serveRuleSetRequest(server, http.MethodPost, "/ui/blocking/rule-sets/add", url.Values{"name": {"Work"}})
	sets := configuration.Current().Config.Blocking.RuleSets
	if added.Code != http.StatusOK || !strings.Contains(added.Body.String(), "Rule set Work added") || len(sets) != 2 || sets[1].Name != "Work" ||
		added.Header().Get("HX-Push-Url") != "/blocked/rule-sets/Work" {
		t.Fatalf("add = %d %v, sets %+v", added.Code, added.Header(), sets)
	}

	// A problem shows in the dialog, leaving what was typed alone.
	for _, form := range []url.Values{
		{"name": {"work"}},
		{"name": {"Default"}},
	} {
		problem := serveRuleSetRequest(server, http.MethodPost, "/ui/blocking/rule-sets/add", form)
		if problem.Code != http.StatusUnprocessableEntity || problem.Header().Get("HX-Retarget") != "#rule-set-notice" ||
			!strings.Contains(problem.Body.String(), `toast-error`) {
			t.Errorf("add %v = %d %v %s", form, problem.Code, problem.Header(), problem.Body.String())
		}
	}

	// The panel's title renames it; a clash keeps the name field open.
	editor := serveRuleSetRequest(server, http.MethodGet, "/ui/blocking/rule-set?name=Kids&edit=name", nil).Body.String()
	if !strings.Contains(editor, `hx-post="/ui/blocking/rule-sets/rename?edit=name"`) || !strings.Contains(editor, `name="original" value="Kids"`) {
		t.Fatalf("rename editor:\n%s", editor)
	}
	clash := serveRuleSetRequest(server, http.MethodPost, "/ui/blocking/rule-sets/rename?edit=name", url.Values{"original": {"Kids"}, "name": {"work"}})
	if clash.Code != http.StatusUnprocessableEntity || !strings.Contains(clash.Body.String(), "already exists") || !strings.Contains(clash.Body.String(), `name="original" value="Kids"`) {
		t.Fatalf("rename to a taken name = %d %s", clash.Code, clash.Body.String())
	}
	renamed := serveRuleSetRequest(server, http.MethodPost, "/ui/blocking/rule-sets/rename?edit=name", url.Values{"original": {"Kids"}, "name": {"Children"}})
	current := configuration.Current().Config
	// Renaming keeps the rule set's devices, block lists, and domains.
	if renamed.Code != http.StatusOK || current.Blocking.RuleSets[0].Name != "Children" || current.Clients[0].RuleSet != "Children" ||
		!slices.Equal(current.Blocking.RuleSets[0].Domains, []string{"games.example"}) || !slices.Equal(current.Blocking.RuleSets[0].Lists, []string{"Strict"}) ||
		renamed.Header().Get("HX-Replace-Url") != "/blocked/rule-sets/Children" || strings.Contains(renamed.Body.String(), "insight-name-editor") ||
		!strings.Contains(renamed.Body.String(), "Rule set Kids renamed to Children") {
		t.Fatalf("rename = %d %v, sets %+v, clients %+v", renamed.Code, renamed.Header(), current.Blocking.RuleSets, current.Clients)
	}

	// Its block lists change as they're checked, keeping the rest.
	lists := serveRuleSetRequest(server, http.MethodPost, "/ui/blocking/rule-sets/lists", url.Values{"name": {"Children"}, "lists": {"Strict", "Ads"}})
	current = configuration.Current().Config
	if lists.Code != http.StatusOK || !slices.Equal(current.Blocking.RuleSets[0].Lists, []string{"Strict", "Ads"}) || !strings.Contains(lists.Body.String(), "Children uses 2 block lists") ||
		!slices.Equal(current.Blocking.RuleSets[0].Domains, []string{"games.example"}) {
		t.Fatalf("lists = %d %s, sets %+v", lists.Code, lists.Body.String(), current.Blocking.RuleSets)
	}

	deleted := serveRuleSetRequest(server, http.MethodPost, "/ui/blocking/rule-sets/delete", url.Values{"name": {"Children"}})
	current = configuration.Current().Config
	if deleted.Code != http.StatusOK || len(current.Blocking.RuleSets) != 1 || len(current.Clients) != 1 || current.Clients[0].RuleSet != "" {
		t.Fatalf("delete = %d, sets %+v, clients %+v", deleted.Code, current.Blocking.RuleSets, current.Clients)
	}
	if again := serveRuleSetRequest(server, http.MethodPost, "/ui/blocking/rule-sets/delete", url.Values{"name": {"Children"}}); again.Code != http.StatusUnprocessableEntity ||
		!strings.Contains(again.Body.String(), "No rule set is called") {
		t.Fatalf("delete twice = %d %s", again.Code, again.Body.String())
	}
}

func TestDefaultPanelPicksItsBlockLists(t *testing.T) {
	t.Parallel()
	server, configuration := newRuleSetTestServer(t)
	panel := serveRuleSetRequest(server, http.MethodGet, "/ui/blocking/rule-set?name=Default", nil).Body.String()
	if !strings.Contains(panel, `value="all" checked`) || !strings.Contains(panel, `hx-post="/ui/blocking/rule-sets/default"`) ||
		strings.Contains(panel, "Rename Default") || strings.Contains(panel, "Devices</h3>") {
		t.Fatalf("default panel = %s", panel)
	}
	// Choosing Only These Lists starts from every list.
	only := serveRuleSetRequest(server, http.MethodPost, "/ui/blocking/rule-sets/default", url.Values{"scope": {"chosen"}})
	if only.Code != http.StatusOK || !slices.Equal(configuration.Current().Config.Blocking.DefaultLists, []string{"Ads", "Strict"}) {
		t.Fatalf("only these lists = %d %v", only.Code, configuration.Current().Config.Blocking.DefaultLists)
	}
	saved := serveRuleSetRequest(server, http.MethodPost, "/ui/blocking/rule-sets/default", url.Values{"scope": {"chosen"}, "lists": {"Ads"}})
	if saved.Code != http.StatusOK || !slices.Equal(configuration.Current().Config.Blocking.DefaultLists, []string{"Ads"}) || !strings.Contains(saved.Body.String(), "Lists: Ads") {
		t.Fatalf("save default lists = %d %v", saved.Code, configuration.Current().Config.Blocking.DefaultLists)
	}
	if none := serveRuleSetRequest(server, http.MethodPost, "/ui/blocking/rule-sets/default", url.Values{"scope": {"chosen"}}); none.Code != http.StatusUnprocessableEntity ||
		!strings.Contains(none.Body.String(), "Choose at least one block list") {
		t.Fatalf("no lists chosen = %d %s", none.Code, none.Body.String())
	}
	// Choosing every list keeps no lists, even ones still ticked.
	every := serveRuleSetRequest(server, http.MethodPost, "/ui/blocking/rule-sets/default", url.Values{"scope": {"all"}, "lists": {"Ads"}})
	if every.Code != http.StatusOK || configuration.Current().Config.Blocking.DefaultLists != nil {
		t.Fatalf("every list = %d %v", every.Code, configuration.Current().Config.Blocking.DefaultLists)
	}

	// The default policy's only list can't be removed out from under it.
	serveRuleSetRequest(server, http.MethodPost, "/ui/blocking/rule-sets/default", url.Values{"scope": {"chosen"}, "lists": {"Ads"}})
	removed := serveRuleSetRequest(server, http.MethodPost, "/ui/blocking/lists/delete", url.Values{"name": {"Ads"}})
	if removed.Code != http.StatusUnprocessableEntity || !strings.Contains(removed.Body.String(), "only block list") {
		t.Fatalf("remove the default's only list = %d %s", removed.Code, removed.Body.String())
	}
	if removed := serveRuleSetRequest(server, http.MethodPost, "/ui/blocking/lists/delete", url.Values{"name": {"Strict"}}); removed.Code != http.StatusOK ||
		len(configuration.Current().Config.Blocking.RuleSets[0].Lists) != 0 {
		t.Fatalf("remove a rule set's list = %d, sets %+v", removed.Code, configuration.Current().Config.Blocking.RuleSets)
	}
}

func TestRuleSetPanelChangesItsOwnDomains(t *testing.T) {
	t.Parallel()
	server, configuration := newRuleSetTestServer(t)

	// Everyone's lists point to the rule sets that keep their own.
	tab := serveRuleSetRequest(server, http.MethodGet, "/blocked?tab=domains", nil).Body.String()
	if !strings.Contains(tab, `hx-get="/ui/blocking/rule-set?name=Kids"`) || !strings.Contains(tab, "has its own blocked domains too") {
		t.Fatalf("the Blocked tab doesn't point to Kids:\n%s", tab)
	}
	if page := serveRuleSetRequest(server, http.MethodGet, "/blocked/rule-sets/Kids", nil).Body.String(); !strings.Contains(page, `data-drawer-route="/blocked/rule-sets/"`) ||
		strings.Contains(page, `data-blocking-panel="rule-sets" hidden`) {
		t.Fatal("a rule set's address doesn't open the Rule Sets tab with its panel")
	}

	panel := serveRuleSetRequest(server, http.MethodGet, "/ui/blocking/rule-set?name=Kids", nil).Body.String()
	for _, want := range []string{">Kids</h2>", "<strong>Leo&#39;s Switch</strong>", "Address 192.0.2.20", "Every device on 10.20.40.0/24", "Strict", `data-policy-domain="games.example"`, "No allowed domains of its own.", `name="kind" value="allowed"`} {
		if !strings.Contains(panel, want) {
			t.Errorf("panel is missing %q", want)
		}
	}

	added := serveRuleSetRequest(server, http.MethodPost, "/ui/blocking/rule-sets/domains/add", url.Values{"name": {"Kids"}, "kind": {"allowed"}, "domain": {"*.School.Example"}})
	if body := added.Body.String(); added.Code != http.StatusOK || !strings.Contains(body, `data-policy-domain="*.school.example"`) || !strings.Contains(body, `hx-swap-oob`) {
		t.Fatalf("allow = %d %s", added.Code, body)
	}
	moved := serveRuleSetRequest(server, http.MethodPost, "/ui/blocking/rule-sets/domains/add", url.Values{"name": {"Kids"}, "kind": {"blocked"}, "domain": {"*.school.example"}})
	set := configuration.Current().Config.Blocking.RuleSets[0]
	if moved.Code != http.StatusOK || !slices.Equal(set.Domains, []string{"*.school.example", "games.example"}) || len(set.AllowedDomains) != 0 {
		t.Fatalf("block what was allowed = %d, set %+v", moved.Code, set)
	}
	if len(configuration.Current().Config.Blocking.Domains) != 0 {
		t.Fatal("a rule set's domain landed on everyone's list")
	}

	removed := serveRuleSetRequest(server, http.MethodPost, "/ui/blocking/rule-sets/domains/delete", url.Values{"name": {"Kids"}, "kind": {"blocked"}, "domain": {"games.example"}})
	if removed.Code != http.StatusOK || slices.Contains(configuration.Current().Config.Blocking.RuleSets[0].Domains, "games.example") {
		t.Fatalf("remove = %d %s", removed.Code, removed.Body.String())
	}
	again := serveRuleSetRequest(server, http.MethodPost, "/ui/blocking/rule-sets/domains/delete", url.Values{"name": {"Kids"}, "kind": {"blocked"}, "domain": {"games.example"}})
	if again.Code != http.StatusUnprocessableEntity || !strings.Contains(again.Body.String(), "is not on the block list") {
		t.Fatalf("remove twice = %d %s", again.Code, again.Body.String())
	}

	missing := serveRuleSetRequest(server, http.MethodPost, "/ui/blocking/rule-sets/domains/add", url.Values{"name": {"Nope"}, "kind": {"blocked"}, "domain": {"x.example"}})
	if missing.Code != http.StatusUnprocessableEntity || !strings.Contains(missing.Body.String(), "Rule set not found") {
		t.Fatalf("an unknown rule set = %d %s", missing.Code, missing.Body.String())
	}
}

func TestRuleSetPanelAddsAndRemovesDevices(t *testing.T) {
	t.Parallel()
	server, configuration := newRuleSetTestServer(t)
	kids := func() []config.Client {
		var clients []config.Client
		for _, client := range configuration.Current().Config.Clients {
			if client.RuleSet == "Kids" {
				clients = append(clients, client)
			}
		}
		return clients
	}
	post := func(path string, values url.Values) (int, string) {
		t.Helper()
		values.Set("name", "Kids")
		response := serveRuleSetRequest(server, http.MethodPost, path, values)
		return response.Code, response.Body.String()
	}

	panel := serveRuleSetRequest(server, http.MethodGet, "/ui/blocking/rule-set?name=Kids", nil).Body.String()
	if !strings.Contains(panel, `name="device" value="" data-device-picker-value`) || !strings.Contains(panel, `hx-post="/ui/blocking/rule-sets/devices/delete"`) {
		t.Fatalf("panel has no way to add or remove devices:\n%s", panel)
	}

	// A hardware address, in any spelling, and a name the operator gave.
	if code, body := post("/ui/blocking/rule-sets/devices/add", url.Values{"device": {"DA-A1-19-00-00-09"}}); code != http.StatusOK ||
		!strings.Contains(body, "da:a1:19:00:00:09 uses the Kids rule set") || !strings.Contains(body, `data-rule-set-device="da:a1:19:00:00:09"`) {
		t.Fatalf("add a hardware address = %d %s", code, body)
	}
	if err := configuration.Update(context.Background(), func(candidate *config.Config) error {
		candidate.Clients = append(candidate.Clients, config.Client{Name: "Mia's iPad", Address: "192.0.2.30"})
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if code, body := post("/ui/blocking/rule-sets/devices/add", url.Values{"device": {"mia's ipad"}}); code != http.StatusOK || !strings.Contains(body, "Mia&#39;s iPad uses the Kids rule set") {
		t.Fatalf("add by name = %d %s", code, body)
	}
	if got := len(kids()); got != 4 {
		t.Fatalf("Kids has %d devices, want 4: %+v", got, kids())
	}
	if code, body := post("/ui/blocking/rule-sets/devices/add", url.Values{"device": {"192.0.2.30"}}); code != http.StatusUnprocessableEntity || !strings.Contains(body, "already in Kids") {
		t.Fatalf("add twice = %d %s", code, body)
	}
	if code, body := post("/ui/blocking/rule-sets/devices/add", url.Values{"device": {"someone's phone"}}); code != http.StatusUnprocessableEntity || !strings.Contains(body, "Enter a device Sable has seen") {
		t.Fatalf("add something unknown = %d %s", code, body)
	}

	// Taking a device out keeps its name; a network's entry goes with it.
	if code, body := post("/ui/blocking/rule-sets/devices/delete", url.Values{"device": {"192.0.2.30"}}); code != http.StatusOK || !strings.Contains(body, "no longer has a rule set of its own") || !strings.Contains(body, `hx-swap-oob`) {
		t.Fatalf("remove = %d %s", code, body)
	}
	if code, _ := post("/ui/blocking/rule-sets/devices/delete", url.Values{"device": {"10.20.40.0/24"}}); code != http.StatusOK {
		t.Fatalf("remove a network = %d", code)
	}
	clients := configuration.Current().Config.Clients
	if !slices.ContainsFunc(clients, func(client config.Client) bool { return client.Name == "Mia's iPad" && client.RuleSet == "" }) ||
		slices.ContainsFunc(clients, func(client config.Client) bool { return client.Address == "10.20.40.0/24" }) {
		t.Fatalf("clients after removing = %+v", clients)
	}
	if code, body := post("/ui/blocking/rule-sets/devices/delete", url.Values{"device": {"192.0.2.30"}}); code != http.StatusUnprocessableEntity || !strings.Contains(body, "isn&#39;t in Kids") {
		t.Fatalf("remove twice = %d %s", code, body)
	}
	if response := serveRuleSetRequest(server, http.MethodPost, "/ui/blocking/rule-sets/devices/add", url.Values{"name": {"Nope"}, "device": {"192.0.2.40"}}); response.Code != http.StatusNotFound {
		t.Fatalf("an unknown rule set = %d", response.Code)
	}
}

func TestRuleSetWithBlockingOffSkipsItsListsAndDomains(t *testing.T) {
	t.Parallel()
	server, configuration := newRuleSetTestServer(t)
	// The switch sends nothing when it's turned off.
	saved := serveRuleSetRequest(server, http.MethodPost, "/ui/blocking/rule-sets/blocking", url.Values{"name": {"Kids"}})
	if saved.Code != http.StatusOK {
		t.Fatalf("save = %d %s", saved.Code, saved.Body.String())
	}
	set := configuration.Current().Config.Blocking.RuleSets[0]
	if !set.Off || !slices.Equal(set.Domains, []string{"games.example"}) || !slices.Equal(set.Lists, []string{"Strict"}) {
		t.Fatalf("rule set = %+v, want blocking off and its lists and domains kept", set)
	}
	panel := saved.Body.String()
	if !strings.Contains(panel, "Blocking off") || !strings.Contains(panel, "hx-swap-oob") {
		t.Fatalf("the Rule Sets tab doesn't say blocking is off:\n%s", panel)
	}
	if !strings.Contains(panel, `name="blocking" value="on"`) || strings.Contains(panel, `name="blocking" value="on" checked`) ||
		!strings.Contains(panel, "Off: everything gets through") || strings.Contains(panel, `id="rule-set-blocked-title"`) || strings.Contains(panel, "<legend>Block Lists</legend>") ||
		!strings.Contains(panel, "Leo&#39;s Switch") {
		t.Fatalf("panel for a rule set with blocking off:\n%s", panel)
	}
	if on := serveRuleSetRequest(server, http.MethodPost, "/ui/blocking/rule-sets/blocking", url.Values{"name": {"Kids"}, "blocking": {"on"}}); on.Code != http.StatusOK ||
		configuration.Current().Config.Blocking.RuleSets[0].Off || !strings.Contains(on.Body.String(), "Blocking is on for Kids devices") {
		t.Fatalf("turn blocking on = %d %s", on.Code, on.Body.String())
	}
}

func TestRuleSetPanelBlocksApps(t *testing.T) {
	t.Parallel()
	server, configuration := newRuleSetTestServer(t)
	kids := func() config.RuleSet { return configuration.Current().Config.Blocking.RuleSets[0] }

	panel := serveRuleSetRequest(server, http.MethodGet, "/ui/blocking/rule-set?name=Kids", nil).Body.String()
	if !strings.Contains(panel, "No blocked apps.") || !strings.Contains(panel, `hx-get="/ui/blocking/rule-sets/apps?name=Kids"`) {
		t.Fatalf("panel has no way to choose apps:\n%s", panel)
	}
	// The picker offers the categories people block, not device platforms.
	picker := serveRuleSetRequest(server, http.MethodGet, "/ui/blocking/rule-sets/apps?name=Kids", nil)
	if picker.Code != http.StatusOK || !strings.Contains(picker.Body.String(), `value="tiktok"`) || strings.Contains(picker.Body.String(), `value="windows-update"`) ||
		!strings.Contains(picker.Body.String(), "<legend>Social</legend>") {
		t.Fatalf("picker = %d %s", picker.Code, picker.Body.String())
	}

	saved := serveRuleSetRequest(server, http.MethodPost, "/ui/blocking/rule-sets/apps", url.Values{"name": {"Kids"}, "app": {"youtube", "tiktok"}})
	if saved.Code != http.StatusOK || !strings.Contains(saved.Body.String(), "Kids blocks 2 apps") || !strings.Contains(saved.Body.String(), `data-rule-set-app="tiktok"`) ||
		!strings.Contains(saved.Body.String(), "hx-swap-oob") {
		t.Fatalf("save = %d %s", saved.Code, saved.Body.String())
	}
	if !slices.Equal(kids().Apps, []string{"tiktok", "youtube"}) {
		t.Fatalf("Kids blocks %v", kids().Apps)
	}
	// The picker checks what the rule set blocks, and keeps an app outside
	// its categories that the config file names, so saving never drops it.
	if err := configuration.Update(context.Background(), func(candidate *config.Config) error {
		candidate.Blocking.RuleSets[0].Apps = append(candidate.Blocking.RuleSets[0].Apps, "windows-update")
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	picker = serveRuleSetRequest(server, http.MethodGet, "/ui/blocking/rule-sets/apps?name=Kids", nil)
	if !strings.Contains(picker.Body.String(), `value="tiktok" checked`) || !strings.Contains(picker.Body.String(), `value="windows-update" checked`) {
		t.Fatalf("picker after saving = %s", picker.Body.String())
	}

	// Changing its block lists keeps its apps.
	if response := serveRuleSetRequest(server, http.MethodPost, "/ui/blocking/rule-sets/lists", url.Values{"name": {"Kids"}, "lists": {"Ads"}}); response.Code != http.StatusOK {
		t.Fatalf("save its lists = %d %s", response.Code, response.Body.String())
	}
	if !slices.Equal(slices.Sorted(slices.Values(kids().Apps)), []string{"tiktok", "windows-update", "youtube"}) {
		t.Fatalf("Kids blocks %v after its lists changed", kids().Apps)
	}

	removed := serveRuleSetRequest(server, http.MethodPost, "/ui/blocking/rule-sets/apps/delete", url.Values{"name": {"Kids"}, "app": {"tiktok"}})
	if removed.Code != http.StatusOK || !strings.Contains(removed.Body.String(), "Kids no longer blocks TikTok") || slices.Contains(kids().Apps, "tiktok") {
		t.Fatalf("remove = %d %s, apps %v", removed.Code, removed.Body.String(), kids().Apps)
	}
	if again := serveRuleSetRequest(server, http.MethodPost, "/ui/blocking/rule-sets/apps/delete", url.Values{"name": {"Kids"}, "app": {"tiktok"}}); again.Code != http.StatusUnprocessableEntity ||
		!strings.Contains(again.Body.String(), "Kids doesn&#39;t block TikTok") {
		t.Fatalf("remove twice = %d %s", again.Code, again.Body.String())
	}
	if unknown := serveRuleSetRequest(server, http.MethodPost, "/ui/blocking/rule-sets/apps", url.Values{"name": {"Kids"}, "app": {"myspace"}}); unknown.Code != http.StatusUnprocessableEntity ||
		!strings.Contains(unknown.Body.String(), "know an app called myspace") {
		t.Fatalf("an unknown app = %d %s", unknown.Code, unknown.Body.String())
	}
	if missing := serveRuleSetRequest(server, http.MethodGet, "/ui/blocking/rule-sets/apps?name=Nope", nil); missing.Code != http.StatusNotFound {
		t.Fatalf("picker for an unknown rule set = %d", missing.Code)
	}
}

// The query log's Block and Allow can change just the rule set the device
// used, and Allow for the rule set gets past the rule set's own block.
func TestQueryLogBlocksAndAllowsForTheRuleSet(t *testing.T) {
	t.Parallel()
	server, configuration := newRuleSetTestServer(t)
	kids := func() config.RuleSet { return configuration.Current().Config.Blocking.RuleSets[0] }

	blocked := serveRuleSetRequest(server, http.MethodPost, "/ui/blocking/query-domain", url.Values{"domain": {"videos.example."}, "action": {"block"}, "rule_set": {"Kids"}})
	if blocked.Code != http.StatusOK || !slices.Contains(kids().Domains, "videos.example") || slices.Contains(configuration.Current().Config.Blocking.Domains, "videos.example") ||
		!strings.Contains(blocked.Body.String(), "Kids") {
		t.Fatalf("block for Kids = %d %s, Kids %+v", blocked.Code, blocked.Body.String(), kids())
	}
	allowed := serveRuleSetRequest(server, http.MethodPost, "/ui/blocking/query-domain", url.Values{"domain": {"games.example"}, "action": {"allow"}, "rule_set": {"Kids"}})
	if allowed.Code != http.StatusOK || !slices.Contains(kids().AllowedDomains, "games.example") || slices.Contains(kids().Domains, "games.example") {
		t.Fatalf("allow for Kids = %d %s, Kids %+v", allowed.Code, allowed.Body.String(), kids())
	}
	if everyone := serveRuleSetRequest(server, http.MethodPost, "/ui/blocking/query-domain", url.Values{"domain": {"ads.example"}, "action": {"block"}}); everyone.Code != http.StatusOK ||
		!slices.Contains(configuration.Current().Config.Blocking.Domains, "ads.example") || slices.Contains(kids().Domains, "ads.example") {
		t.Fatalf("block for everyone = %d, Kids %+v", everyone.Code, kids())
	}
	if missing := serveRuleSetRequest(server, http.MethodPost, "/ui/blocking/query-domain", url.Values{"domain": {"ads.example"}, "action": {"block"}, "rule_set": {"Teens"}}); !strings.Contains(missing.Body.String(), "Teens") {
		t.Fatalf("a deleted rule set = %s", missing.Body.String())
	}
}
