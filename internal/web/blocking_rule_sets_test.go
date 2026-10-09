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
		`id="blocking-tab-rule-sets"`, `data-blocking-panel="rule-sets"`, `data-rule-set="Default"`, "Every block list",
		`data-rule-set="Kids"`, "Lists: Strict · 1 blocked domain", "Devices: Leo&#39;s Switch, 10.20.40.0/24",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("Rule Sets tab is missing %q", want)
		}
	}
	if strings.Contains(body, `id="blocking-panel-rule-sets" role="tabpanel" aria-labelledby="blocking-tab-rule-sets" data-blocking-panel="rule-sets" hidden`) {
		t.Error("the Rule Sets tab is hidden although it was asked for")
	}

	form := serveRuleSetRequest(server, http.MethodGet, "/ui/blocking/rule-sets/form?name=Kids", nil).Body.String()
	for _, want := range []string{"Edit Kids", `name="original" value="Kids"`, `value="Strict" checked`} {
		if !strings.Contains(form, want) {
			t.Errorf("rule set form is missing %q", want)
		}
	}
	if strings.Contains(form, `value="Ads" checked`) || strings.Contains(form, "<textarea") {
		t.Error("rule set form checks a list the rule set doesn't use, or still edits its domains")
	}
	if missing := serveRuleSetRequest(server, http.MethodGet, "/ui/blocking/rule-sets/form?name=Gone", nil); missing.Code != http.StatusNotFound ||
		missing.Header().Get("HX-Retarget") != "#rule-set-notice" {
		t.Fatalf("form for a missing rule set = %d %v", missing.Code, missing.Header())
	}
}

func TestRuleSetDialogSavesRenamesAndDeletes(t *testing.T) {
	t.Parallel()
	server, configuration := newRuleSetTestServer(t)

	added := serveRuleSetRequest(server, http.MethodPost, "/ui/blocking/rule-sets/save", url.Values{
		"name": {"Work"}, "lists": {"Ads"},
	})
	sets := configuration.Current().Config.Blocking.RuleSets
	if added.Code != http.StatusOK || !strings.Contains(added.Body.String(), "Rule set Work added") || len(sets) != 2 || !slices.Equal(sets[1].Lists, []string{"Ads"}) {
		t.Fatalf("add = %d, sets %+v", added.Code, sets)
	}

	// A problem shows in the dialog, leaving what was typed alone.
	for _, form := range []url.Values{
		{"name": {"work"}},
		{"name": {"Default"}},
	} {
		problem := serveRuleSetRequest(server, http.MethodPost, "/ui/blocking/rule-sets/save", form)
		if problem.Code != http.StatusUnprocessableEntity || problem.Header().Get("HX-Retarget") != "#rule-set-notice" ||
			!strings.Contains(problem.Body.String(), `toast-error`) {
			t.Errorf("save %v = %d %v %s", form, problem.Code, problem.Header(), problem.Body.String())
		}
	}

	renamed := serveRuleSetRequest(server, http.MethodPost, "/ui/blocking/rule-sets/save", url.Values{"original": {"Kids"}, "name": {"Children"}, "lists": {"Strict", "Ads"}})
	current := configuration.Current().Config
	// Renaming keeps the rule set's own domains, which the dialog doesn't edit.
	if renamed.Code != http.StatusOK || current.Blocking.RuleSets[0].Name != "Children" || current.Clients[0].RuleSet != "Children" ||
		!slices.Equal(current.Blocking.RuleSets[0].Domains, []string{"games.example"}) {
		t.Fatalf("rename = %d, sets %+v, clients %+v", renamed.Code, current.Blocking.RuleSets, current.Clients)
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

func TestDefaultListsDialog(t *testing.T) {
	t.Parallel()
	server, configuration := newRuleSetTestServer(t)
	form := serveRuleSetRequest(server, http.MethodGet, "/ui/blocking/rule-sets/form?default=1", nil).Body.String()
	if !strings.Contains(form, "Edit Default") || !strings.Contains(form, `value="all" checked`) {
		t.Fatalf("default form = %s", form)
	}
	saved := serveRuleSetRequest(server, http.MethodPost, "/ui/blocking/rule-sets/default", url.Values{"scope": {"chosen"}, "lists": {"Ads"}})
	if saved.Code != http.StatusOK || !slices.Equal(configuration.Current().Config.Blocking.DefaultLists, []string{"Ads"}) || !strings.Contains(saved.Body.String(), "Lists: Ads") {
		t.Fatalf("save default lists = %d %v", saved.Code, configuration.Current().Config.Blocking.DefaultLists)
	}
	if none := serveRuleSetRequest(server, http.MethodPost, "/ui/blocking/rule-sets/default", url.Values{"scope": {"chosen"}}); none.Code != http.StatusUnprocessableEntity ||
		none.Header().Get("HX-Retarget") != "#rule-set-notice" {
		t.Fatalf("no lists chosen = %d %v", none.Code, none.Header())
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
	for _, want := range []string{">Kids</h2>", "Leo&#39;s Switch, 10.20.40.0/24", "Strict", `data-policy-domain="games.example"`, "No allowed domains of its own.", `name="kind" value="allowed"`} {
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
