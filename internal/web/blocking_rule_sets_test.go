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
	for _, want := range []string{"Edit Kids", `name="original" value="Kids"`, `value="Strict" checked`, ">games.example</textarea>"} {
		if !strings.Contains(form, want) {
			t.Errorf("rule set form is missing %q", want)
		}
	}
	if strings.Contains(form, `value="Ads" checked`) {
		t.Error("rule set form checks a list the rule set doesn't use")
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
		"name": {"Work"}, "lists": {"Ads"}, "domains": {"Tracker.Example.\n\ntracker.example"}, "allowed_domains": {"*.Corp.Example"},
	})
	sets := configuration.Current().Config.Blocking.RuleSets
	if added.Code != http.StatusOK || !strings.Contains(added.Body.String(), "Rule set Work added") || len(sets) != 2 ||
		!slices.Equal(sets[1].Domains, []string{"tracker.example"}) || !slices.Equal(sets[1].AllowedDomains, []string{"*.corp.example"}) {
		t.Fatalf("add = %d, sets %+v", added.Code, sets)
	}

	// A problem shows in the dialog, leaving what was typed alone.
	for _, form := range []url.Values{
		{"name": {"work"}},
		{"name": {"Default"}},
		{"name": {"Guests"}, "domains": {"bad..example"}},
	} {
		problem := serveRuleSetRequest(server, http.MethodPost, "/ui/blocking/rule-sets/save", form)
		if problem.Code != http.StatusUnprocessableEntity || problem.Header().Get("HX-Retarget") != "#rule-set-notice" ||
			!strings.Contains(problem.Body.String(), `toast-error`) {
			t.Errorf("save %v = %d %v %s", form, problem.Code, problem.Header(), problem.Body.String())
		}
	}

	renamed := serveRuleSetRequest(server, http.MethodPost, "/ui/blocking/rule-sets/save", url.Values{"original": {"Kids"}, "name": {"Children"}, "lists": {"Strict", "Ads"}})
	current := configuration.Current().Config
	if renamed.Code != http.StatusOK || current.Blocking.RuleSets[0].Name != "Children" || current.Clients[0].RuleSet != "Children" ||
		len(current.Blocking.RuleSets[0].Domains) != 0 {
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
