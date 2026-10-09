package web

import (
	"cmp"
	"context"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/drudge/sable/internal/config"
	"github.com/drudge/sable/internal/insights/devices"
	"github.com/drudge/sable/internal/web/pages"
)

// ruleSetsTab is the Blocking tab that lists rule sets.
const ruleSetsTab = "rule-sets"

// ruleSetFormPanel fills the rule set dialog: a new rule set, the one named,
// or with default=1 the default policy's block lists.
func (server *Server) ruleSetFormPanel(writer http.ResponseWriter, request *http.Request) {
	configuration := server.config.Current().Config
	form := pages.RuleSetFormView{Default: request.URL.Query().Get("default") == "1", DefaultLists: configuration.Blocking.DefaultLists}
	for _, list := range configuration.Blocking.Lists {
		form.Lists = append(form.Lists, list.Name)
	}
	if name := request.URL.Query().Get("name"); name != "" && !form.Default {
		index := slices.IndexFunc(configuration.Blocking.RuleSets, func(set config.RuleSet) bool { return set.Name == name })
		if index < 0 {
			server.renderRuleSetProblem(writer, request, refuse(http.StatusNotFound, "No rule set is called %s. It may have been deleted.", name))
			return
		}
		form.Original = name
		form.Set = ruleSetView(configuration.Blocking.RuleSets[index])
	}
	writer.Header().Set("Cache-Control", "no-store")
	server.render(writer, request, pages.RuleSetForm(form))
}

func (server *Server) saveRuleSet(writer http.ResponseWriter, request *http.Request) {
	if err := request.ParseForm(); err != nil {
		server.renderRuleSetProblem(writer, request, refuse(http.StatusBadRequest, "Sable could not read the form."))
		return
	}
	set := config.RuleSet{Name: strings.TrimSpace(request.FormValue("name")), Lists: request.Form["lists"]}
	var err error
	if set.Domains, err = ruleSetDomains(request.FormValue("domains"), "blocked"); err == nil {
		set.AllowedDomains, err = ruleSetDomains(request.FormValue("allowed_domains"), "allowed")
	}
	message := ""
	if err == nil {
		message, err = server.ruleSetService().Save(request.Context(), requestActor(request, ""), request.FormValue("original"), set)
	}
	if err != nil {
		server.renderRuleSetProblem(writer, request, err)
		return
	}
	server.renderPolicyChange(writer, request, ruleSetsTab, message, nil)
}

func (server *Server) deleteRuleSet(writer http.ResponseWriter, request *http.Request) {
	if err := request.ParseForm(); err != nil {
		server.renderPolicyChange(writer, request, ruleSetsTab, "", refuse(http.StatusBadRequest, "Invalid rule set form."))
		return
	}
	message, err := server.ruleSetService().Delete(request.Context(), requestActor(request, ""), request.FormValue("name"))
	server.renderPolicyChange(writer, request, ruleSetsTab, message, err)
}

func (server *Server) saveDefaultLists(writer http.ResponseWriter, request *http.Request) {
	if err := request.ParseForm(); err != nil {
		server.renderRuleSetProblem(writer, request, refuse(http.StatusBadRequest, "Sable could not read the form."))
		return
	}
	var lists []string
	// "Every list" sends no lists, which is what an empty choice means too.
	if request.FormValue("scope") == "chosen" {
		lists = request.Form["lists"]
		if len(lists) == 0 {
			server.renderRuleSetProblem(writer, request, refuse(http.StatusUnprocessableEntity, "Choose at least one block list, or Every Block List."))
			return
		}
	}
	message, err := server.ruleSetService().SetDefaultLists(request.Context(), requestActor(request, ""), lists)
	if err != nil {
		server.renderRuleSetProblem(writer, request, err)
		return
	}
	server.renderPolicyChange(writer, request, ruleSetsTab, message, nil)
}

// renderRuleSetProblem shows why the rule set dialog could not save, inside
// it, leaving what was typed alone.
func (server *Server) renderRuleSetProblem(writer http.ResponseWriter, request *http.Request, err error) {
	writer.Header().Set("HX-Retarget", "#rule-set-notice")
	writer.Header().Set("HX-Reswap", "innerHTML")
	writeFragmentStatus(writer, serviceStatus(err))
	server.render(writer, request, pages.ToastSticky(sentence(err.Error()), "error"))
}

// ruleSetDomains reads one domain per line, or separated by commas, as the
// rule set dialog's text boxes take them.
func ruleSetDomains(value, kind string) ([]string, error) {
	var domains []string
	for _, line := range splitFormLines(value) {
		if strings.TrimSpace(line) == "" {
			continue
		}
		domain, err := normalizePolicyEntry(strings.TrimSuffix(strings.TrimSpace(line), "."))
		if err != nil {
			return nil, refuse(http.StatusUnprocessableEntity, "%s is not a valid %s domain: %v", strings.TrimSpace(line), kind, err)
		}
		if !slices.Contains(domains, domain) {
			domains = append(domains, domain)
		}
	}
	return domains, nil
}

// ruleSetViews describes each rule set with the devices in it, by the name
// the operator or UniFi gave each one, or its address.
func (server *Server) ruleSetViews(ctx context.Context, configuration config.Config) []pages.RuleSetView {
	var given *devices.GivenNames
	name := func(client config.Client) string {
		if client.Name != "" {
			return client.Name
		}
		if given == nil {
			names := server.givenClientNames(ctx, time.Now().Add(-devices.Lookback))
			given = &names
		}
		if client.MAC != "" {
			return cmp.Or(given.Hardware(client.MAC), client.MAC)
		}
		return cmp.Or(given.Address(client.Address), client.Address)
	}
	views := make([]pages.RuleSetView, 0, len(configuration.Blocking.RuleSets))
	for _, set := range configuration.Blocking.RuleSets {
		view := ruleSetView(set)
		for _, client := range configuration.Clients {
			if client.RuleSet == set.Name {
				view.Devices = append(view.Devices, name(client))
			}
		}
		views = append(views, view)
	}
	return views
}

func ruleSetView(set config.RuleSet) pages.RuleSetView {
	return pages.RuleSetView{
		Name: set.Name, Lists: slices.Clone(set.Lists),
		Domains: slices.Clone(set.Domains), AllowedDomains: slices.Clone(set.AllowedDomains),
	}
}
