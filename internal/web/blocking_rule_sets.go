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
	message, err := server.ruleSetService().Save(request.Context(), requestActor(request, ""), request.FormValue("original"), set)
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

// ruleSetPanel fills a rule set's panel.
func (server *Server) ruleSetPanel(writer http.ResponseWriter, request *http.Request) {
	writer.Header().Set("Cache-Control", "no-store")
	server.render(writer, request, pages.RuleSetDrawer(server.ruleSetDrawerView(request, request.URL.Query().Get("name"))))
}

func (server *Server) ruleSetDrawerView(request *http.Request, name string) pages.RuleSetDrawerView {
	configuration := server.config.Current().Config
	view := pages.RuleSetDrawerView{CanWrite: server.consoleView(request).CanWriteBlocking}
	index := slices.IndexFunc(configuration.Blocking.RuleSets, func(set config.RuleSet) bool { return set.Name == name })
	if index < 0 {
		view.Missing = true
		return view
	}
	set := configuration.Blocking.RuleSets[index]
	configuration.Blocking.RuleSets = []config.RuleSet{set}
	view.Set = server.ruleSetViews(request.Context(), configuration)[0]
	return view
}

func (server *Server) addRuleSetDomain(writer http.ResponseWriter, request *http.Request) {
	server.changeRuleSetDomain(writer, request, server.policyService().Add)
}

func (server *Server) deleteRuleSetDomain(writer http.ResponseWriter, request *http.Request) {
	server.changeRuleSetDomain(writer, request, server.policyService().Remove)
}

// changeRuleSetDomain adds a domain to, or takes one off, a rule set's own
// blocked or allowed list, then shows its panel again with the page beneath.
func (server *Server) changeRuleSetDomain(
	writer http.ResponseWriter,
	request *http.Request,
	change func(context.Context, actor, string, string, bool) (domainRuleChange, error),
) {
	if err := request.ParseForm(); err != nil {
		server.renderRuleSetChange(writer, request, "", "", refuse(http.StatusBadRequest, "Sable could not read the form."))
		return
	}
	name := request.FormValue("name")
	result, err := change(request.Context(), requestActor(request, ""), name, request.FormValue("domain"), request.FormValue("kind") == "allowed")
	if err == nil && !result.Changed {
		err = refuse(http.StatusUnprocessableEntity, "%s", sentence(result.Message))
	}
	server.renderRuleSetChange(writer, request, name, result.Message, err)
}

func (server *Server) renderRuleSetChange(writer http.ResponseWriter, request *http.Request, name, message string, err error) {
	view := server.ruleSetDrawerView(request, name)
	if err != nil {
		view.Error = sentence(err.Error())
		writeFragmentStatus(writer, serviceStatus(err))
	} else {
		view.Message = sentence(message)
	}
	if !server.render(writer, request, pages.RuleSetDrawer(view)) {
		return
	}
	page := server.blockingView(request, "", "", ruleSetsTab)
	page.OutOfBand = true
	server.render(writer, request, pages.BlockingContent(page))
}
