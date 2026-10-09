package web

import (
	"cmp"
	"context"
	"maps"
	"net"
	"net/http"
	"net/netip"
	"slices"
	"strings"
	"time"

	"github.com/drudge/sable/internal/config"
	"github.com/drudge/sable/internal/insights/devices"
	"github.com/drudge/sable/internal/querylog"
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
	set := config.RuleSet{Name: strings.TrimSpace(request.FormValue("name")), Off: request.FormValue("off") == "true", Lists: request.Form["lists"]}
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

// ruleSetViews describes each rule set with the devices in it.
func (server *Server) ruleSetViews(ctx context.Context, configuration config.Config) []pages.RuleSetView {
	label := server.clientLabeler(ctx)
	views := make([]pages.RuleSetView, 0, len(configuration.Blocking.RuleSets))
	for _, set := range configuration.Blocking.RuleSets {
		view := ruleSetView(set)
		for _, client := range configuration.Clients {
			if client.RuleSet == set.Name {
				view.Devices = append(view.Devices, pages.RuleSetDevice{
					Label: label(client), Entry: cmp.Or(client.MAC, client.Address), Kind: clientEntryKind(client), Type: client.Type,
				})
			}
		}
		views = append(views, view)
	}
	return views
}

// clientLabeler names devices by the name the operator or UniFi gave each
// one, or else its hardware address or address. It reads the given names
// only when a device needs them.
func (server *Server) clientLabeler(ctx context.Context) func(config.Client) string {
	var given *devices.GivenNames
	return func(client config.Client) string {
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
}

func clientEntryKind(client config.Client) string {
	switch {
	case client.MAC != "":
		return "mac"
	case strings.Contains(client.Address, "/"):
		return "network"
	default:
		return "address"
	}
}

func ruleSetView(set config.RuleSet) pages.RuleSetView {
	return pages.RuleSetView{
		Name: set.Name, Off: set.Off, Lists: slices.Clone(set.Lists),
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
	if view.CanWrite {
		view.DeviceOptions = server.ruleSetDeviceOptions(request.Context(), configuration, set.Name)
	}
	return view
}

// ruleSetDeviceLimit bounds how many seen devices the Add Device field
// offers.
const ruleSetDeviceLimit = 500

// ruleSetDeviceOptions offers the devices Sable has seen, by hardware
// address when it knows one, and the ones the operator named, leaving out
// those already in the rule set.
func (server *Server) ruleSetDeviceOptions(ctx context.Context, configuration config.Config, name string) []pages.RuleSetDeviceOption {
	taken := map[string]bool{}
	for _, client := range configuration.Clients {
		if client.RuleSet == name {
			taken[cmp.Or(client.MAC, client.Address)] = true
		}
	}
	var identities []querylog.ClientIdentity
	if reader, ok := server.queries.(clientIdentityReader); ok && server.insightsEnabled() {
		var err error
		if identities, err = reader.ClientIdentities(ctx, time.Now().Add(-devices.Lookback)); err != nil {
			server.logger.Warn("read client identities", "error", err)
		}
	}
	given := devices.NewGivenNames(identities, configuration.Clients)
	options := map[string]pages.RuleSetDeviceOption{}
	add := func(entry, label string) {
		if entry == "" || taken[entry] {
			return
		}
		if _, found := options[entry]; !found || label != entry {
			options[entry] = pages.RuleSetDeviceOption{Value: entry, Label: cmp.Or(label, entry)}
		}
	}
	for _, identity := range identities {
		if identity.MAC != "" {
			add(identity.MAC, cmp.Or(given.Hardware(identity.MAC), identity.Hostname))
		} else {
			add(identity.Address, cmp.Or(given.Address(identity.Address), identity.Hostname))
		}
	}
	for _, client := range configuration.Clients {
		add(cmp.Or(client.MAC, client.Address), client.Name)
	}
	list := slices.SortedFunc(maps.Values(options), func(left, right pages.RuleSetDeviceOption) int {
		return cmp.Or(strings.Compare(strings.ToLower(left.Label), strings.ToLower(right.Label)), strings.Compare(left.Value, right.Value))
	})
	return list[:min(len(list), ruleSetDeviceLimit)]
}

func (server *Server) addRuleSetDevice(writer http.ResponseWriter, request *http.Request) {
	server.changeRuleSetDevice(writer, request, true)
}

func (server *Server) deleteRuleSetDevice(writer http.ResponseWriter, request *http.Request) {
	server.changeRuleSetDevice(writer, request, false)
}

// changeRuleSetDevice puts a device, address, or network in a rule set, or
// takes it out, then shows the rule set's panel again with the page beneath.
// A device can be named by what the Add Device field offers or by its name.
func (server *Server) changeRuleSetDevice(writer http.ResponseWriter, request *http.Request, add bool) {
	if err := request.ParseForm(); err != nil {
		server.renderRuleSetChange(writer, request, "", "", refuse(http.StatusBadRequest, "Sable could not read the form."))
		return
	}
	name := request.FormValue("name")
	message, err := server.assignRuleSetDevice(request, name, strings.TrimSpace(request.FormValue("device")), add)
	server.renderRuleSetChange(writer, request, name, message, err)
}

func (server *Server) assignRuleSetDevice(request *http.Request, name, entry string, add bool) (string, error) {
	configuration := server.config.Current().Config
	if !slices.ContainsFunc(configuration.Blocking.RuleSets, func(set config.RuleSet) bool { return set.Name == name }) {
		return "", refuse(http.StatusNotFound, "No rule set is called %s. It may have been deleted.", name)
	}
	if add {
		entry = server.ruleSetDeviceEntry(request.Context(), configuration, name, entry)
	}
	device, ok := readClientEntry(entry)
	if !ok {
		return "", refuse(http.StatusUnprocessableEntity, "Enter a device Sable has seen, an IP address, a network such as 10.0.20.0/24, or a hardware address.")
	}
	label := server.clientLabeler(request.Context())(device)
	current := slices.IndexFunc(configuration.Clients, func(client config.Client) bool { return client.Key() == device.Key() && client.RuleSet == name })
	switch {
	case add && current >= 0:
		return "", refuse(http.StatusUnprocessableEntity, "%s is already in %s.", label, name)
	case !add && current < 0:
		return "", refuse(http.StatusUnprocessableEntity, "%s isn't in %s.", label, name)
	case add:
		device.RuleSet = name
	}
	var addresses []string
	if device.MAC != "" {
		var err error
		if addresses, err = server.deviceAddresses(request.Context(), "mac:"+device.MAC); err != nil {
			return "", err
		}
	}
	return server.ruleSetService().Assign(request.Context(), requestActor(request, ""), device, addresses, label)
}

// ruleSetDeviceEntry turns what was typed into the Add Device field into an
// entry: a device's name becomes the entry the field offers for it.
func (server *Server) ruleSetDeviceEntry(ctx context.Context, configuration config.Config, name, typed string) string {
	if _, ok := readClientEntry(typed); ok {
		return typed
	}
	for _, option := range server.ruleSetDeviceOptions(ctx, configuration, name) {
		if strings.EqualFold(option.Label, typed) {
			return option.Value
		}
	}
	return typed
}

// readClientEntry reads a hardware address, IP address, or network into the
// entry that names it in [[clients]].
func readClientEntry(entry string) (config.Client, bool) {
	if _, err := net.ParseMAC(entry); err == nil {
		return clientForEntry(entry), true
	}
	if _, err := netip.ParsePrefix(entry); err == nil {
		return clientForEntry(entry), true
	}
	if _, err := netip.ParseAddr(entry); err == nil {
		return clientForEntry(entry), true
	}
	return config.Client{}, false
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
