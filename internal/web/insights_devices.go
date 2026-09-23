package web

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/drudge/sable/internal/config"
	"github.com/drudge/sable/internal/insights"
	"github.com/drudge/sable/internal/insights/devices"
	"github.com/drudge/sable/internal/insights/services"
	"github.com/drudge/sable/internal/querylog"
	"github.com/drudge/sable/internal/web/pages"
)

const (
	// insightsDeviceDomains is how many names the device drawer lists.
	insightsDeviceDomains = 10
	// insightsDeviceAppDomains is how many of a device's busiest names are
	// read to name the apps it used.
	insightsDeviceAppDomains = 500
	// insightsDeviceApps is how many apps the device drawer lists.
	insightsDeviceApps = 8
	// insightsDeviceLimit bounds the device table.
	insightsDeviceLimit = 500
	// insightsDomainHistoryLimit bounds how many names one device's history
	// read returns. A device with more is not checked for new apps.
	insightsDomainHistoryLimit = 20_000
)

// deviceInsightReader is the optional store capability behind Devices and
// What changed.
type deviceInsightReader interface {
	ClientActivity(context.Context, time.Time, time.Time) (querylog.ClientActivityReport, error)
	ClientIdentities(context.Context, time.Time) ([]querylog.ClientIdentity, error)
	ClientNewDomains(context.Context, []string, time.Time, time.Time, int) ([]querylog.ClientDomain, error)
	ClientNewDomainCount(context.Context, []string, time.Time, time.Time) (uint64, error)
	ClientTopDomains(context.Context, []string, time.Time, time.Time, int) ([]querylog.ClientDomain, error)
	ClientDomainHistory(context.Context, []string, int) ([]querylog.ClientDomain, error)
	ClientNamesMatching(context.Context, time.Time, []string) (map[string][]string, error)
	ClientHourlyActivity(context.Context, time.Time, time.Time) (map[string]map[time.Time]uint64, error)
}

// deviceTypeSuffixes are the domains of the services whose use says what a
// device is.
var deviceTypeSuffixes = services.Suffixes(devices.ServiceClueIDs())

// deviceReport is the devices for one window, with when first-seen tracking
// began so "new" is only claimed where it can be.
type deviceReport struct {
	devices   []devices.Device
	seenSince time.Time
	window    insightWindow
}

// insightDevices groups the window's client activity into named devices.
func (server *Server) insightDevices(ctx context.Context, reader deviceInsightReader, window insightWindow) (deviceReport, error) {
	activity, counted, err := server.deviceActivityCache.load(ctx, window, reader.ClientActivity)
	if err != nil {
		return deviceReport{}, err
	}
	identities, err := reader.ClientIdentities(ctx, counted.Start)
	if err != nil {
		return deviceReport{}, err
	}
	snapshot := server.config.Current().Config
	built := devices.Build(devices.Input{
		Activity: activity, Identities: identities, Clients: snapshot.Clients,
		Names: server.discoveredClientNames(activity, snapshot.Resolver.Hosts),
	})
	for index := range built {
		if len(built[index].Addresses) < 2 {
			continue
		}
		// Each address counts its own first-time names; across addresses the
		// same name must count once.
		count, err := reader.ClientNewDomainCount(ctx, built[index].ClientAddresses(), counted.Start, counted.End)
		if err != nil {
			return deviceReport{}, err
		}
		built[index].NewDomains = count
	}
	signals, _, err := server.deviceSignalCache.load(ctx, window, func(ctx context.Context, since, _ time.Time) (map[string][]string, error) {
		return reader.ClientNamesMatching(ctx, since, deviceTypeSuffixes)
	})
	if err != nil {
		// Types then rest on makers and names alone.
		server.logger.Warn("read device service signals", "error", err)
	}
	devices.Identify(built, signals)
	return deviceReport{devices: built, seenSince: activity.SeenSince, window: counted}, nil
}

// discoveredClientNames names addresses from local host entries, local reverse
// zones, and then the resolver's PTR answers, which is what the dashboard uses.
func (server *Server) discoveredClientNames(activity querylog.ClientActivityReport, hosts []config.HostOverride) map[string]devices.DiscoveredName {
	counts := make(map[string]uint64, len(activity.Clients))
	for _, client := range activity.Clients {
		counts[client.Client] = client.Queries + client.Baseline
	}
	local := make(map[string]string)
	for _, host := range hosts {
		for _, address := range host.Addresses {
			local[address] = host.Name
		}
	}
	names := make(map[string]devices.DiscoveredName, len(counts))
	ranked := rankedStats(counts, dashboardClientNames(counts, nil, server.zones.Current().Zones), len(counts))
	server.nameRankedClients(ranked)
	for _, client := range ranked {
		switch {
		case local[client.Name] != "":
			names[client.Name] = devices.DiscoveredName{Name: local[client.Name], Source: devices.SourceLocal}
		case client.Secondary != "":
			names[client.Name] = devices.DiscoveredName{Name: client.Secondary, Source: devices.SourceReverse}
		}
	}
	return names
}

// domainEvidence links each name to the query log only when the device has a
// single address, because a link covers one client address and must reproduce
// what the list says about the whole device.
func domainEvidence(device devices.Device, domains []querylog.ClientDomain) []insights.DomainEvidence {
	evidence := make([]insights.DomainEvidence, 0, len(domains))
	for _, domain := range domains {
		item := insights.DomainEvidence{Name: domain.Name, FirstSeen: domain.FirstSeen}
		if len(device.Addresses) == 1 {
			item.Query = &insights.QueryFilter{Name: domain.Name, ClientIP: device.Addresses[0].Address}
		}
		evidence = append(evidence, item)
	}
	return evidence
}

func insightDeviceViews(report deviceReport) []pages.InsightDeviceView {
	views := make([]pages.InsightDeviceView, 0, min(len(report.devices), insightsDeviceLimit))
	for _, device := range report.devices {
		if device.Queries == 0 {
			continue
		}
		if len(views) == insightsDeviceLimit {
			break
		}
		views = append(views, insightDeviceView(device, report))
	}
	return views
}

func insightDeviceView(device devices.Device, report deviceReport) pages.InsightDeviceView {
	view := pages.InsightDeviceView{
		Key: device.Key, Label: devices.Label(device), Named: device.Name != "", NameSource: device.NameSource,
		MAC: device.MAC, PrivateMAC: device.PrivateMAC, Queries: device.Queries, Blocked: device.Blocked,
		NewDomains: device.NewDomains, FirstSeen: device.FirstSeen, LastSeen: device.LastSeen,
		OperatorNamed: device.Named && device.NameSource == devices.SourceOperator,
		New: !device.FirstSeen.Before(report.window.Start) && !report.seenSince.IsZero() &&
			report.seenSince.Add(time.Hour).Before(device.FirstSeen),
	}
	for _, address := range device.Addresses {
		view.Addresses = append(view.Addresses, pages.InsightDeviceAddressView{Address: address.Address, Queries: address.Queries, Blocked: address.Blocked})
	}
	view.Vendor = device.Vendor
	if device.Guess.Type != "" {
		view.Type, view.TypeLabel, view.TypeConfidence = device.Guess.Type, devices.TypeLabel(device.Guess.Type), string(device.Guess.Confidence)
		for _, reason := range device.Guess.Reasons {
			view.TypeReasons = append(view.TypeReasons, pages.InsightReasonView{Text: reason.Text, Code: reason.Code})
		}
	}
	return view
}

// insightsDevicePanel loads one device's details into the open drawer.
func (server *Server) insightsDevicePanel(writer http.ResponseWriter, request *http.Request) {
	console := server.consoleView(request)
	if !console.CanLogs {
		server.authenticationFailure(writer, request, http.StatusForbidden, "")
		return
	}
	window := insightsWindow(request.URL.Query().Get("range"), time.Now())
	editing := request.URL.Query().Get("edit") == "1"
	server.renderDeviceDrawer(writer, request, console, window, request.URL.Query().Get("key"), editing, "", "")
}

func (server *Server) renderDeviceDrawer(writer http.ResponseWriter, request *http.Request, console pages.DashboardView, window insightWindow, key string, editing bool, message, errorMessage string) {
	view := pages.InsightDeviceDrawerView{
		Range: window.Range, TimeDisplay: console.TimeDisplay, CanName: console.CanWriteSettings,
		Editing: editing && console.CanWriteSettings, Message: message, Error: errorMessage,
	}
	reader, ok := server.queries.(deviceInsightReader)
	if !ok {
		writeFragmentStatus(writer, http.StatusServiceUnavailable)
		view.Error = "Device details are not available for this database."
		server.renderDeviceDrawerView(writer, request, view)
		return
	}
	report, err := server.insightDevices(request.Context(), reader, window)
	if err != nil {
		server.logger.Warn("build insights devices", "error", err)
		writeFragmentStatus(writer, http.StatusInternalServerError)
		view.Error = "Device details could not be loaded right now."
		server.renderDeviceDrawerView(writer, request, view)
		return
	}
	view.LogWindowQuery = report.window.logWindowQuery()
	device, found := devices.Find(report.devices, key)
	if !found {
		view.Missing = true
		server.renderDeviceDrawerView(writer, request, view)
		return
	}
	view.Device = insightDeviceView(device, report)
	view.Device.TypeOptions = devices.TypeLabels()
	addresses := device.ClientAddresses()
	// One ranking feeds both lists: the apps need the long tail, the domain
	// list only its head.
	top, err := reader.ClientTopDomains(request.Context(), addresses, report.window.Start, report.window.End, insightsDeviceAppDomains)
	if err != nil {
		server.logger.Warn("rank device domains", "error", err)
	}
	view.Apps = insightAppViews(top)
	top = top[:min(len(top), insightsDeviceDomains)]
	fresh, err := reader.ClientNewDomains(request.Context(), addresses, report.window.Start, report.window.End, insightsDeviceDomains)
	if err != nil {
		server.logger.Warn("read device first-time domains", "error", err)
	}
	single := len(addresses) == 1
	for _, domain := range top {
		item := pages.InsightDeviceDomainView{Name: domain.Name, Queries: domain.Queries, Blocked: domain.Blocked}
		if single {
			item.ClientIP = addresses[0]
		}
		view.TopDomains = append(view.TopDomains, item)
	}
	for _, domain := range fresh {
		item := pages.InsightDeviceDomainView{Name: domain.Name, FirstSeen: domain.FirstSeen}
		if single {
			item.ClientIP = addresses[0]
		}
		view.NewDomains = append(view.NewDomains, item)
	}
	server.renderDeviceDrawerView(writer, request, view)
}

func (server *Server) renderDeviceDrawerView(writer http.ResponseWriter, request *http.Request, view pages.InsightDeviceDrawerView) {
	if err := pages.InsightDeviceDrawer(view).Render(request.Context(), writer); err != nil {
		server.logger.Error("render insights device", "error", err)
	}
}

// nameInsightsDevice gives a device the operator's own name, or clears it.
func (server *Server) nameInsightsDevice(writer http.ResponseWriter, request *http.Request) {
	console := server.consoleView(request)
	if !console.CanLogs || !console.CanWriteSettings {
		server.authenticationFailure(writer, request, http.StatusForbidden, "")
		return
	}
	request.Body = http.MaxBytesReader(writer, request.Body, maximumFormBytes)
	if err := request.ParseForm(); err != nil {
		writeFragmentStatus(writer, http.StatusBadRequest)
		return
	}
	window := insightsWindow(request.FormValue("range"), time.Now())
	key := request.FormValue("key")
	name := request.FormValue("name")
	if request.FormValue("remove") == "1" {
		name = ""
	}
	client, err := clientForDeviceKey(key, name)
	if err == nil {
		err = server.updateClients(request, func(clients []config.Client) ([]config.Client, error) {
			return config.SetClientName(clients, client)
		})
	}
	if err != nil {
		server.logger.Warn("name insights device", "client", requestClientIP(request), "error", err)
		writeFragmentStatus(writer, http.StatusUnprocessableEntity)
		server.renderDeviceDrawer(writer, request, console, window, key, true, "", err.Error())
		return
	}
	message := "Name saved."
	summary := "named device " + deviceKeyIdentifier(key) + " " + client.Name
	if client.Name == "" {
		message, summary = "Name removed.", "removed the name of device "+deviceKeyIdentifier(key)
	}
	server.recordControlPlaneAudit(request, "insights.device.name", summary)
	// The page behind the drawer shows the old name until it reloads itself.
	writer.Header().Set("HX-Trigger", "insightsChanged")
	server.renderDeviceDrawer(writer, request, console, window, key, false, message, "")
}

// typeInsightsDevice records what kind of device a device is, or returns it
// to Sable's own guess.
func (server *Server) typeInsightsDevice(writer http.ResponseWriter, request *http.Request) {
	console := server.consoleView(request)
	if !console.CanLogs || !console.CanWriteSettings {
		server.authenticationFailure(writer, request, http.StatusForbidden, "")
		return
	}
	request.Body = http.MaxBytesReader(writer, request.Body, maximumFormBytes)
	if err := request.ParseForm(); err != nil {
		writeFragmentStatus(writer, http.StatusBadRequest)
		return
	}
	window := insightsWindow(request.FormValue("range"), time.Now())
	key, kind := request.FormValue("key"), strings.TrimSpace(request.FormValue("type"))
	client, err := clientForDeviceKey(key, "")
	if err == nil {
		client.Type = kind
		err = server.updateClients(request, func(clients []config.Client) ([]config.Client, error) {
			return config.SetClientType(clients, client)
		})
	}
	if err != nil {
		server.logger.Warn("set insights device type", "client", requestClientIP(request), "error", err)
		writeFragmentStatus(writer, http.StatusUnprocessableEntity)
		server.renderDeviceDrawer(writer, request, console, window, key, false, "", err.Error())
		return
	}
	message, summary := "Type saved.", "set device "+deviceKeyIdentifier(key)+" type to "+kind
	if kind == "" {
		message, summary = "Sable will guess this device's type again.", "cleared the type of device "+deviceKeyIdentifier(key)
	}
	server.recordControlPlaneAudit(request, "insights.device.type", summary)
	writer.Header().Set("HX-Trigger", "insightsChanged")
	server.renderDeviceDrawer(writer, request, console, window, key, false, message, "")
}

// updateClients saves a change to the operator's device entries.
func (server *Server) updateClients(request *http.Request, change func([]config.Client) ([]config.Client, error)) error {
	editor, ok := server.config.(settingsEditor)
	if !ok {
		return errors.New("configuration cannot be edited on this server")
	}
	return editor.Update(request.Context(), func(configuration *config.Config) error {
		updated, err := change(configuration.Clients)
		if err != nil {
			return err
		}
		configuration.Clients = updated
		return nil
	})
}

// clientForDeviceKey turns a device key into the configuration entry that
// names it: by hardware address when Sable knows one, by address otherwise.
func clientForDeviceKey(key, name string) (config.Client, error) {
	name = strings.TrimSpace(name)
	switch {
	case strings.HasPrefix(key, "mac:"):
		return config.Client{Name: name, MAC: strings.TrimPrefix(key, "mac:")}, nil
	case strings.HasPrefix(key, "ip:"):
		return config.Client{Name: name, Address: strings.TrimPrefix(key, "ip:")}, nil
	default:
		return config.Client{}, errors.New("unknown device")
	}
}

func deviceKeyIdentifier(key string) string {
	_, identifier, _ := strings.Cut(key, ":")
	return identifier
}

// insightAppViews names the apps behind a device's busiest domains.
func insightAppViews(domains []querylog.ClientDomain) []pages.InsightAppView {
	named := make([]services.Domain, 0, len(domains))
	for _, domain := range domains {
		named = append(named, services.Domain{Name: domain.Name, Queries: domain.Queries})
	}
	usages := services.Group(named)
	views := make([]pages.InsightAppView, 0, min(len(usages), insightsDeviceApps))
	for _, usage := range usages[:min(len(usages), insightsDeviceApps)] {
		views = append(views, pages.InsightAppView{
			Name: usage.Service.Name, Category: usage.Service.Category, Queries: usage.Queries, Domains: len(usage.Domains),
		})
	}
	return views
}
