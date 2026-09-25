package web

import (
	"cmp"
	"fmt"
	"net/http"
	"slices"
	"time"

	"github.com/drudge/sable/internal/insights/devices"
	"github.com/drudge/sable/internal/insights/services"
	"github.com/drudge/sable/internal/web/pages"
)

// insightsAppDevices bounds how many devices an app's drawer lists.
const insightsAppDevices = 50

// insightsAppPanel loads one app's details into the open drawer: the domains
// it was reached at, counted as Top Apps counts them, and the devices that
// looked it up.
func (server *Server) insightsAppPanel(writer http.ResponseWriter, request *http.Request) {
	console := server.consoleView(request)
	if !console.CanLogs {
		server.authenticationFailure(writer, request, http.StatusForbidden, "")
		return
	}
	window := insightsWindow(request.URL.Query().Get("range"), time.Now())
	view := pages.InsightAppDrawerView{Range: window.Range}
	queries, counts := server.queries.(queryInsightReader)
	reader, groups := server.queries.(deviceInsightReader)
	if !counts || !groups {
		writeFragmentStatus(writer, http.StatusServiceUnavailable)
		view.Error = "App details are not available for this database."
		server.renderAppDrawer(writer, request, view)
		return
	}
	service, known := services.Find(request.URL.Query().Get("id"))
	counted, countedWindow, err := server.appCache.load(request.Context(), window, queries.QueryLogInsights)
	if err != nil {
		server.logger.Warn("read app domains", "error", err)
		writeFragmentStatus(writer, http.StatusInternalServerError)
		view.Error = "App details could not be loaded right now."
		server.renderAppDrawer(writer, request, view)
		return
	}
	view.LogWindowQuery = countedWindow.logWindowQuery()
	domains := make([]pages.InsightDeviceDomainView, 0)
	for name, hits := range counted.Domains {
		if owner, found := services.Lookup(name); known && found && owner.ID == service.ID {
			domains = append(domains, pages.InsightDeviceDomainView{Name: name, Queries: hits})
			view.App.Queries += hits
		}
	}
	if len(domains) == 0 {
		view.Missing = true
		server.renderAppDrawer(writer, request, view)
		return
	}
	slices.SortFunc(domains, func(left, right pages.InsightDeviceDomainView) int {
		return cmp.Or(cmp.Compare(right.Queries, left.Queries), cmp.Compare(left.Name, right.Name))
	})
	view.App.ID, view.App.Name, view.App.Category, view.App.Domains = service.ID, service.Name, service.Category, len(domains)
	view.Domains = domains[:min(len(domains), insightsDeviceDomains)]

	used, err := reader.ClientNamesMatching(request.Context(), countedWindow.Start, services.Suffixes([]string{service.ID}))
	if err != nil {
		server.logger.Warn("read app devices", "error", err)
	}
	report, err := server.insightDevices(request.Context(), reader, window)
	if err != nil {
		server.logger.Warn("build insights devices", "error", err)
	}
	for _, device := range report.devices {
		if !slices.ContainsFunc(device.Addresses, func(address devices.Address) bool { return len(used[address.Address]) > 0 }) {
			continue
		}
		if len(view.Devices) == insightsAppDevices {
			view.MoreDevices++
			continue
		}
		label := devices.Label(device)
		row := pages.InsightAppDeviceView{Key: device.Key, Label: label, Named: device.Name != "", Detail: deviceAddressDetail(label, device.ClientAddresses())}
		if device.Guess.Type != "" {
			row.Type, row.TypeLabel, row.TypeConfidence = device.Guess.Type, devices.TypeLabel(device.Guess.Type), string(device.Guess.Confidence)
		}
		view.Devices = append(view.Devices, row)
	}
	server.renderAppDrawer(writer, request, view)
}

func (server *Server) renderAppDrawer(writer http.ResponseWriter, request *http.Request, view pages.InsightAppDrawerView) {
	if err := pages.InsightAppDrawer(view).Render(request.Context(), writer); err != nil {
		server.logger.Error("render insights app", "error", err)
	}
}

// deviceAddressDetail names a device's addresses under its label: its one
// address, unless that is the label, or how many it has.
func deviceAddressDetail(label string, addresses []string) string {
	switch {
	case len(addresses) == 1 && addresses[0] != label:
		return addresses[0]
	case len(addresses) > 1:
		return fmt.Sprintf("%d addresses", len(addresses))
	default:
		return ""
	}
}
