package web

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/drudge/sable/internal/insights/devices"
	"github.com/drudge/sable/internal/insights/services"
	"github.com/drudge/sable/internal/querylog"
	"github.com/drudge/sable/internal/web/pages"
)

// insightsAppDevices bounds how many devices an app's drawer lists.
const insightsAppDevices = 50

// appInsightReader is the optional store capability behind the Apps tab, Top
// Apps, and the app drawer.
type appInsightReader interface {
	AppActivity(context.Context, time.Time, time.Time) (querylog.AppActivity, error)
	AppDomains(context.Context, time.Time, time.Time, []string) ([]querylog.AppDomain, error)
	AppSightings(context.Context) (querylog.AppSightings, error)
	LastLookup(context.Context, []string, querylog.Source, time.Time, time.Time) (time.Time, error)
}

// appSightings reads when each app was first and last used. The window only
// keys the cache; sightings span all history.
func appSightings(reader appInsightReader) func(context.Context, time.Time, time.Time) (querylog.AppSightings, error) {
	return func(ctx context.Context, _, _ time.Time) (querylog.AppSightings, error) {
		return reader.AppSightings(ctx)
	}
}

// appUsage is one app's traffic in a window, with how many devices it came
// from.
type appUsage struct {
	service services.Service
	counts  querylog.AppCounts
	devices int
}

// appUsages totals each app's traffic, busiest first. Addresses the device
// report ties to one device count as that device; the rest count alone.
func appUsages(activity querylog.AppActivity, report deviceReport) []appUsage {
	owners := make(map[string]string)
	for _, device := range report.devices {
		for _, address := range device.Addresses {
			owners[address.Address] = device.Key
		}
	}
	usages := make([]appUsage, 0, len(activity.Clients))
	for id, clients := range activity.Clients {
		service, found := services.Find(id)
		if !found {
			continue
		}
		usage := appUsage{service: service}
		seen := make(map[string]struct{}, len(clients))
		for client, counts := range clients {
			usage.counts.Queries += counts.Queries
			usage.counts.Failed += counts.Failed
			usage.counts.Blocked += counts.Blocked
			seen[cmp.Or(owners[client], client)] = struct{}{}
		}
		usage.devices = len(seen)
		usages = append(usages, usage)
	}
	slices.SortFunc(usages, func(left, right appUsage) int {
		return cmp.Or(cmp.Compare(right.counts.Queries, left.counts.Queries), cmp.Compare(left.service.Name, right.service.Name))
	})
	return usages
}

// appFailingWindow is how recently an app must have failed to count as
// failing now. Failures older than that are history, most often a problem
// already fixed.
const appFailingWindow = "hour"

// An app is failing now when, in the last hour, at least appFailingShare
// percent of its lookups failed and at least appFailingMinimum of them did.
// One upstream timeout fails about three lookups as the device retries, so
// the minimum keeps a quiet app from flagging on a single blip, and the
// share keeps a busy app from flagging on a few in thousands. A device that
// is refused outright fails every lookup and clears both.
const (
	appFailingShare   = 1
	appFailingMinimum = 5
)

// appFailing reports whether an app's last hour counts as failing now.
func appFailing(counts querylog.AppCounts) bool {
	return counts.Failed >= appFailingMinimum && counts.Failed*100 >= counts.Queries*appFailingShare
}

// insightApps loads the Overview's Top Apps and the Apps tab together, since
// both come from one count. A report of no devices counts each address as its
// own device.
func (server *Server) insightApps(ctx context.Context, window insightWindow, report deviceReport) (top []pages.RankedStatView, rows []pages.InsightAppRowView, activity querylog.AppActivity, err error) {
	reader, ok := server.queries.(appInsightReader)
	if !ok {
		return nil, nil, activity, errAppsUnavailable
	}
	activity, counted, err := server.appActivityCache.load(ctx, window, reader.AppActivity)
	if err != nil {
		return nil, nil, activity, err
	}
	failingNow := make(map[string]bool)
	recentWindow, _ := chartInsightWindow(appFailingWindow, counted.End)
	if recent, _, err := server.appActivityCache.load(ctx, recentWindow, reader.AppActivity); err != nil {
		server.logger.Warn("read recent app failures", "error", err)
	} else {
		for app, clients := range recent.Clients {
			var total querylog.AppCounts
			for _, counts := range clients {
				total.Queries += counts.Queries
				total.Failed += counts.Failed
			}
			failingNow[app] = appFailing(total)
		}
	}
	sightings, _, err := server.appSightingCache.load(ctx, window, appSightings(reader))
	if err != nil {
		// The list still stands without when each app was first and last used.
		server.logger.Warn("read app sightings", "error", err)
	}
	usages := appUsages(activity, report)
	top = make([]pages.RankedStatView, 0, min(len(usages), insightsRankLimit))
	rows = make([]pages.InsightAppRowView, 0, len(usages))
	for _, usage := range usages {
		service := usage.service
		// Operating system check-ins are not apps anyone chose to use, so the
		// ranking leaves them to the Apps tab.
		if service.Category != services.CategoryPlatform && len(top) < insightsRankLimit {
			top = append(top, pages.RankedStatView{
				Name: service.Name, Secondary: service.Category, Value: usage.counts.Queries,
				Drawer: pages.AppDrawerLink(service.ID, window.Range),
				Icon:   pages.AppIcon(service.ID, service.Category),
			})
		}
		sighting := sightings.Apps[service.ID]
		rows = append(rows, pages.InsightAppRowView{
			ID: service.ID, Name: service.Name, Category: service.Category, Devices: usage.devices,
			Queries: usage.counts.Queries, Failed: usage.counts.Failed, Blocked: usage.counts.Blocked,
			LastSeen: sighting.LastSeen, FailingNow: failingNow[service.ID],
			New: !sighting.FirstSeen.IsZero() && !sighting.FirstSeen.Before(counted.Start) &&
				!sightings.SeenSince.IsZero() && sightings.SeenSince.Add(time.Hour).Before(sighting.FirstSeen),
		})
	}
	return top, rows, activity, nil
}

// errAppsUnavailable reports a store that cannot count apps.
var errAppsUnavailable = errors.New("app activity is not available for this database")

// insightsAppShows are the Apps tab's choices of which apps to show.
var insightsAppShows = map[string]struct{}{"failing": {}, "blocked": {}, "new": {}}

// insightAppFilter reads the Apps tab's search and filters, from the request
// or, for a range change or refresh, from the page URL htmx reports.
func insightAppFilter(request *http.Request) pages.InsightAppFilterView {
	values := request.URL.Query()
	if !values.Has("app_search") && !values.Has("category") && !values.Has("app_show") {
		if current, err := url.Parse(request.Header.Get("HX-Current-URL")); err == nil {
			values = current.Query()
		}
	}
	filter := pages.InsightAppFilterView{Search: strings.TrimSpace(values.Get("app_search"))}
	if len(filter.Search) > maximumDeviceSearch {
		filter.Search = strings.ToValidUTF8(filter.Search[:maximumDeviceSearch], "")
	}
	if category := values.Get("category"); slices.ContainsFunc(services.All(), func(service services.Service) bool { return service.Category == category }) {
		filter.Category = category
	}
	if _, offered := insightsAppShows[values.Get("app_show")]; offered {
		filter.Show = values.Get("app_show")
	}
	return filter
}

// insightsAppPanel loads one app's details into the open drawer: its traffic,
// the names it was reached at and which of them failed, and the devices that
// used it, from every lookup rather than the busiest names.
func (server *Server) insightsAppPanel(writer http.ResponseWriter, request *http.Request) {
	console := server.consoleView(request)
	if !console.CanLogs {
		server.authenticationFailure(writer, request, http.StatusForbidden, "")
		return
	}
	window := insightsWindow(request.URL.Query().Get("range"), time.Now())
	view := pages.InsightAppDrawerView{Range: window.Range, RangeLabel: window.Label, TimeDisplay: console.TimeDisplay}
	apps, counts := server.queries.(appInsightReader)
	reader, groups := server.queries.(deviceInsightReader)
	if !counts || !groups {
		writeFragmentStatus(writer, http.StatusServiceUnavailable)
		view.Error = "App details are not available for this database."
		server.renderAppDrawer(writer, request, view)
		return
	}
	service, known := services.Find(request.URL.Query().Get("id"))
	activity, countedWindow, err := server.appActivityCache.load(request.Context(), window, apps.AppActivity)
	if err != nil {
		server.logger.Warn("read app activity", "error", err)
		writeFragmentStatus(writer, http.StatusInternalServerError)
		view.Error = "App details could not be loaded right now."
		server.renderAppDrawer(writer, request, view)
		return
	}
	view.LogWindowQuery = countedWindow.logWindowQuery()
	clients := activity.Clients[service.ID]
	if !known || len(clients) == 0 {
		view.Missing = true
		server.renderAppDrawer(writer, request, view)
		return
	}
	view.App.ID, view.App.Name, view.App.Category = service.ID, service.Name, service.Category
	for _, counts := range clients {
		view.App.Queries += counts.Queries
		view.App.Failed += counts.Failed
		view.App.Blocked += counts.Blocked
	}

	domains, err := apps.AppDomains(request.Context(), countedWindow.Start, countedWindow.End, services.Suffixes([]string{service.ID}))
	if err != nil {
		server.logger.Warn("read app domains", "error", err)
	}
	view.App.Domains = len(domains)
	var failing, blocked []string
	for _, domain := range domains {
		if domain.Failed > 0 {
			failing = append(failing, domain.Name)
		}
		if domain.Blocked > 0 {
			blocked = append(blocked, domain.Name)
		}
	}
	if view.App.LastFailed, err = apps.LastLookup(request.Context(), failing, querylog.SourceError, countedWindow.Start, countedWindow.End); err != nil {
		server.logger.Warn("read last app failure", "error", err)
	}
	if view.App.LastBlocked, err = apps.LastLookup(request.Context(), blocked, querylog.SourceBlocked, countedWindow.Start, countedWindow.End); err != nil {
		server.logger.Warn("read last app block", "error", err)
	}
	slices.SortFunc(domains, func(left, right querylog.AppDomain) int {
		return cmp.Or(cmp.Compare(right.Queries, left.Queries), cmp.Compare(left.Name, right.Name))
	})
	for _, domain := range domains[:min(len(domains), insightsDeviceDomains)] {
		view.Domains = append(view.Domains, pages.InsightDeviceDomainView{Name: domain.Name, Queries: domain.Queries, Failed: domain.Failed})
	}
	slices.SortFunc(domains, func(left, right querylog.AppDomain) int {
		return cmp.Or(cmp.Compare(right.Failed, left.Failed), cmp.Compare(left.Name, right.Name))
	})
	for _, domain := range domains {
		if domain.Failed == 0 || len(view.Failures) == insightsDeviceDomains {
			break
		}
		view.Failures = append(view.Failures, pages.InsightDeviceDomainView{Name: domain.Name, Queries: domain.Queries, Failed: domain.Failed})
	}

	report, err := server.insightDevices(request.Context(), reader, window)
	if err != nil {
		server.logger.Warn("build insights devices", "error", err)
	}
	view.Devices, view.MoreDevices = appDeviceViews(clients, report)
	server.renderAppDrawer(writer, request, view)
}

// appDeviceViews lists the devices behind an app's clients, busiest first,
// each with its queries and failures summed across its addresses. An address
// no device claims is listed as itself.
func appDeviceViews(clients map[string]querylog.AppCounts, report deviceReport) ([]pages.InsightAppDeviceView, int) {
	byDevice := make(map[string]*pages.InsightAppDeviceView)
	order := make([]*pages.InsightAppDeviceView, 0)
	claimed := make(map[string]bool, len(clients))
	for _, device := range report.devices {
		var row *pages.InsightAppDeviceView
		for _, address := range device.Addresses {
			counts, used := clients[address.Address]
			if !used {
				continue
			}
			claimed[address.Address] = true
			if row == nil {
				label := devices.Label(device)
				row = &pages.InsightAppDeviceView{Key: device.Key, Label: label, Named: device.Name != "", Detail: deviceAddressDetail(label, device.ClientAddresses())}
				if device.Guess.Type != "" {
					row.Type, row.TypeLabel, row.TypeConfidence = device.Guess.Type, devices.TypeLabel(device.Guess.Type), string(device.Guess.Confidence)
				}
				byDevice[device.Key] = row
				order = append(order, row)
			}
			row.Queries += counts.Queries
			row.Failed += counts.Failed
		}
	}
	for client, counts := range clients {
		if claimed[client] {
			continue
		}
		order = append(order, &pages.InsightAppDeviceView{Key: client, Label: client, Queries: counts.Queries, Failed: counts.Failed})
	}
	slices.SortFunc(order, func(left, right *pages.InsightAppDeviceView) int {
		return cmp.Or(cmp.Compare(right.Queries, left.Queries), cmp.Compare(left.Label, right.Label))
	})
	views := make([]pages.InsightAppDeviceView, 0, min(len(order), insightsAppDevices))
	for _, row := range order[:min(len(order), insightsAppDevices)] {
		views = append(views, *row)
	}
	return views, len(order) - len(views)
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
