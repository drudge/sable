package web

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"net/url"
	"strings"
	"time"

	"github.com/drudge/sable/internal/config"
	"github.com/drudge/sable/internal/dnsprovider"
	"github.com/drudge/sable/internal/insights"
	blockinginsights "github.com/drudge/sable/internal/insights/blocking"
	"github.com/drudge/sable/internal/insights/devices"
	"github.com/drudge/sable/internal/querylog"
	"github.com/drudge/sable/internal/web/pages"
	zonemodel "github.com/drudge/sable/internal/zone"
)

// The analyzers themselves live in internal/insights. The console only
// supplies their data: each source below reads through the console's caches
// and stores for one request, honors the operator's permissions, and keeps
// what it loaded so the page can show the same material the analyzers
// examined without loading it twice.

// errActivityUnavailable reports a query log store that cannot aggregate
// history, which leaves query-based findings out rather than guessing.
var errActivityUnavailable = errors.New("query history is not available for insights")

// insightAnalyzers returns the analyzers the operator's permissions allow,
// with the sources the page reuses for its own sections. Each runs with the
// limits in Insights settings and skips the kinds that are off.
func (server *Server) insightAnalyzers(console pages.DashboardView, window insightWindow) ([]insights.Analyzer, *blockingSources, *deviceSources) {
	configuration := server.config.Current().Config
	blocking := &blockingSources{server: server, console: console, window: window, configuration: configuration.Blocking}
	settings := configuration.Insights.Findings
	off := insightModesOf(settings).off()
	analyzers := []insights.Analyzer{}
	var deviceData *deviceSources
	if console.CanLogs {
		if reader, ok := server.queries.(deviceInsightReader); ok {
			deviceData = &deviceSources{server: server, reader: reader, window: window}
			analyzers = append(analyzers, devices.Analyzer{Sources: deviceData, Limits: insightDeviceLimits(settings), Off: off})
		}
	}
	analyzers = append(analyzers, blockinginsights.Analyzer{Sources: blocking, Limits: insightBlockingLimits(settings), Off: off})
	return analyzers, blocking, deviceData
}

// blockingSources feeds the blocking analyzer.
type blockingSources struct {
	server        *Server
	console       pages.DashboardView
	window        insightWindow
	configuration config.Blocking

	activityLoaded bool
	activity       *querylog.BlockingActivity
	counted        insightWindow
	activityErr    error

	contributionLoaded bool
	contribution       *blockinginsights.Contribution
	contributionErr    error
}

// loadActivity counts the window's blocked queries once per request.
func (sources *blockingSources) loadActivity(ctx context.Context) (*querylog.BlockingActivity, error) {
	if sources.activityLoaded {
		return sources.activity, sources.activityErr
	}
	sources.activityLoaded = true
	sources.counted = sources.window
	if !sources.console.CanLogs {
		return nil, nil
	}
	reader, ok := sources.server.queries.(blockingInsightReader)
	if !ok {
		sources.activityErr = errActivityUnavailable
		return nil, sources.activityErr
	}
	activity, counted, err := sources.server.blockingActivityCache.load(ctx, sources.window, reader.BlockingActivity)
	if err != nil {
		sources.activityErr = err
		return nil, err
	}
	sources.activity, sources.counted = &activity, counted
	return sources.activity, nil
}

func (sources *blockingSources) Contribution(ctx context.Context) (*blockinginsights.Contribution, error) {
	if sources.contributionLoaded {
		return sources.contribution, sources.contributionErr
	}
	sources.contributionLoaded = true
	if !sources.console.CanBlocking {
		return nil, nil
	}
	lists := make([]blockinginsights.List, 0, len(sources.configuration.Lists))
	for _, list := range sources.configuration.Lists {
		lists = append(lists, blockinginsights.List{Name: list.Name, Path: list.Path, URL: list.URL, Format: list.Format})
	}
	contribution, err := sources.server.blockListAnalysis.Contribution(ctx, sources.server.baseDirectory, lists)
	if err != nil {
		sources.contributionErr = err
		return nil, err
	}
	sources.contribution = &contribution
	return sources.contribution, nil
}

func (sources *blockingSources) ListHealth() ([]blockinginsights.ListHealth, time.Duration) {
	interval := sources.configuration.UpdateInterval.Duration
	if !sources.console.CanBlocking {
		return nil, interval
	}
	status := sources.server.blockLists.Status()
	byURL := make(map[string]blockinginsights.ListHealth, len(status.Sources))
	for _, source := range status.Sources {
		byURL[source.URL] = blockinginsights.ListHealth{Health: source}
	}
	health := make([]blockinginsights.ListHealth, 0, len(sources.configuration.Lists))
	for _, list := range sources.configuration.Lists {
		if tracked, found := byURL[list.URL]; found && list.URL != "" {
			tracked.Name = list.Name
			health = append(health, tracked)
		}
	}
	return health, interval
}

func (sources *blockingSources) SourceQueries(ctx context.Context, _ insights.Window) (*blockinginsights.SourceQueries, error) {
	activity, err := sources.loadActivity(ctx)
	if err != nil || activity == nil {
		// Missing history drops the query counts, not the list findings.
		return nil, nil
	}
	return &blockinginsights.SourceQueries{Lists: activity.Sources, Since: activity.SourcesSince}, nil
}

// PastBlocks needs both halves of the evidence: the allow rule is blocking
// configuration and the blocked queries are query history.
func (sources *blockingSources) PastBlocks(ctx context.Context, _ insights.Window) ([]blockinginsights.PastBlock, error) {
	if !sources.console.CanBlocking {
		return nil, nil
	}
	if activity, err := sources.loadActivity(ctx); err != nil || activity == nil {
		return nil, nil
	}
	reader, ok := sources.server.queries.(blockingInsightReader)
	if !ok {
		return nil, nil
	}
	return sources.server.pastBlocks(ctx, reader, sources.counted, sources.configuration), nil
}

// deviceSources feeds the device analyzer.
type deviceSources struct {
	server *Server
	reader deviceInsightReader
	window insightWindow

	loaded bool
	report deviceReport
	err    error
}

func (sources *deviceSources) load(ctx context.Context) (deviceReport, error) {
	if !sources.loaded {
		sources.loaded = true
		sources.report, sources.err = sources.server.insightDevices(ctx, sources.reader, sources.window)
	}
	return sources.report, sources.err
}

func (sources *deviceSources) Devices(ctx context.Context, _ insights.Window) (devices.Report, error) {
	report, err := sources.load(ctx)
	if err != nil {
		return devices.Report{}, err
	}
	return devices.Report{
		Devices: report.devices, SeenSince: report.seenSince,
		Window: insights.Window{Start: report.window.Start, End: report.window.End},
	}, nil
}

func (sources *deviceSources) NewDomains(ctx context.Context, device devices.Device, window insights.Window) ([]insights.DomainEvidence, error) {
	found, err := sources.reader.ClientNewDomains(ctx, device.ClientAddresses(), window.Start, window.End, insightsDeviceDomains)
	if err != nil {
		sources.server.logger.Warn("read device first-time domains", "error", err)
		return nil, err
	}
	return domainEvidence(device, found), nil
}

func (sources *deviceSources) DomainHistory(ctx context.Context, device devices.Device) ([]insights.DomainEvidence, bool, error) {
	history, err := sources.reader.ClientDomainHistory(ctx, device.ClientAddresses(), insightsDomainHistoryLimit)
	if err != nil {
		sources.server.logger.Warn("read device domain history", "error", err)
		return nil, false, err
	}
	return domainEvidence(device, history), len(history) < insightsDomainHistoryLimit, nil
}

func (sources *deviceSources) HourlyActivity(ctx context.Context, since time.Time) (map[string]map[time.Time]uint64, error) {
	report, err := sources.load(ctx)
	if err != nil {
		return nil, err
	}
	activity, err := sources.reader.ClientHourlyActivity(ctx, since, report.window.End)
	if err != nil {
		sources.server.logger.Warn("read device hourly activity", "error", err)
	}
	return activity, err
}

// RepeatedLookups reads the last day's repeated lookups once per window and
// leaves out names in zones this server answers for, which are the network's
// own hosts rather than anything a device phones home to, and the lookups a
// Sable server makes for itself, such as its dynamic DNS updates.
func (sources *deviceSources) RepeatedLookups(ctx context.Context, since time.Time) ([]querylog.LookupTimes, error) {
	lookups, _, err := sources.server.repeatedLookupCache.load(ctx, sources.window, repeatedLookups(sources.reader, since))
	if err != nil {
		sources.server.logger.Warn("read repeated lookups", "error", err)
		return nil, err
	}
	zones := sources.server.zones.Current().Zones
	servers, own := sources.server.sableServers(), ownLookups(sources.server.config.Current().Config)
	kept := make([]querylog.LookupTimes, 0, len(lookups))
	for _, lookup := range lookups {
		ownLookup := servers[lookup.Client] != "" && own[strings.TrimSuffix(strings.ToLower(lookup.Name), ".")]
		if ownLookup || inLocalZone(lookup.Name, zones) {
			continue
		}
		kept = append(kept, lookup)
	}
	return kept, nil
}

// repeatedLookups reads the names one client looked up again and again from
// since to the end of the window.
func repeatedLookups(reader deviceInsightReader, since time.Time) func(context.Context, time.Time, time.Time) ([]querylog.LookupTimes, error) {
	return func(ctx context.Context, _, until time.Time) ([]querylog.LookupTimes, error) {
		return reader.RepeatedLookups(ctx, since, until)
	}
}

func inLocalZone(name string, zones []zonemodel.Zone) bool {
	name = strings.TrimSuffix(strings.ToLower(name), ".")
	for _, zone := range zones {
		origin := strings.TrimSuffix(strings.ToLower(zone.Name), ".")
		if origin != "" && (name == origin || strings.HasSuffix(name, "."+origin)) {
			return true
		}
	}
	return false
}

// Labels for the devices that run Sable.
const (
	thisServerLabel = "This server"
	sableNodeLabel  = "Sable node"
)

// sableServers marks the client addresses of Sable servers: every address of
// this host, which is where Sable's own lookups come from when the host
// resolves through it, and the DNS addresses of the rest of its cluster.
func (server *Server) sableServers() map[string]string {
	servers := make(map[string]string)
	if server.cluster != nil {
		state := server.cluster.Snapshot()
		for _, node := range state.Nodes {
			label := sableNodeLabel
			if node.ID == state.NodeID {
				label = thisServerLabel
			}
			for _, address := range node.Addresses {
				if parsed, err := netip.ParseAddrPort(address); err == nil {
					servers[parsed.Addr().Unmap().String()] = label
				} else if parsed, err := netip.ParseAddr(address); err == nil {
					servers[parsed.Unmap().String()] = label
				}
			}
		}
	}
	assigned, _ := net.InterfaceAddrs()
	for _, address := range assigned {
		if prefix, err := netip.ParsePrefix(address.String()); err == nil {
			servers[prefix.Addr().Unmap().WithZone("").String()] = thisServerLabel
		}
	}
	return servers
}

// ownLookups lists the names Sable looks up for itself on a timer: where it
// discovers its public address and its provider's API for dynamic DNS, the
// UniFi controller, and block list downloads.
func ownLookups(configuration config.Config) map[string]bool {
	names := make(map[string]bool)
	add := func(endpoint string) {
		if parsed, err := url.Parse(strings.TrimSpace(endpoint)); err == nil && parsed.Hostname() != "" {
			names[strings.ToLower(parsed.Hostname())] = true
		}
	}
	if settings := configuration.DynamicDNS; settings.Runnable() {
		add(settings.IPv4URL)
		add(settings.IPv6URL)
		for _, provider := range settings.ProviderNames() {
			for _, host := range dnsprovider.APIHosts(provider) {
				names[host] = true
			}
		}
	}
	if configuration.UniFi.Enabled {
		add(configuration.UniFi.ControllerURL)
	}
	for _, list := range configuration.Blocking.Lists {
		add(list.URL)
	}
	return names
}
