package web

import (
	"context"
	"slices"
	"time"

	"github.com/drudge/sable/internal/cluster"
	"github.com/drudge/sable/internal/insights/devices"
	"github.com/drudge/sable/internal/querylog"
	"github.com/drudge/sable/internal/unifi"
	"github.com/drudge/sable/internal/web/pages"
)

// coverageInsightReader is the store capability behind finding devices that
// don't use Sable: the UniFi sync's latest reading and when each client
// address last asked this node anything.
type coverageInsightReader interface {
	UniFiReading(context.Context, time.Time) (unifi.Reading, error)
	ClientLastLookups(context.Context, time.Time) (map[string]time.Time, error)
	ClientIdentities(context.Context, time.Time) ([]querylog.ClientIdentity, error)
}

// replicaLookupReader is the cluster capability that hands the lead what each
// replica said about the addresses that asked it.
type replicaLookupReader interface {
	ReplicaLookups() ([]cluster.NodeLookups, bool)
}

// coverageSources feeds the coverage analyzer, and keeps what it loaded so
// the Devices tab lists the same silent devices the finding names.
type coverageSources struct {
	server *Server
	reader coverageInsightReader
	now    time.Time

	loaded bool
	input  devices.CoverageInput
	err    error
}

func (sources *coverageSources) Coverage(ctx context.Context) (devices.CoverageInput, error) {
	if !sources.loaded {
		sources.loaded = true
		sources.input, sources.err = sources.server.coverageInput(ctx, sources.reader, sources.now)
	}
	return sources.input, sources.err
}

// silent lists the devices UniFi shows online and busy that sent no node a
// lookup, for the Devices tab.
func (sources *coverageSources) silent(ctx context.Context) devices.Coverage {
	input, err := sources.Coverage(ctx)
	if err != nil {
		return devices.Coverage{}
	}
	input.Limits = insightDeviceLimits(sources.server.config.Current().Config.Insights.Findings)
	coverage := devices.FindSilent(input)
	if !coverage.Ready {
		return devices.Coverage{}
	}
	return coverage
}

// coverageInput gathers what the coverage analyzer reads. Only the node that
// runs the UniFi sync has a current reading, which is the cluster's lead, so
// any other node finds nothing rather than judging from a reading it kept
// from when it led.
func (server *Server) coverageInput(ctx context.Context, reader coverageInsightReader, now time.Time) (devices.CoverageInput, error) {
	configuration := server.config.Current().Config
	input := devices.CoverageInput{Now: now, Interval: configuration.UniFi.Interval.Duration}
	if !configuration.UniFi.Runnable() {
		return input, nil
	}
	nodes, replicas, leads := []string{"this server"}, []cluster.NodeLookups(nil), true
	if server.cluster != nil {
		state := server.cluster.Snapshot()
		if state.Initialized {
			lookups, ok := server.cluster.(replicaLookupReader)
			if !ok {
				return input, nil
			}
			replicas, leads = lookups.ReplicaLookups()
			for _, node := range state.Nodes {
				if node.ID == state.NodeID {
					nodes[0] = node.Name
				}
			}
		}
	}
	if !leads {
		return input, nil
	}
	window := time.Duration(max(configuration.Insights.Findings.NotUsingSable.Hours, 1)) * time.Hour
	reading, err := reader.UniFiReading(ctx, now.Add(-window-2*time.Hour))
	if err != nil {
		return input, err
	}
	local, err := reader.ClientLastLookups(ctx, now.Add(-window))
	if err != nil {
		return input, err
	}
	identities, err := reader.ClientIdentities(ctx, now.Add(-devices.Lookback))
	if err != nil {
		return input, err
	}
	input.Reading, input.Lookups, input.Identities = reading, local, identities
	input.Clients, input.Servers, input.Nodes = configuration.Clients, server.sableServers(), nodes
	for _, replica := range replicas {
		input.Nodes = append(input.Nodes, replica.Name)
		if replica.Reported.IsZero() {
			input.Unheard = append(input.Unheard, replica.Name)
			continue
		}
		for address, last := range replica.Last {
			if last.After(input.Lookups[address]) {
				input.Lookups[address] = last
			}
		}
	}
	input.Expected = server.expectedSilentDevices(ctx, now)
	return input, nil
}

// expectedSilentDevices lists the devices an operator said are expected not
// to use Sable, by device key.
func (server *Server) expectedSilentDevices(ctx context.Context, now time.Time) map[string]bool {
	store, ok := server.queries.(insightFeedbackStore)
	if !ok {
		return nil
	}
	feedback, err := store.InsightFeedback(ctx, now)
	if err != nil {
		server.logger.Warn("read insight feedback for silent devices", "error", err)
		return nil
	}
	expected := make(map[string]bool)
	for _, entry := range feedback {
		if key, found := devices.NotUsingSableDevice(entry.FindingID); found && entry.Active(now) {
			expected[key] = true
		}
	}
	return expected
}

// isRollupMember reports whether a finding ID names one device within the
// rolled-up finding about devices that don't use Sable.
func isRollupMember(id string) bool {
	_, found := devices.NotUsingSableDevice(id)
	return found
}

// withSilentDevices marks the listed devices that don't use Sable and adds
// the ones the list leaves out, which sent nothing in the period, after the
// rest.
func withSilentDevices(views []pages.InsightDeviceView, coverage devices.Coverage, report deviceReport) []pages.InsightDeviceView {
	for _, silent := range silentDevices(coverage) {
		line := silentDeviceLine(coverage)
		if index := slices.IndexFunc(views, func(view pages.InsightDeviceView) bool { return view.Key == silent.Key }); index >= 0 {
			views[index].NotUsingSable = line
			continue
		}
		view := insightDeviceView(silent, report)
		view.NotUsingSable = line
		views = append(views, view)
	}
	return views
}

// silentDevices are the devices that don't use Sable, with the type each
// one's maker and UniFi suggest.
func silentDevices(coverage devices.Coverage) []devices.Device {
	found := make([]devices.Device, 0, len(coverage.Silent))
	for _, silent := range coverage.Silent {
		found = append(found, silent.Device)
	}
	devices.Identify(found, nil)
	return found
}

// silentDeviceLine is what a silent device's drawer says about it.
func silentDeviceLine(coverage devices.Coverage) string {
	return "UniFi sees traffic, but no lookups reached Sable in " + devices.WindowText(coverage.Window) + "."
}

// expectedSilentViews lists the devices an operator said are expected not to
// use Sable, so each can be shown again.
func expectedSilentViews(coverage devices.Coverage) []pages.InsightHiddenFindingView {
	views := make([]pages.InsightHiddenFindingView, 0)
	for _, silent := range coverage.Silent {
		if silent.Expected {
			views = append(views, pages.InsightHiddenFindingView{
				FindingID: devices.NotUsingSableDeviceID(silent.Key), Label: "Doesn't use Sable: " + devices.Label(silent.Device), Status: "Marked normal",
			})
		}
	}
	return views
}
