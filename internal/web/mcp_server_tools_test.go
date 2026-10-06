package web

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/drudge/sable/internal/alerts"
	"github.com/drudge/sable/internal/cluster"
	"github.com/drudge/sable/internal/config"
	"github.com/drudge/sable/internal/dnsprovider"
	"github.com/drudge/sable/internal/dnsserver"
	"github.com/drudge/sable/internal/dynamicdns"
	"github.com/drudge/sable/internal/procstats"
	"github.com/drudge/sable/internal/update"
	"github.com/drudge/sable/internal/version"
)

// testCachedUpdateController remembers how fresh a check had to be.
type testCachedUpdateController struct {
	testUpdateController
	fresh []time.Duration
}

func (controller *testCachedUpdateController) CheckIfStale(_ context.Context, preRelease bool, fresh time.Duration) (update.Status, error) {
	controller.mutex.Lock()
	defer controller.mutex.Unlock()
	controller.fresh = append(controller.fresh, fresh)
	controller.preRelease = preRelease
	return controller.status, nil
}

type testMCPClusterController struct {
	clusterController
	state cluster.State
}

func (controller testMCPClusterController) Snapshot() cluster.State { return controller.state }

func setMCPTestRelease(t *testing.T, release string) {
	t.Helper()
	previous := version.Release
	version.Release = release
	t.Cleanup(func() { version.Release = previous })
}

// get_version reads the version from the build, so it cannot run in parallel
// with other tests that change it.
func TestMCPGetVersion(t *testing.T) {
	server, configuration := newMCPTestServer(t)

	setMCPTestRelease(t, "dev")
	development, failure := callMCPToolForTest(t, server, "sable_pat_updates", "get_version", map[string]any{"check": true})
	if failure != "" || development["development"] != true || development["latest"] != nil {
		t.Fatalf("development build = %v %q", development, failure)
	}
	if _, failure := callMCPToolForTest(t, server, "sable_pat_metrics", "get_version", map[string]any{}); !strings.Contains(failure, "updates.read") {
		t.Fatalf("without updates.read = %q", failure)
	}

	setMCPTestRelease(t, "1.5.1-beta.3")
	controller := &testCachedUpdateController{testUpdateController: testUpdateController{status: update.Status{
		CurrentVersion: "1.5.1-beta.3", LatestVersion: "1.5.1", ReleaseURL: "https://github.com/drudge/sable/releases/tag/v1.5.1",
		ReleaseNotes: "## Fixed\n- Referral loops.", Available: true, CheckedAt: time.Now().Add(-time.Hour),
		Releases: []update.ReleaseNote{
			{Version: "1.5.1", Notes: "## Fixed\n- Referral loops."},
			{Version: "1.5.1-rc.1", Notes: "## Added\n- A minimization switch.", PreRelease: true},
		},
	}}}
	server.SetUpdateController(controller)
	server.SetClusterController(testMCPClusterController{state: cluster.State{Initialized: true, Nodes: []cluster.Node{
		{Name: "ns1", Role: cluster.RolePrimary, Version: "1.5.1-beta.3"},
		{Name: "ns2", Role: cluster.RoleReplica, Version: "1.5.1-beta.2"},
	}}})

	result, failure := callMCPToolForTest(t, server, "sable_pat_admin", "get_version", map[string]any{})
	latest, _ := result["latest"].(map[string]any)
	notes, _ := latest["notes"].(string)
	if failure != "" || result["update_available"] != true || latest["release"] != "1.5.1" || result["channel"] != "stable" {
		t.Fatalf("get_version = %v %q", result, failure)
	}
	if !strings.Contains(notes, "# 1.5.1\n") || !strings.Contains(notes, "# 1.5.1-rc.1\n") || strings.Index(notes, "1.5.1-rc.1") < strings.Index(notes, "Referral") {
		t.Fatalf("rolled-up notes = %q", notes)
	}
	if nodes, _ := result["nodes"].([]any); len(nodes) != 2 || nodes[1].(map[string]any)["version"] != "1.5.1-beta.2" {
		t.Fatalf("nodes = %v", result["nodes"])
	}
	if len(controller.fresh) != 0 {
		t.Fatal("get_version asked GitHub without check")
	}

	// Nodes need cluster.read, and notes can be left out.
	quiet, _ := callMCPToolForTest(t, server, "sable_pat_updates", "get_version", map[string]any{"notes": false, "check": true})
	if quiet["nodes"] != nil || quiet["latest"].(map[string]any)["notes"] != nil {
		t.Fatalf("updates.read only, no notes = %v", quiet)
	}
	if len(controller.fresh) != 1 || controller.fresh[0] != mcpVersionCheckFloor || controller.preRelease {
		t.Fatalf("forced check freshness = %v, pre-release %t", controller.fresh, controller.preRelease)
	}

	// A check on the stable channel says nothing about pre-releases.
	configuration.snapshot.Config.Updates.PreRelease = true
	other, _ := callMCPToolForTest(t, server, "sable_pat_updates", "get_version", map[string]any{})
	if other["channel"] != "pre-release" || other["latest"] != nil || !strings.Contains(other["note"].(string), "check true") {
		t.Fatalf("other channel = %v", other)
	}
}

func TestMCPReleaseNotesStayUnderTheCap(t *testing.T) {
	t.Parallel()
	long := strings.Repeat("- A line about a fix that matters.\n", 400)
	status := update.Status{Releases: []update.ReleaseNote{{Version: "1.2.0", Notes: long}, {Version: "1.1.0", Notes: long}}}
	notes, truncated := mcpReleaseNotes(status)
	if !truncated || len(notes) > mcpMaximumNotesBytes || !strings.HasPrefix(notes, "# 1.2.0") || !strings.HasSuffix(notes, "matters.") {
		t.Fatalf("notes are %d bytes, truncated %t, ending %q", len(notes), truncated, notes[len(notes)-20:])
	}
	if notes, truncated := mcpReleaseNotes(update.Status{ReleaseNotes: "Short."}); notes != "Short." || truncated {
		t.Fatalf("latest-only notes = %q %t", notes, truncated)
	}
}

// get_stats counts from the dashboard's own buckets, so its numbers are the
// dashboard's for the same range.
func TestMCPGetStats(t *testing.T) {
	t.Parallel()
	server, _ := newMCPTestServer(t)
	now := time.Now()
	server.history.record(now, dnsserver.Stats{})
	server.history.record(now, dnsserver.Stats{Queries: 10, Blocked: 3, NoError: 7, NXDomain: 3, CacheHits: 4, CacheMisses: 2})

	stats, failure := callMCPToolForTest(t, server, "sable_pat_metrics", "get_stats", map[string]any{})
	if failure != "" || stats["range"].(map[string]any)["name"] != "day" {
		t.Fatalf("get_stats = %v %q", stats, failure)
	}
	cache := stats["cache"].(map[string]any)
	if stats["queries"] != float64(10) || stats["blocked"] != float64(3) || stats["blocked_percent"] != float64(30) ||
		cache["hits"] != float64(4) || cache["hit_ratio"] != 0.667 || stats["responses"].(map[string]any)["nxdomain"] != float64(3) {
		t.Fatalf("counts = %v", stats)
	}
	process := stats["process"].(map[string]any)
	memory := process["memory"].(map[string]any)
	if process["goroutines"].(float64) < 1 || memory["heap_inuse_bytes"].(float64) <= 0 || process["cpu"].(map[string]any)["cores"].(float64) < 1 {
		t.Fatalf("process = %v", process)
	}
	// Who asked and what was blocked come from the query log.
	if stats["top_blocked"] != nil || stats["clients"] != nil || !strings.Contains(stats["note"].(string), "logs.read") {
		t.Fatalf("metrics.read alone = %v", stats)
	}
	full, _ := callMCPToolForTest(t, server, "sable_pat_admin", "get_stats", map[string]any{"range": "hour", "top": 1})
	if blocked, _ := full["top_blocked"].([]any); full["clients"] == nil || len(blocked) > 1 {
		t.Fatalf("with logs.read = %v", full)
	}
	if _, failure := callMCPToolForTest(t, server, "sable_pat_metrics", "get_stats", map[string]any{"range": "fortnight"}); !strings.Contains(failure, "range must be") {
		t.Fatalf("unknown range = %q", failure)
	}
	if _, failure := callMCPToolForTest(t, server, "sable_pat_blocking", "get_stats", map[string]any{}); !strings.Contains(failure, "metrics.read") {
		t.Fatalf("without metrics.read = %q", failure)
	}
}

func TestMCPProcess(t *testing.T) {
	t.Parallel()
	started := time.Date(2026, 10, 6, 12, 0, 0, 0, time.UTC)
	lastGC := started.Add(90 * time.Second)
	process := mcpProcess(procstats.Stats{
		StartTime: started, CPUSeconds: 30, HasCPU: true, ResidentBytes: 64 << 20, HasMemory: true, NumCPU: 4,
		OpenFDs: 40, HasOpenFDs: true, MaxFDs: 1024, HasMaxFDs: true, MemoryLimitBytes: 256 << 20,
		GCCycles: 3, GCPauseSeconds: 0.0012345, LastGC: lastGC,
	}, started.Add(10*time.Minute))
	if *process.CPU.Seconds != 30 || *process.CPU.AveragePercent != 5 || *process.Memory.ResidentBytes != 64<<20 ||
		*process.Memory.LimitBytes != 256<<20 || *process.OpenFDs != 40 || *process.MaxFDs != 1024 ||
		process.GC.PauseTotalMS != 1.235 || !process.GC.LastAt.Equal(lastGC) || !process.StartedAt.Equal(started) {
		t.Fatalf("process = %+v", process)
	}
	// What the platform cannot report is left out, not zero.
	unknown := mcpProcess(procstats.Stats{}, started)
	if unknown.CPU.Seconds != nil || unknown.CPU.AveragePercent != nil || unknown.Memory.ResidentBytes != nil ||
		unknown.Memory.LimitBytes != nil || unknown.OpenFDs != nil || unknown.MaxFDs != nil || unknown.GC.LastAt != nil {
		t.Fatalf("unknown = %+v", unknown)
	}
}

func TestMCPLatencyPercentiles(t *testing.T) {
	t.Parallel()
	bucket := func(bound time.Duration, count uint64) dnsserver.DNSLatencyBucket {
		return dnsserver.DNSLatencyBucket{UpperBoundNanoseconds: uint64(bound), Count: count}
	}
	// 100 answers: 60 within 1 ms, 35 more within 10 ms, and 5 slower than
	// the largest bound, split across two histograms.
	histograms := []dnsserver.DNSLatencyHistogram{
		{Count: 60, Buckets: []dnsserver.DNSLatencyBucket{bucket(time.Millisecond, 60), bucket(10*time.Millisecond, 60), bucket(2*time.Second, 60)}},
		{Count: 40, Buckets: []dnsserver.DNSLatencyBucket{bucket(time.Millisecond, 0), bucket(10*time.Millisecond, 35), bucket(2*time.Second, 35)}},
	}
	got := mcpLatencyPercentiles(histograms)
	if got["p50"] != 0.8 || got["p95"] != 10 || got["p99"] != 2000 {
		t.Fatalf("percentiles = %v", got)
	}
	if mcpLatencyPercentiles(nil) != nil {
		t.Fatal("no answers should give no percentiles")
	}
}

func TestMCPGetDynamicDNS(t *testing.T) {
	t.Parallel()
	server, configuration := newMCPTestServer(t)
	server.SetDynamicDNSController(&testDynamicDNSController{})

	off, failure := callMCPToolForTest(t, server, "sable_pat_settings", "get_dynamic_dns", map[string]any{})
	if failure != "" || off["configured"] != false || !strings.Contains(off["note"].(string), "not set up") {
		t.Fatalf("not set up = %v %q", off, failure)
	}
	if _, failure := callMCPToolForTest(t, server, "sable_pat_metrics", "get_dynamic_dns", map[string]any{}); !strings.Contains(failure, "settings.read") {
		t.Fatalf("without settings.read = %q", failure)
	}

	const token = "cf-token-8f3kq92LmZ"
	changed := time.Date(2026, 9, 27, 14, 2, 10, 0, time.UTC)
	configuration.snapshot.Config.DynamicDNS = config.DynamicDNS{Enabled: true, Publishers: []config.DynamicDNSPublisher{{
		Provider: "cloudflare", Records: []config.DynamicDNSRecord{{Zone: "example.com", Name: "home", IPv4: true, IPv6: true, TTL: 300}},
	}}}
	server.SetDynamicDNSController(&testDynamicDNSController{
		configured: true, credentials: dnsprovider.Credentials{APIToken: token},
		status: dynamicdns.Status{
			CredentialsConfigured: true, IPv4: "203.0.113.44", PreviousIPv4: "198.51.100.7", IPv4ChangedAt: changed,
			LastAttempt: changed.Add(time.Hour), ConsecutiveFailures: 6,
			// A provider that echoes the credential back, both in a field
			// that looks like one and in plain text.
			LastError: "authentication error: token=" + token + " rejected; " + token + " lacks Zone.DNS edit",
		},
	})
	status, failure := callMCPToolForTest(t, server, "sable_pat_settings", "get_dynamic_dns", map[string]any{})
	ipv4, _ := status["ipv4"].(map[string]any)
	records, _ := status["records"].([]any)
	if failure != "" || status["provider"] != "cloudflare" || ipv4["current"] != "203.0.113.44" || ipv4["previous"] != "198.51.100.7" ||
		len(records) != 1 || status["consecutive_failures"] != float64(6) || status["ipv6"] != nil {
		t.Fatalf("get_dynamic_dns = %v %q", status, failure)
	}
	if lastError, _ := status["last_error"].(string); strings.Contains(lastError, token) || !strings.Contains(lastError, "Zone.DNS edit") {
		t.Fatalf("last_error = %q", lastError)
	}

	server.SetClusterController(testReplicaClusterController{})
	replica, _ := callMCPToolForTest(t, server, "sable_pat_settings", "get_dynamic_dns", map[string]any{})
	if replica["running"] != false || replica["ipv4"] != nil || !strings.Contains(replica["note"].(string), "primary") {
		t.Fatalf("replica = %v", replica)
	}
}

func TestMCPSyncDynamicDNS(t *testing.T) {
	t.Parallel()
	server, configuration := newMCPTestServer(t)
	controller := &testDynamicDNSController{configured: true}
	server.SetDynamicDNSController(controller)
	addMCPTools(configuration, "sync_dynamic_dns")

	if _, failure := callMCPToolForTest(t, server, "sable_pat_operator", "sync_dynamic_dns", map[string]any{}); !strings.Contains(failure, "not set up") {
		t.Fatalf("not set up = %q", failure)
	}
	configuration.snapshot.Config.DynamicDNS = config.DynamicDNS{Publishers: []config.DynamicDNSPublisher{{
		Provider: "cloudflare", Records: []config.DynamicDNSRecord{{Zone: "example.com", Name: "home", IPv4: true}},
	}}}
	if _, failure := callMCPToolForTest(t, server, "sable_pat_operator", "sync_dynamic_dns", map[string]any{}); !strings.Contains(failure, "paused") {
		t.Fatalf("paused = %q", failure)
	}
	configuration.snapshot.Config.DynamicDNS.Enabled = true
	if _, failure := callMCPToolForTest(t, server, "sable_pat_settings", "sync_dynamic_dns", map[string]any{}); !strings.Contains(failure, "settings.write") {
		t.Fatalf("without settings.write = %q", failure)
	}
	started, failure := callMCPToolForTest(t, server, "sable_pat_operator", "sync_dynamic_dns", map[string]any{})
	if failure != "" || started["started"] != true || controller.syncs != 1 {
		t.Fatalf("sync_dynamic_dns = %v %q, %d syncs", started, failure, controller.syncs)
	}
	server.SetClusterController(testReplicaClusterController{})
	if _, failure := callMCPToolForTest(t, server, "sable_pat_operator", "sync_dynamic_dns", map[string]any{}); !strings.Contains(failure, "primary") || controller.syncs != 1 {
		t.Fatalf("replica = %q, %d syncs", failure, controller.syncs)
	}
}

// testMCPLeadClusterController is a lead with a rolling update and a
// replica that reported a problem.
type testMCPLeadClusterController struct {
	testMCPClusterController
	rollout  cluster.RolloutStatus
	reported map[string][]alerts.Alert
}

func (controller testMCPLeadClusterController) RollingUpdatesSupported() bool { return true }

func (controller testMCPLeadClusterController) RolloutStatus() cluster.RolloutStatus {
	return controller.rollout
}

func (testMCPLeadClusterController) StartRollout(context.Context, string) error { return nil }

func (testMCPLeadClusterController) StopRollout() error { return nil }

func (controller testMCPLeadClusterController) ReportedAlertsByNode(time.Time) map[string][]alerts.Alert {
	return controller.reported
}

func TestMCPGetClusterStatus(t *testing.T) {
	t.Parallel()
	server, _ := newMCPTestServer(t)

	alone, failure := callMCPToolForTest(t, server, "sable_pat_cluster", "get_cluster_status", map[string]any{})
	if failure != "" || alone["mode"] != "not-configured" || alone["summary"] != "This server is not in a cluster." {
		t.Fatalf("standalone = %v %q", alone, failure)
	}
	if _, failure := callMCPToolForTest(t, server, "sable_pat_metrics", "get_cluster_status", map[string]any{}); !strings.Contains(failure, "cluster.read") {
		t.Fatalf("without cluster.read = %q", failure)
	}

	now := time.Now()
	state := cluster.State{
		Initialized: true, Mode: "primary-replica", ClusterID: "cluster-1", ClusterDomain: "cluster.example.net",
		Generation: 1842, NodeID: "node-1", PrimaryID: "node-1", LocalRole: cluster.RolePrimary,
		Nodes: []cluster.Node{
			{ID: "node-1", Name: "ns1", Role: cluster.RolePrimary, State: cluster.StateOnline, Version: "1.5.1",
				Addresses: []string{"192.0.2.1"}, AppliedGeneration: 1842, SyncState: cluster.SyncCurrent, LastContact: now},
			{ID: "node-2", Name: "ns2", Role: cluster.RoleReplica, State: cluster.StateOnline, Version: "1.5.1",
				AppliedGeneration: 1839, Lag: 3, SyncState: "behind", LastContact: now},
		},
	}
	server.SetClusterController(testMCPLeadClusterController{
		testMCPClusterController: testMCPClusterController{state: state},
		rollout: cluster.RolloutStatus{
			ID: "rollout-1", ClusterID: "cluster-1", PrimaryID: "node-1", Version: "1.5.2", Phase: "updating",
			Nodes: []cluster.RolloutNode{{ID: "node-2", Name: "ns2", Phase: "restarting"}, {ID: "node-1", Name: "ns1", Phase: "pending"}},
		},
		reported: map[string][]alerts.Alert{"node-2": {
			{ID: "certificates.renewal", Problem: true, Headline: "Certificate renewal is failing on ns2."},
			{ID: "backups.done", Headline: "A backup finished."},
		}},
	})
	status, failure := callMCPToolForTest(t, server, "sable_pat_cluster", "get_cluster_status", map[string]any{})
	nodes, _ := status["nodes"].([]any)
	if failure != "" || status["primary"] != "ns1" || status["local_node"] != "ns1" || len(nodes) != 2 ||
		status["summary"] != "2 nodes, 2 online, 1 behind, 1 with problems" {
		t.Fatalf("get_cluster_status = %v %q", status, failure)
	}
	replica := nodes[1].(map[string]any)
	if problems, _ := replica["problems"].([]any); replica["lag"] != float64(3) || len(problems) != 1 || replica["addresses"] != nil {
		t.Fatalf("replica = %v", replica)
	}
	if rollout, _ := status["rollout"].(map[string]any); rollout["version"] != "1.5.2" || rollout["active"] != true {
		t.Fatalf("rollout = %v", status["rollout"])
	}

	one, failure := callMCPToolForTest(t, server, "sable_pat_cluster", "get_cluster_status", map[string]any{"node": "NS2"})
	if nodes, _ := one["nodes"].([]any); failure != "" || len(nodes) != 1 || nodes[0].(map[string]any)["name"] != "ns2" {
		t.Fatalf("one node = %v %q", one, failure)
	}
	if _, failure := callMCPToolForTest(t, server, "sable_pat_cluster", "get_cluster_status", map[string]any{"node": "ns9"}); !strings.Contains(failure, "ns1, ns2") {
		t.Fatalf("unknown node = %q", failure)
	}
	server.SetClusterController(testReplicaClusterController{})
	if replica, _ := callMCPToolForTest(t, server, "sable_pat_cluster", "get_cluster_status", map[string]any{}); !strings.Contains(replica["note"].(string), "primary") {
		t.Fatalf("replica = %v", replica)
	}
}
