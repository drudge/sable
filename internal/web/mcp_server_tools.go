package web

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/http"
	"os"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/drudge/sable/internal/alerts"
	"github.com/drudge/sable/internal/auth"
	"github.com/drudge/sable/internal/cluster"
	"github.com/drudge/sable/internal/dnsprovider"
	"github.com/drudge/sable/internal/dnsserver"
	"github.com/drudge/sable/internal/update"
	"github.com/drudge/sable/internal/version"
)

const (
	// mcpVersionCheckFloor is how often get_version may ask GitHub, however
	// often an assistant passes check, so it cannot use up the
	// unauthenticated rate limit the console's own checks share.
	mcpVersionCheckFloor = 5 * time.Minute
	// mcpMaximumNotesBytes caps release notes rolled up across releases.
	mcpMaximumNotesBytes = 8 << 10
	mcpDefaultTopBlocked = 5
	mcpMaximumTopBlocked = 25
)

// mcpServerTools report on the server itself: its version, how DNS is doing,
// Dynamic DNS, and the cluster.
var mcpServerTools = []mcpTool{
	{
		Name:  "get_version",
		Title: "Get Sable's version",
		Description: "Say which Sable version is running, whether a newer release is out on the server's update " +
			"channel, and what changed in every release since the running one. Uses the last saved check unless " +
			"check is true; a fresh check asks GitHub at most once every 5 minutes.",
		InputSchema: mcpObjectSchema(map[string]any{
			"check": map[string]any{"type": "boolean", "description": "Ask GitHub now instead of using the last saved check. Defaults to false."},
			"notes": map[string]any{"type": "boolean", "description": "Include release notes. Defaults to true."},
		}, nil),
		Annotations: mcpToolAnnotations{Title: "Get Sable's version", ReadOnlyHint: true, IdempotentHint: true, OpenWorldHint: true},
		call:        (*Server).mcpGetVersion,
		section:     "server",
		grant:       "updates.read",
	},
	{
		Name:  "get_stats",
		Title: "Get DNS statistics",
		Description: "Give the dashboard's numbers for a period: queries, how many were blocked, cache hits, and " +
			"response codes. It also gives what this node counted since it started: where answers came from, " +
			"upstream errors, DNSSEC results, and response times. Counts only, never which device asked for what. " +
			"Numbers are for the node the assistant is connected to.",
		InputSchema: mcpObjectSchema(map[string]any{
			"range": map[string]any{
				"type": "string", "enum": []string{"hour", "day", "week", "month", "year"},
				"description": "How far back to count, as on the dashboard. Defaults to day.",
			},
			"top": map[string]any{
				"type": "integer", "minimum": 0, "maximum": mcpMaximumTopBlocked,
				"description": "How many of the most blocked domains to list, 0 to 25. Defaults to 5. Needs logs.read.",
			},
		}, nil),
		Annotations: mcpToolAnnotations{Title: "Get DNS statistics", ReadOnlyHint: true, IdempotentHint: true},
		call:        (*Server).mcpGetStats,
		section:     "server",
		grant:       "metrics.read",
	},
	{
		Name:  "get_dynamic_dns",
		Title: "Get Dynamic DNS status",
		Description: "Say whether Dynamic DNS is keeping public records pointed at this network: the current and " +
			"previous public addresses and when they changed, which records it keeps up to date, when it last " +
			"succeeded, and its last error. running is true while an update is under way. Check it first when " +
			"home cannot be reached from outside.",
		InputSchema: mcpObjectSchema(nil, nil),
		Annotations: mcpToolAnnotations{Title: "Get Dynamic DNS status", ReadOnlyHint: true, IdempotentHint: true},
		call:        (*Server).mcpGetDynamicDNS,
		section:     "server",
		grant:       "settings.read",
	},
	{
		Name:  "sync_dynamic_dns",
		Title: "Update Dynamic DNS now",
		Description: "Look up this network's public addresses and update the Dynamic DNS records now instead of " +
			"waiting for the next scheduled run. It returns at once; call get_dynamic_dns a few seconds later " +
			"to see how it went.",
		InputSchema: mcpObjectSchema(nil, nil),
		Annotations: mcpToolAnnotations{Title: "Update Dynamic DNS now", IdempotentHint: true, OpenWorldHint: true},
		call:        (*Server).mcpSyncDynamicDNS,
		section:     "server",
		grant:       "settings.write",
	},
	{
		Name:  "get_cluster_status",
		Title: "Get cluster status",
		Description: "Say how the cluster is doing: which node leads, which nodes are online, whether each has " +
			"caught up with the latest changes, what version each runs, each node's open problems, and any " +
			"rolling update under way. A node is online when its last heartbeat is under 5 seconds old; lag is " +
			"how many changes it has yet to apply.",
		InputSchema: mcpObjectSchema(map[string]any{
			"node": mcpString("Optional node name or ID, to report on that node alone."),
		}, nil),
		Annotations: mcpToolAnnotations{Title: "Get cluster status", ReadOnlyHint: true, IdempotentHint: true},
		call:        (*Server).mcpGetClusterStatus,
		section:     "server",
		grant:       "cluster.read",
	},
}

type mcpLatestRelease struct {
	Release        string `json:"release"`
	PreRelease     bool   `json:"pre_release"`
	URL            string `json:"url,omitempty"`
	Notes          string `json:"notes,omitempty"`
	NotesTruncated bool   `json:"notes_truncated,omitempty"`
}

type mcpNodeVersion struct {
	Name    string `json:"name"`
	Role    string `json:"role"`
	Version string `json:"version"`
}

func (server *Server) mcpGetVersion(request *http.Request, arguments json.RawMessage) (any, error) {
	input := struct {
		Check bool  `json:"check"`
		Notes *bool `json:"notes"`
	}{}
	if err := decodeMCPArguments(arguments, &input); err != nil {
		return nil, err
	}
	build := version.Current()
	preRelease := server.config.Current().Config.Updates.PreRelease
	channel := "stable"
	if preRelease {
		channel = "pre-release"
	}
	result := map[string]any{"current": build, "development": build.Development(), "channel": channel}
	if nodes := server.mcpNodeVersions(request); nodes != nil {
		result["nodes"] = nodes
	}
	switch {
	case build.Development():
		result["note"] = "This is a development build, so Sable does not check for releases."
		return result, nil
	case server.updates == nil:
		result["note"] = "This server cannot check for releases."
		return result, nil
	}
	status := server.updates.Status()
	if input.Check {
		status = server.mcpCheckForRelease(request, preRelease, status)
	}
	// A check made on the other channel says nothing about this one.
	if !status.Checked() || status.LatestVersion == "" || status.IncludePreRelease != preRelease {
		result["update_available"] = false
		result["note"] = "Sable has not checked for releases on this channel yet. Pass check true to ask GitHub now."
		if status.Error != "" {
			result["error"] = status.Error
		}
		return result, nil
	}
	latest := mcpLatestRelease{Release: status.LatestVersion, PreRelease: status.PreRelease, URL: status.ReleaseURL}
	if input.Notes == nil || *input.Notes {
		latest.Notes, latest.NotesTruncated = mcpReleaseNotes(status)
	}
	result["latest"] = latest
	result["update_available"] = status.NewerRelease()
	result["checked_at"] = status.CheckedAt
	if status.Error != "" {
		result["error"] = status.Error
	}
	if status.Installed {
		result["note"] = "The newer release is installed. Sable runs it after a restart."
	}
	return result, nil
}

// mcpCheckForRelease asks GitHub unless a check on this channel is newer
// than the floor, and keeps what was known when it cannot.
func (server *Server) mcpCheckForRelease(request *http.Request, preRelease bool, known update.Status) update.Status {
	checker, ok := server.updates.(interface {
		CheckIfStale(context.Context, bool, time.Duration) (update.Status, error)
	})
	if !ok {
		return known
	}
	status, err := checker.CheckIfStale(request.Context(), preRelease, mcpVersionCheckFloor)
	if err != nil && !errors.Is(err, update.ErrUpdateInProgress) {
		server.logger.Warn("check for Sable updates", "error", err, "via", "mcp")
	}
	if status.CheckedAt.After(known.CheckedAt) {
		server.recordControlPlaneAudit(request, "update.check", "checked for a newer Sable release via=mcp")
	}
	return status
}

// mcpReleaseNotes rolls up the notes of every release after the running one,
// newest first, or the latest release's notes when Sable runs it already.
func mcpReleaseNotes(status update.Status) (string, bool) {
	var sections []string
	for _, release := range status.Releases {
		if notes := strings.TrimSpace(release.Notes); notes != "" {
			sections = append(sections, "# "+release.Version+"\n\n"+notes)
		}
	}
	notes := strings.Join(sections, "\n\n")
	if len(sections) < 2 {
		notes = strings.TrimSpace(status.ReleaseNotes)
	}
	if len(notes) <= mcpMaximumNotesBytes {
		return notes, false
	}
	cut := mcpMaximumNotesBytes
	for cut > 0 && !utf8.RuneStart(notes[cut]) {
		cut--
	}
	if line := strings.LastIndexByte(notes[:cut], '\n'); line > 0 {
		cut = line
	}
	return strings.TrimSpace(notes[:cut]), true
}

// mcpNodeVersions lists what each cluster node runs, for a token that may
// read the cluster, or nothing when there is no cluster to list.
func (server *Server) mcpNodeVersions(request *http.Request) []mcpNodeVersion {
	if server.cluster == nil || !server.mcpHasPermission(request, auth.PermissionClusterRead) {
		return nil
	}
	state := server.cluster.Snapshot()
	if !state.Initialized {
		return nil
	}
	nodes := make([]mcpNodeVersion, 0, len(state.Nodes))
	for _, node := range state.Nodes {
		nodes = append(nodes, mcpNodeVersion{Name: node.Name, Role: node.Role, Version: node.Version})
	}
	return nodes
}

type mcpStatsRange struct {
	Name  string    `json:"name"`
	Start time.Time `json:"start"`
	End   time.Time `json:"end"`
}

type mcpCacheStats struct {
	Hits     uint64  `json:"hits"`
	Misses   uint64  `json:"misses"`
	HitRatio float64 `json:"hit_ratio"`
	Entries  int     `json:"entries"`
}

type mcpResponseStats struct {
	NoError  uint64 `json:"noerror"`
	NXDomain uint64 `json:"nxdomain"`
	ServFail uint64 `json:"servfail"`
	Refused  uint64 `json:"refused"`
}

// mcpSinceStartStats are counters this process keeps only since it started,
// which the dashboard's history does not break down by period.
type mcpSinceStartStats struct {
	StartedAt      time.Time          `json:"started_at"`
	UptimeSeconds  int64              `json:"uptime_seconds"`
	AnsweredBy     map[string]uint64  `json:"answered_by"`
	UpstreamErrors uint64             `json:"upstream_errors"`
	DNSSEC         map[string]uint64  `json:"dnssec"`
	LatencyMS      map[string]float64 `json:"latency_ms,omitempty"`
}

func (server *Server) mcpGetStats(request *http.Request, arguments json.RawMessage) (any, error) {
	input := struct {
		Range string `json:"range"`
		Top   *int   `json:"top"`
	}{}
	if err := decodeMCPArguments(arguments, &input); err != nil {
		return nil, err
	}
	rangeName := strings.ToLower(strings.TrimSpace(input.Range))
	if rangeName == "" {
		rangeName = "day"
	}
	duration, valid := chartDuration(rangeName)
	if !valid {
		return nil, fmt.Errorf("range must be hour, day, week, month, or year, not %q", input.Range)
	}
	top := mcpDefaultTopBlocked
	if input.Top != nil {
		top = min(max(*input.Top, 0), mcpMaximumTopBlocked)
	}
	now := time.Now()
	current := server.stats.Stats()
	server.history.record(now, current)
	start := now.Add(-duration)
	// The same buckets as the dashboard chart, so the numbers match it.
	counted := chartStats(server.history.points(request.Context(), start, now))
	result := map[string]any{
		"node":    server.mcpNodeName(),
		"range":   mcpStatsRange{Name: rangeName, Start: start.UTC(), End: now.UTC()},
		"queries": counted.Queries, "blocked": counted.Blocked, "blocked_percent": mcpPercent(counted.Blocked, counted.Queries),
		"cache": mcpCacheStats{
			Hits: counted.CacheHits, Misses: counted.CacheMisses, Entries: current.CacheEntries,
			HitRatio: mcpRatio(counted.CacheHits, counted.CacheHits+counted.CacheMisses),
		},
		"responses": mcpResponseStats{
			NoError: counted.NoError, NXDomain: counted.NXDomain, ServFail: counted.ServerFailures, Refused: counted.Refused,
		},
		"since_start": mcpSinceStart(current, now),
	}
	// Who asked and what was blocked come from the query log, which the
	// dashboard shows only to those who may read it.
	reader, readable := server.queries.(queryInsightReader)
	switch {
	case !readable:
	case !server.mcpHasPermission(request, auth.PermissionLogsRead):
		result["note"] = "clients and top_blocked come from the query log and need logs.read."
	default:
		insights, _, err := server.insightCache.load(request.Context(), insightWindow{Range: "custom", Start: start, End: now}, reader.QueryLogInsights)
		if err != nil {
			server.logger.Warn("read query log for MCP statistics", "error", err)
			break
		}
		result["clients"] = len(insights.Clients)
		blocked := make([]mcpDomainCount, 0, top)
		for _, domain := range rankedStats(insights.Blocked, nil, top) {
			blocked = append(blocked, mcpDomainCount{Domain: domain.Name, Count: domain.Value})
		}
		result["top_blocked"] = blocked
	}
	return result, nil
}

type mcpDomainCount struct {
	Domain string `json:"domain"`
	Count  uint64 `json:"count"`
}

func mcpSinceStart(current dnsserver.Stats, now time.Time) mcpSinceStartStats {
	stats := mcpSinceStartStats{
		StartedAt: current.StartedAt.UTC(), UpstreamErrors: current.UpstreamErrors, AnsweredBy: map[string]uint64{},
		DNSSEC: map[string]uint64{"secure": current.DNSSECSecure, "insecure": current.DNSSECInsecure, "bogus": current.DNSSECBogus},
	}
	if !current.StartedAt.IsZero() {
		stats.UptimeSeconds = int64(now.Sub(current.StartedAt).Seconds())
	}
	for _, histogram := range current.Latency {
		stats.AnsweredBy[histogram.Source] += histogram.Count
	}
	if latency := mcpLatencyPercentiles(current.Latency); latency != nil {
		stats.LatencyMS = latency
	}
	return stats
}

// mcpLatencyPercentiles merges every response-time histogram and estimates
// the median, 95th, and 99th percentiles the way Prometheus's
// histogram_quantile does: linearly within the bucket the rank falls in.
func mcpLatencyPercentiles(histograms []dnsserver.DNSLatencyHistogram) map[string]float64 {
	var total uint64
	var bounds []uint64
	var cumulative []uint64
	for _, histogram := range histograms {
		total += histogram.Count
		for index, bucket := range histogram.Buckets {
			if index >= len(bounds) {
				bounds = append(bounds, bucket.UpperBoundNanoseconds)
				cumulative = append(cumulative, 0)
			}
			cumulative[index] += bucket.Count
		}
	}
	if total == 0 || len(bounds) == 0 {
		return nil
	}
	quantile := func(q float64) float64 {
		rank := q * float64(total)
		lower, below := 0.0, 0.0
		for index, bound := range bounds {
			if float64(cumulative[index]) >= rank {
				inBucket := float64(cumulative[index]) - below
				value := float64(bound)
				if inBucket > 0 {
					value = lower + (float64(bound)-lower)*(rank-below)/inBucket
				}
				return math.Round(value/1e5) / 10
			}
			lower, below = float64(bound), float64(cumulative[index])
		}
		// Slower than the largest bound: all that can be said is "at least".
		return math.Round(float64(bounds[len(bounds)-1])/1e5) / 10
	}
	return map[string]float64{"p50": quantile(0.5), "p95": quantile(0.95), "p99": quantile(0.99)}
}

func mcpRatio(part, whole uint64) float64 {
	if whole == 0 {
		return 0
	}
	return math.Round(float64(part)/float64(whole)*1000) / 1000
}

func mcpPercent(part, whole uint64) float64 {
	return math.Round(mcpRatio(part, whole)*1000) / 10
}

// mcpNodeName names the node answering: its cluster name, or the host name
// of a server on its own.
func (server *Server) mcpNodeName() string {
	if server.cluster != nil {
		state := server.cluster.Snapshot()
		for _, node := range state.Nodes {
			if node.ID == state.NodeID && node.Name != "" {
				return node.Name
			}
		}
	}
	name, _ := os.Hostname()
	return name
}

type mcpPublicAddress struct {
	Current   string     `json:"current"`
	Previous  string     `json:"previous,omitempty"`
	ChangedAt *time.Time `json:"changed_at,omitempty"`
}

type mcpDynamicDNSRecord struct {
	Provider string `json:"provider"`
	Zone     string `json:"zone"`
	Name     string `json:"name"`
	IPv4     bool   `json:"ipv4"`
	IPv6     bool   `json:"ipv6"`
	TTL      uint32 `json:"ttl,omitempty"`
}

func (server *Server) mcpGetDynamicDNS(request *http.Request, arguments json.RawMessage) (any, error) {
	if err := decodeMCPArguments(arguments, &struct{}{}); err != nil {
		return nil, err
	}
	settings := server.config.Current().Config.DynamicDNS
	publishers := settings.ConfiguredPublishers()
	records := []mcpDynamicDNSRecord{}
	for _, publisher := range publishers {
		for _, record := range publisher.Records {
			records = append(records, mcpDynamicDNSRecord{
				Provider: publisher.Provider, Zone: record.Zone, Name: record.Name, IPv4: record.IPv4, IPv6: record.IPv6, TTL: record.TTL,
			})
		}
	}
	result := map[string]any{"configured": len(publishers) > 0, "enabled": settings.Runnable(), "records": records}
	providers := settings.ProviderNames()
	if len(providers) == 1 {
		result["provider"] = providers[0]
	} else if len(providers) > 1 {
		result["providers"] = providers
	}
	switch {
	case server.dynamicDNS == nil:
		result["running"] = false
		result["note"] = "Dynamic DNS is unavailable on this server."
		return result, nil
	case len(publishers) == 0:
		result["running"] = false
		result["note"] = "Dynamic DNS is not set up. Set it up in Sable under Integrations, Dynamic DNS."
		return result, nil
	case server.mcpReplica():
		// Only the primary publishes, so a replica's view is not the answer.
		result["running"] = false
		result["note"] = "Dynamic DNS runs only on the cluster primary. Connect to the primary to see its status."
		return result, nil
	}
	status := server.dynamicDNS.Status(request.Context())
	result["running"] = status.Running
	result["credentials_configured"] = status.CredentialsConfigured
	if address := mcpPublicAddressView(status.IPv4, status.PreviousIPv4, status.IPv4ChangedAt); address != nil {
		result["ipv4"] = address
	}
	if address := mcpPublicAddressView(status.IPv6, status.PreviousIPv6, status.IPv6ChangedAt); address != nil {
		result["ipv6"] = address
	}
	for key, at := range map[string]time.Time{
		"last_attempt": status.LastAttempt, "last_success": status.LastSuccess,
		"last_published": status.LastPublished, "next_attempt": status.NextAttempt,
	} {
		if !at.IsZero() {
			result[key] = at.UTC()
		}
	}
	result["consecutive_failures"] = status.ConsecutiveFailures
	if status.LastError != "" {
		result["last_error"] = server.mcpDynamicDNSError(request.Context(), providers, status.LastError)
	}
	if !settings.Enabled {
		result["note"] = "Dynamic DNS is paused, so public records are not being updated."
	}
	return result, nil
}

func (server *Server) mcpSyncDynamicDNS(request *http.Request, arguments json.RawMessage) (any, error) {
	if err := decodeMCPArguments(arguments, &struct{}{}); err != nil {
		return nil, err
	}
	if server.mcpReplica() {
		return nil, errors.New("Dynamic DNS runs only on the cluster primary; connect to the primary to update it")
	}
	settings := server.config.Current().Config.DynamicDNS
	switch {
	case server.dynamicDNS == nil:
		return nil, errors.New("Dynamic DNS is unavailable on this server")
	case len(settings.ConfiguredPublishers()) == 0:
		return nil, errors.New("Dynamic DNS is not set up; set it up in Sable under Integrations, Dynamic DNS")
	case !settings.Runnable():
		return nil, errors.New("Dynamic DNS is paused; resume it in Sable under Integrations, Dynamic DNS")
	}
	server.dynamicDNS.SyncNow()
	server.recordControlPlaneAudit(request, "integrations.dynamic_dns.sync", "requested an immediate dynamic DNS publication via=mcp")
	server.logger.Info("dynamic DNS publication requested", "client", requestClientIP(request), "via", "mcp")
	return map[string]any{
		"started": true, "message": "Dynamic DNS update started. Call get_dynamic_dns in a few seconds to see how it went.",
	}, nil
}

func mcpPublicAddressView(current, previous string, changedAt time.Time) *mcpPublicAddress {
	if current == "" && previous == "" {
		return nil
	}
	view := &mcpPublicAddress{Current: current, Previous: previous}
	if !changedAt.IsZero() {
		changed := changedAt.UTC()
		view.ChangedAt = &changed
	}
	return view
}

// mcpDynamicDNSError words a provider error the way the Integrations page
// does, which hides fields that look like credentials, then blanks every
// stored credential wherever it still appears, since a provider may echo one
// back in a message of its own.
func (server *Server) mcpDynamicDNSError(ctx context.Context, providers []string, raw string) string {
	provider := ""
	if len(providers) == 1 {
		provider = providers[0]
	}
	summary, _ := dynamicDNSErrorDisplay(provider, raw)
	for _, name := range providers {
		credentials, found := server.dynamicDNS.StoredCredentials(ctx, name)
		if !found {
			continue
		}
		summary = redactKnownSecrets(summary, dynamicDNSSecretValues(credentials)...)
	}
	return summary
}

// dynamicDNSSecretValues are the credentials that must never be shown. Names
// such as the TSIG key name, the zone ID, and the endpoint are not secret.
func dynamicDNSSecretValues(credentials dnsprovider.Credentials) []string {
	return []string{
		credentials.APIToken, credentials.APIKey, credentials.Secret, credentials.TSIGSecret,
		credentials.SecretAccessKey, credentials.SessionToken, credentials.ApplicationSecret,
		credentials.ConsumerKey, credentials.AccessKeyID, credentials.ApplicationKey,
	}
}

// redactKnownSecrets blanks each secret wherever it appears in text. Very
// short values are left alone, since blanking them would garble the text
// without hiding anything worth guessing.
func redactKnownSecrets(text string, secrets ...string) string {
	for _, secret := range secrets {
		if secret = strings.TrimSpace(secret); len(secret) >= 6 {
			text = strings.ReplaceAll(text, secret, "[redacted]")
		}
	}
	return text
}

type mcpClusterNode struct {
	Name              string     `json:"name"`
	Role              string     `json:"role"`
	State             string     `json:"state"`
	Version           string     `json:"version,omitempty"`
	UpSince           *time.Time `json:"up_since,omitempty"`
	LastContact       *time.Time `json:"last_contact,omitempty"`
	LastSync          *time.Time `json:"last_sync,omitempty"`
	AppliedGeneration uint64     `json:"applied_generation"`
	Lag               uint64     `json:"lag"`
	SyncState         string     `json:"sync_state"`
	Problems          []string   `json:"problems,omitempty"`
}

type mcpRollout struct {
	Version    string           `json:"version"`
	Phase      string           `json:"phase"`
	Active     bool             `json:"active"`
	Error      string           `json:"error,omitempty"`
	FailedNode string           `json:"failed_node,omitempty"`
	Nodes      []mcpRolloutNode `json:"nodes"`
	StartedAt  *time.Time       `json:"started_at,omitempty"`
	FinishedAt *time.Time       `json:"finished_at,omitempty"`
}

type mcpRolloutNode struct {
	Name  string `json:"name"`
	Phase string `json:"phase"`
}

// mcpRolloutNews is how long a finished rolling update is still reported.
const mcpRolloutNews = 24 * time.Hour

func (server *Server) mcpGetClusterStatus(request *http.Request, arguments json.RawMessage) (any, error) {
	var input struct {
		Node string `json:"node"`
	}
	if err := decodeMCPArguments(arguments, &input); err != nil {
		return nil, err
	}
	if server.cluster == nil {
		return map[string]any{"mode": "not-configured", "summary": "This server is not in a cluster."}, nil
	}
	state := server.cluster.Snapshot()
	if !state.Initialized {
		return map[string]any{"mode": state.Mode, "summary": "This server is not in a cluster."}, nil
	}
	now := time.Now()
	problems := server.mcpNodeProblems(request.Context(), state, now)
	names := make(map[string]string, len(state.Nodes))
	nodes := make([]mcpClusterNode, 0, len(state.Nodes))
	for _, node := range state.Nodes {
		names[node.ID] = node.Name
		nodes = append(nodes, mcpClusterNode{
			Name: node.Name, Role: node.Role, State: node.State, Version: node.Version,
			UpSince: mcpTime(node.UpSince), LastContact: mcpTime(node.LastContact), LastSync: mcpTime(node.LastSync),
			AppliedGeneration: node.AppliedGeneration, Lag: node.Lag, SyncState: node.SyncState, Problems: problems[node.ID],
		})
	}
	result := map[string]any{
		"mode": state.Mode, "cluster_domain": state.ClusterDomain, "generation": state.Generation,
		"local_node": names[state.NodeID], "primary": names[state.PrimaryID], "summary": mcpClusterSummary(nodes),
		"rollout": server.mcpRollout(state, names, now),
	}
	if target := strings.TrimSpace(input.Node); target != "" {
		index := slices.IndexFunc(state.Nodes, func(node cluster.Node) bool {
			return strings.EqualFold(node.Name, target) || node.ID == target
		})
		if index < 0 {
			known := make([]string, 0, len(nodes))
			for _, node := range nodes {
				known = append(known, node.Name)
			}
			return nil, fmt.Errorf("no node is named %s; the nodes are %s", target, strings.Join(known, ", "))
		}
		nodes = nodes[index : index+1]
	}
	result["nodes"] = nodes
	if state.LocalRole == cluster.RoleReplica {
		result["note"] = "This node is a replica, so it hears only from the primary. Connect to the primary " +
			"for every node's heartbeat, lag, and problems."
	}
	return result, nil
}

func mcpClusterSummary(nodes []mcpClusterNode) string {
	online, behind, troubled := 0, 0, 0
	for _, node := range nodes {
		if node.State == cluster.StateOnline {
			online++
		}
		if node.Lag > 0 {
			behind++
		}
		if len(node.Problems) > 0 {
			troubled++
		}
	}
	summary := fmt.Sprintf("%d nodes, %d online", len(nodes), online)
	if behind > 0 {
		summary += fmt.Sprintf(", %d behind", behind)
	}
	if troubled > 0 {
		summary += fmt.Sprintf(", %d with problems", troubled)
	}
	return summary
}

// mcpNodeProblems lists each node's own open problems, worded for people.
func (server *Server) mcpNodeProblems(ctx context.Context, state cluster.State, now time.Time) map[string][]string {
	found := make(map[string][]string)
	for nodeID, list := range server.clusterNodeProblems(ctx, state, now) {
		for _, alert := range list {
			found[nodeID] = append(found[nodeID], alertProblemText(alert))
		}
	}
	return found
}

// clusterNodeProblems gathers each node's own open problems: this node's from
// its alert sources, and, on the primary, what each replica last reported in
// its heartbeat. A problem worded the same way twice is listed once.
func (server *Server) clusterNodeProblems(ctx context.Context, state cluster.State, now time.Time) map[string][]alerts.Alert {
	found := make(map[string][]alerts.Alert)
	add := func(nodeID string, list []alerts.Alert) {
		for _, alert := range list {
			if !alert.Problem {
				continue
			}
			text := alertProblemText(alert)
			if slices.ContainsFunc(found[nodeID], func(known alerts.Alert) bool { return alertProblemText(known) == text }) {
				continue
			}
			found[nodeID] = append(found[nodeID], alert)
		}
	}
	if server.alerts != nil {
		local, err := server.alerts.Local(ctx, now)
		if err != nil {
			server.logger.Warn("gather this node's alerts", "error", err)
		}
		add(state.NodeID, local)
	}
	if reporter, ok := server.cluster.(interface {
		ReportedAlertsByNode(time.Time) map[string][]alerts.Alert
	}); ok {
		for nodeID, list := range reporter.ReportedAlertsByNode(now) {
			add(nodeID, list)
		}
	}
	return found
}

// alertProblemText is an alert in one sentence.
func alertProblemText(alert alerts.Alert) string {
	if alert.Headline != "" {
		return alert.Headline
	}
	return strings.TrimSpace(alert.Title + " " + alert.Subject)
}

// mcpRollout reports a rolling update that is under way or ended in the last
// day, or nothing.
func (server *Server) mcpRollout(state cluster.State, names map[string]string, now time.Time) *mcpRollout {
	controller, ok := server.cluster.(clusterUpdateController)
	if !ok {
		return nil
	}
	rollout := controller.RolloutStatus()
	if rollout.ID == "" || rollout.ClusterID != state.ClusterID || rollout.PrimaryID != state.PrimaryID {
		return nil
	}
	if !rollout.Active() && (rollout.FinishedAt.IsZero() || now.Sub(rollout.FinishedAt) > mcpRolloutNews) {
		return nil
	}
	view := &mcpRollout{
		Version: rollout.Version, Phase: rollout.Phase, Active: rollout.Active(), Error: rollout.Error,
		FailedNode: names[rollout.FailedNode], StartedAt: mcpTime(rollout.StartedAt), FinishedAt: mcpTime(rollout.FinishedAt),
		Nodes: make([]mcpRolloutNode, 0, len(rollout.Nodes)),
	}
	if view.FailedNode == "" {
		view.FailedNode = rollout.FailedNode
	}
	for _, node := range rollout.Nodes {
		view.Nodes = append(view.Nodes, mcpRolloutNode{Name: node.Name, Phase: node.Phase})
	}
	return view
}

func mcpTime(at time.Time) *time.Time {
	if at.IsZero() {
		return nil
	}
	at = at.UTC()
	return &at
}
