package web

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	blockcompiler "github.com/drudge/sable/internal/blocking"
	"github.com/drudge/sable/internal/version"
)

const prometheusContentType = "text/plain; version=0.0.4; charset=utf-8"

type prometheusMetric struct {
	name       string
	help       string
	metricType string
	value      uint64
}

type clusterPrometheusNode struct {
	id           string
	name         string
	role         string
	connected    uint64
	synchronized uint64
	lag          uint64
}

func (server *Server) metrics(writer http.ResponseWriter, _ *http.Request) {
	dnsStats := server.stats.Stats()
	queryLogStats := server.queryLog.Stats()
	blockListStatus := server.blockLists.Status()
	trustAnchorUpdates := uint64(0)
	if dnsStats.DNSSECTrustAnchorUpdates {
		trustAnchorUpdates = 1
	}
	clusterInitialized := uint64(0)
	clusterNodes := uint64(0)
	clusterConnected := uint64(0)
	clusterSynchronized := uint64(0)
	clusterGeneration := uint64(0)
	clusterPrimary := uint64(0)
	var clusterStateNodes []clusterPrometheusNode
	if server.cluster != nil {
		state := server.cluster.Snapshot()
		if state.Initialized {
			clusterInitialized = 1
		}
		clusterNodes = uint64(len(state.Nodes))
		clusterConnected = uint64(state.Connected)
		clusterSynchronized = uint64(state.Synchronized)
		clusterGeneration = state.Generation
		if state.PrimaryID == state.NodeID && state.PrimaryID != "" {
			clusterPrimary = 1
		}
		clusterStateNodes = make([]clusterPrometheusNode, 0, len(state.Nodes))
		for _, node := range state.Nodes {
			connected := uint64(0)
			if node.State == "online" {
				connected = 1
			}
			synchronized := uint64(0)
			if node.SyncState == "current" {
				synchronized = 1
			}
			clusterStateNodes = append(clusterStateNodes, clusterPrometheusNode{
				id: node.ID, name: node.Name, role: node.Role,
				connected: connected, synchronized: synchronized, lag: node.Lag,
			})
		}
	}
	metrics := []prometheusMetric{
		{name: "sable_dns_queries_total", help: "DNS queries received.", metricType: "counter", value: dnsStats.Queries},
		{name: "sable_dns_blocked_total", help: "DNS queries blocked by policy.", metricType: "counter", value: dnsStats.Blocked},
		{name: "sable_dns_local_answers_total", help: "DNS queries answered by local host overrides.", metricType: "counter", value: dnsStats.LocalAnswers},
		{name: "sable_dns_authoritative_answers_total", help: "DNS queries answered by authoritative zones.", metricType: "counter", value: dnsStats.AuthoritativeAnswers},
		{name: "sable_dns_response_write_failures_total", help: "DNS response write failures.", metricType: "counter", value: dnsStats.Failures},
		{name: "sable_dns_upstream_errors_total", help: "Queries for which every upstream attempt failed.", metricType: "counter", value: dnsStats.UpstreamErrors},
		{name: "sable_dns_routed_queries_total", help: "Queries using a conditional forwarding route.", metricType: "counter", value: dnsStats.RoutedQueries},
		{name: "sable_dnssec_secure_total", help: "Recursive responses authenticated as DNSSEC secure.", metricType: "counter", value: dnsStats.DNSSECSecure},
		{name: "sable_dnssec_insecure_total", help: "Recursive responses proven to be DNSSEC insecure.", metricType: "counter", value: dnsStats.DNSSECInsecure},
		{name: "sable_dnssec_bogus_total", help: "Recursive responses rejected as DNSSEC bogus.", metricType: "counter", value: dnsStats.DNSSECBogus},
		{name: "sable_dnssec_trust_anchor_updates_enabled", help: "Whether RFC 5011 trust-anchor updates are active.", metricType: "gauge", value: trustAnchorUpdates},
		{name: "sable_dnssec_trust_anchors", help: "Active RFC 5011 DNSSEC trust anchors.", metricType: "gauge", value: uint64(dnsStats.DNSSECTrustAnchors.Active)},
		{name: "sable_dnssec_trust_anchors_pending", help: "RFC 5011 trust anchors in add hold-down.", metricType: "gauge", value: uint64(dnsStats.DNSSECTrustAnchors.Pending)},
		{name: "sable_dnssec_trust_anchors_missing", help: "Active RFC 5011 trust anchors missing from the latest authenticated DNSKEY RRset.", metricType: "gauge", value: uint64(dnsStats.DNSSECTrustAnchors.Missing)},
		{name: "sable_dnssec_trust_anchors_revoked", help: "RFC 5011 trust anchors retained in revoked state.", metricType: "gauge", value: uint64(dnsStats.DNSSECTrustAnchors.Revoked)},
		{name: "sable_cache_hits_total", help: "DNS response cache hits.", metricType: "counter", value: dnsStats.CacheHits},
		{name: "sable_cache_misses_total", help: "DNS response cache misses.", metricType: "counter", value: dnsStats.CacheMisses},
		{name: "sable_cache_entries", help: "Current DNS response cache entries.", metricType: "gauge", value: uint64(dnsStats.CacheEntries)},
		{name: "sable_blocked_domains", help: "Compiled blocked domain count.", metricType: "gauge", value: uint64(dnsStats.BlockedDomains)},
		{name: "sable_block_lists", help: "Compiled managed block-list count.", metricType: "gauge", value: uint64(dnsStats.BlockLists)},
		{name: "sable_local_hosts", help: "Compiled local host override count.", metricType: "gauge", value: uint64(dnsStats.LocalHosts)},
		{name: "sable_authoritative_zones", help: "Compiled authoritative zone count.", metricType: "gauge", value: uint64(dnsStats.Zones)},
		{name: "sable_query_log_queued", help: "Query events waiting for persistence.", metricType: "gauge", value: uint64(queryLogStats.Queued)},
		{name: "sable_query_log_persisted_total", help: "Query events persisted.", metricType: "counter", value: queryLogStats.Persisted},
		{name: "sable_query_log_dropped_total", help: "Query events dropped.", metricType: "counter", value: queryLogStats.Dropped},
		{name: "sable_query_log_write_errors_total", help: "Query-log persistence errors.", metricType: "counter", value: queryLogStats.WriteErrors},
		{name: "sable_cluster_initialized", help: "Whether this node has initialized cluster state.", metricType: "gauge", value: clusterInitialized},
		{name: "sable_cluster_nodes", help: "Nodes in the current cluster membership view.", metricType: "gauge", value: clusterNodes},
		{name: "sable_cluster_nodes_connected", help: "Cluster nodes currently connected.", metricType: "gauge", value: clusterConnected},
		{name: "sable_cluster_nodes_synchronized", help: "Cluster nodes synchronized to the current generation.", metricType: "gauge", value: clusterSynchronized},
		{name: "sable_cluster_generation", help: "Current cluster configuration generation observed by this node.", metricType: "gauge", value: clusterGeneration},
		{name: "sable_cluster_is_primary", help: "Whether this node is the writable cluster primary.", metricType: "gauge", value: clusterPrimary},
		{name: "sable_block_list_sources_degraded", help: "Remote block lists whose most recent download attempt failed.", metricType: "gauge", value: uint64(blockListStatus.Degraded)},
	}

	var output strings.Builder
	release := version.Current()
	fmt.Fprintf(
		&output,
		"# HELP sable_build_info Sable build information.\n# TYPE sable_build_info gauge\nsable_build_info{version=\"%s\",commit=\"%s\",go_version=\"%s\"} 1\n",
		prometheusLabel(release.Release), prometheusLabel(release.Commit), prometheusLabel(release.Go),
	)
	fmt.Fprintln(&output, "# HELP sable_uptime_seconds Seconds since the DNS handler started.")
	fmt.Fprintln(&output, "# TYPE sable_uptime_seconds gauge")
	fmt.Fprintf(&output, "sable_uptime_seconds %.3f\n", time.Since(dnsStats.StartedAt).Seconds())
	for _, metric := range metrics {
		fmt.Fprintf(&output, "# HELP %s %s\n", metric.name, metric.help)
		fmt.Fprintf(&output, "# TYPE %s %s\n", metric.name, metric.metricType)
		fmt.Fprintf(&output, "%s %d\n", metric.name, metric.value)
	}
	for _, metric := range []struct{ name, help string }{
		{"sable_cluster_node_connected", "Whether the cluster node is currently connected."},
		{"sable_cluster_node_synchronized", "Whether the cluster node is synchronized to the current generation."},
		{"sable_cluster_node_replication_lag_generations", "Cluster generations not yet applied by the node."},
	} {
		fmt.Fprintf(&output, "# HELP %s %s\n# TYPE %s gauge\n", metric.name, metric.help, metric.name)
		for _, node := range clusterStateNodes {
			value := node.lag
			if metric.name == "sable_cluster_node_connected" {
				value = node.connected
			} else if metric.name == "sable_cluster_node_synchronized" {
				value = node.synchronized
			}
			fmt.Fprintf(&output, "%s{node_id=\"%s\",node=\"%s\",role=\"%s\"} %d\n", metric.name, prometheusLabel(node.id), prometheusLabel(node.name), prometheusLabel(node.role), value)
		}
	}

	for _, metric := range []struct{ name, help, metricType string }{
		{"sable_block_list_source_healthy", "Whether the most recent download attempt for the block list succeeded.", "gauge"},
		{"sable_block_list_source_consecutive_failures", "Consecutive failed download attempts for the block list.", "gauge"},
		{"sable_block_list_source_downloads_total", "Successful block-list downloads.", "counter"},
		{"sable_block_list_source_failures_total", "Failed block-list download attempts.", "counter"},
		{"sable_block_list_source_last_success_timestamp_seconds", "Unix time of the last successful download, or 0 if it has never succeeded.", "gauge"},
	} {
		fmt.Fprintf(&output, "# HELP %s %s\n# TYPE %s %s\n", metric.name, metric.help, metric.name, metric.metricType)
		for _, source := range blockListStatus.Sources {
			fmt.Fprintf(
				&output, "%s{list=\"%s\",url=\"%s\"} %d\n",
				metric.name, prometheusLabel(source.Name), prometheusLabel(source.URL),
				blockListSourceMetricValue(metric.name, source),
			)
		}
	}

	writer.Header().Set("Content-Type", prometheusContentType)
	writer.WriteHeader(http.StatusOK)
	_, _ = writer.Write([]byte(output.String()))
}

func blockListSourceMetricValue(name string, source blockcompiler.SourceHealth) uint64 {
	switch name {
	case "sable_block_list_source_healthy":
		if source.Healthy() {
			return 1
		}
		return 0
	case "sable_block_list_source_consecutive_failures":
		return uint64(source.ConsecutiveFailures)
	case "sable_block_list_source_downloads_total":
		return source.Downloads
	case "sable_block_list_source_failures_total":
		return source.Failures
	default:
		if source.LastSuccess.IsZero() {
			return 0
		}
		return uint64(source.LastSuccess.Unix())
	}
}

func prometheusLabel(value string) string {
	replacer := strings.NewReplacer("\\", "\\\\", "\n", "\\n", "\"", "\\\"")
	return replacer.Replace(value)
}
