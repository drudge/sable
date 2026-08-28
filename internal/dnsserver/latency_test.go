package dnsserver

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/drudge/sable/internal/querylog"
)

func TestDNSLatencyHistogramsAreCumulativeAndBounded(t *testing.T) {
	t.Parallel()
	var histograms dnsLatencyHistograms
	histograms.observe(querylog.SourceCache, "udp", querylog.CacheHit, dns.RcodeSuccess, 50*time.Microsecond)
	histograms.observe(querylog.SourceCache, "UDP", querylog.CacheHit, dns.RcodeSuccess, 2*time.Millisecond)
	histograms.observe(querylog.SourceCache, "udp", querylog.CacheHit, dns.RcodeSuccess, 3*time.Second)

	snapshot := histograms.snapshot()
	if len(snapshot) != 1 {
		t.Fatalf("snapshot groups = %d, want 1", len(snapshot))
	}
	histogram := snapshot[0]
	if histogram.Source != "cache" || histogram.Protocol != "udp" || histogram.Cache != "hit" || histogram.ResponseCode != "NOERROR" || histogram.Count != 3 {
		t.Fatalf("histogram identity = %+v", histogram)
	}
	if histogram.SumNanoseconds != uint64(3*time.Second+2050*time.Microsecond) {
		t.Fatalf("histogram sum = %d", histogram.SumNanoseconds)
	}
	if got := histogram.Buckets[0].Count; got != 1 {
		t.Fatalf("100us bucket = %d, want 1", got)
	}
	if got := histogram.Buckets[4].Count; got != 2 {
		t.Fatalf("2.5ms bucket = %d, want 2", got)
	}
	if got := histogram.Buckets[len(histogram.Buckets)-1].Count; got != 2 {
		t.Fatalf("last finite bucket = %d, want 2", got)
	}
}

func TestDNSLatencySnapshotMarshalsAsJSON(t *testing.T) {
	t.Parallel()
	stats := Stats{Latency: []DNSLatencyHistogram{{
		Source: "cache", Protocol: "udp", Cache: "hit", ResponseCode: "NOERROR",
		Count: 2, SumNanoseconds: uint64(1500 * time.Microsecond),
		Buckets: []DNSLatencyBucket{{UpperBoundNanoseconds: uint64(time.Millisecond), Count: 1}},
	}}}
	if _, err := json.Marshal(stats); err != nil {
		t.Fatal(err)
	}
}

func TestDNSLatencyHistogramsNormalizeUnknownLabels(t *testing.T) {
	t.Parallel()
	var histograms dnsLatencyHistograms
	histograms.observe(querylog.Source("unexpected"), "unexpected", querylog.CacheDecision("unexpected"), 99, time.Millisecond)
	histograms.observe(querylog.SourceUpstream, "TLS", querylog.CacheMiss, dns.RcodeSuccess, time.Millisecond)

	snapshot := histograms.snapshot()
	if len(snapshot) != 2 {
		t.Fatalf("snapshot groups = %d, want 2", len(snapshot))
	}
	if snapshot[0].Source != "upstream" || snapshot[0].Protocol != "tcp" || snapshot[0].Cache != "miss" || snapshot[0].ResponseCode != "NOERROR" {
		t.Fatalf("known histogram = %+v", snapshot[0])
	}
	if snapshot[1].Source != "other" || snapshot[1].Protocol != "other" || snapshot[1].Cache != "other" || snapshot[1].ResponseCode != "OTHER" {
		t.Fatalf("fallback histogram = %+v", snapshot[1])
	}
}
