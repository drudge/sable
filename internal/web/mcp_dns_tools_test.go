package web

import (
	"net"
	"slices"
	"strings"
	"testing"

	"github.com/miekg/dns"

	"github.com/drudge/sable/internal/dnsserver"
	"github.com/drudge/sable/internal/querylog"
)

// mcpTestStats stands in for the DNS handler: tracker.example is blocked by a
// list, and every lookup answers 192.0.2.99 from upstream.
type mcpTestStats struct{ testStats }

func (mcpTestStats) Lookup(name string, recordType uint16) (dnsserver.LookupResult, error) {
	response := new(dns.Msg)
	response.SetQuestion(name, recordType)
	response.Response = true
	response.Answer = []dns.RR{&dns.A{
		Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 42}, A: net.ParseIP("192.0.2.99"),
	}}
	return dnsserver.LookupResult{Response: response, Source: querylog.SourceUpstream,
		Decision: querylog.Decision{Policy: querylog.PolicyNoMatch}}, nil
}

func (mcpTestStats) PurgeCacheName(string) int { return 2 }

func (mcpTestStats) DomainPolicy(name string) dnsserver.DomainPolicy {
	if name == "tracker.example" || strings.HasSuffix(name, ".tracker.example") {
		return dnsserver.DomainPolicy{Decision: querylog.PolicyBlocked, Rule: "tracker.example", Sources: []string{"Hagezi Pro"}}
	}
	return dnsserver.DomainPolicy{Decision: querylog.PolicyNoMatch}
}

func TestMCPLookupAndCache(t *testing.T) {
	t.Parallel()
	server, _ := newMCPTestServer(t)

	answer, failure := callMCPToolForTest(t, server, "sable_pat_reader", "lookup", map[string]any{"name": "App.Example.com"})
	answers, _ := answer["answers"].([]any)
	if failure != "" || answer["source"] != "upstream" || len(answers) != 1 {
		t.Fatalf("lookup = %v %q", answer, failure)
	}
	if first := answers[0].(map[string]any); first["value"] != "192.0.2.99" || first["name"] != "app.example.com" || first["ttl"] != float64(42) {
		t.Fatalf("answer = %v", first)
	}
	// A token that only reads metrics may not use Sable as a resolver.
	if _, failure := callMCPToolForTest(t, server, "sable_pat_metrics", "lookup", map[string]any{"name": "example.com"}); !strings.Contains(failure, "zones.read") {
		t.Fatalf("metrics token lookup = %q", failure)
	}
	if _, failure := callMCPToolForTest(t, server, "sable_pat_reader", "lookup", map[string]any{"name": "example.com", "type": "BOGUS"}); !strings.Contains(failure, "unsupported") {
		t.Fatalf("bad type failure = %q", failure)
	}

	purged, failure := callMCPToolForTest(t, server, "sable_pat_admin", "purge_cache", map[string]any{"name": "app.example.com"})
	if failure != "" || purged["removed"] != float64(2) {
		t.Fatalf("purge_cache = %v %q", purged, failure)
	}
	if _, failure := callMCPToolForTest(t, server, "sable_pat_scoped", "purge_cache", map[string]any{"name": "app.example.com"}); !strings.Contains(failure, "settings.write") {
		t.Fatalf("scoped purge = %q", failure)
	}
}

func TestMCPCheckDomain(t *testing.T) {
	t.Parallel()
	server, _ := newMCPTestServer(t)

	blocked, failure := callMCPToolForTest(t, server, "sable_pat_blocking", "check_domain", map[string]any{"domain": "cdn.tracker.example."})
	if failure != "" || blocked["blocked"] != true || blocked["rule"] != "tracker.example" || !strings.Contains(blocked["explanation"].(string), "Hagezi Pro") {
		t.Fatalf("blocked check = %v %q", blocked, failure)
	}
	open, failure := callMCPToolForTest(t, server, "sable_pat_blocking", "check_domain", map[string]any{"domain": "example.org"})
	if failure != "" || open["blocked"] != false || open["explanation"] != "Nothing blocks this domain." {
		t.Fatalf("open check = %v %q", open, failure)
	}
	zoned, failure := callMCPToolForTest(t, server, "sable_pat_admin", "check_domain", map[string]any{"domain": "www.example.test"})
	if failure != "" || zoned["answered_by_zone"] != "example.test" {
		t.Fatalf("zone check = %v %q", zoned, failure)
	}
	if _, failure := callMCPToolForTest(t, server, "sable_pat_scoped", "check_domain", map[string]any{"domain": "example.org"}); !strings.Contains(failure, "blocking.read") {
		t.Fatalf("scoped check = %q", failure)
	}
}

func TestMCPDomainRules(t *testing.T) {
	t.Parallel()
	server, configuration := newMCPTestServer(t)
	const token = "sable_pat_blocking"
	lists := func() (blocked, allowed []string) {
		policy := configuration.snapshot.Config.Blocking
		return policy.Domains, policy.AllowedDomains
	}
	change := func(tool, domain string) map[string]any {
		t.Helper()
		result, failure := callMCPToolForTest(t, server, token, tool, map[string]any{"domain": domain})
		if failure != "" {
			t.Fatalf("%s(%s) failed: %s", tool, domain, failure)
		}
		return result
	}

	if result := change("allow_domain", "Shop.Example."); result["changed"] != true || result["domain"] != "shop.example" {
		t.Fatalf("allow = %v", result)
	}
	revision := configuration.snapshot.Revision
	if result := change("allow_domain", "shop.example"); result["changed"] != false || configuration.snapshot.Revision != revision {
		t.Fatalf("repeated allow = %v, revision %d -> %d", result, revision, configuration.snapshot.Revision)
	}
	// Blocking an allowed domain must drop the allow entry, or the block would
	// do nothing.
	if result := change("block_domain", "shop.example"); result["changed"] != true || !strings.Contains(result["message"].(string), "allow list") {
		t.Fatalf("block = %v", result)
	}
	if blocked, allowed := lists(); !slices.Contains(blocked, "shop.example") || slices.Contains(allowed, "shop.example") {
		t.Fatalf("after block: blocked=%v allowed=%v", blocked, allowed)
	}
	if result := change("remove_domain_rule", "shop.example"); result["changed"] != true {
		t.Fatalf("remove = %v", result)
	}
	if blocked, allowed := lists(); slices.Contains(blocked, "shop.example") || slices.Contains(allowed, "shop.example") {
		t.Fatalf("after remove: blocked=%v allowed=%v", blocked, allowed)
	}
	if result := change("remove_domain_rule", "shop.example"); result["changed"] != false {
		t.Fatalf("second remove = %v", result)
	}

	if _, failure := callMCPToolForTest(t, server, "sable_pat_reader", "block_domain", map[string]any{"domain": "x.example"}); !strings.Contains(failure, "blocking.write") {
		t.Fatalf("reader block = %q", failure)
	}
	server.SetClusterController(testReplicaClusterController{})
	if _, failure := callMCPToolForTest(t, server, token, "block_domain", map[string]any{"domain": "x.example"}); failure != replicaWriteMessage {
		t.Fatalf("replica block = %q", failure)
	}
	if _, failure := callMCPToolForTest(t, server, token, "check_domain", map[string]any{"domain": "x.example"}); failure != "" {
		t.Fatalf("replica check failed: %s", failure)
	}
}
