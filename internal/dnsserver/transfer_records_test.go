package dnsserver

import (
	"context"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func TestTransferredPrivateRecordRetainsNumericType(t *testing.T) {
	record, err := dns.NewRR(`good.test. 600 IN TYPE65281 \# 15 000a3139322e302e322e353300000a`)
	if err != nil {
		t.Fatal(err)
	}
	records, err := zoneRecordsFromRR("good.test", []dns.RR{record})
	if err != nil || len(records) != 1 || records[0].Type != "TYPE65281" || records[0].Name != "@" || records[0].Value != `\# 15 000a3139322e302e322e353300000a` {
		t.Fatalf("private RR lost in transfer: %+v %v", records, err)
	}
}

func TestForwarderLocalOverridesAndThisServerFallback(t *testing.T) {
	for _, mode := range []string{"forward", "recursive", "secondary-forward", "secondary-recursive"} {
		t.Run(mode, func(t *testing.T) {
			configuration := testRuntimeConfig()
			configuration.Mode = strings.TrimPrefix(mode, "secondary-")
			if configuration.Mode == "recursive" {
				configuration.RootHints = []string{"192.0.2.1:53"}
			}
			configuration.Zones = []AuthoritativeZone{{Name: "example.test", Type: "forwarder", Records: []ZoneRecord{
				{Name: "@", Type: "SOA", Value: "ns.example.test. hostmaster.example.test. 1 60 10 600 300", TTL: 300},
				{Name: "@", Type: "FWD", Value: "udp 0 this-server", TTL: 300},
				{Name: "@", Type: "A", Value: "192.0.2.40", TTL: 300},
				{Name: "local", Type: "A", Value: "192.0.2.14", TTL: 300},
				{Name: "local", Type: "AAAA", Value: "2001:db8::14", TTL: 300},
				{Name: "local", Type: "TXT", Value: `"local verification"`, TTL: 300},
				{Name: "@", Type: "MX", Value: "10 mail.example.test.", TTL: 300},
				{Name: "alias", Type: "CNAME", Value: "local.example.test.", TTL: 300},
			}}}
			if strings.HasPrefix(mode, "secondary-") {
				configuration.Zones[0].Type = "secondary_forwarder"
				configuration.Zones[0].PrimaryServers = []string{"192.0.2.53:53"}
				configuration.Zones[0].PrimaryProtocol = "tcp"
			}
			runtime, err := Compile(configuration)
			if err != nil {
				t.Fatal(err)
			}
			handler := NewHandler(runtime)
			calls := 0
			handler.upstreamExchange = func(_ context.Context, query *dns.Msg, endpoint string, _ time.Duration) (*dns.Msg, error) {
				calls++
				if strings.Contains(endpoint, "this-server") {
					t.Fatal("this-server was sent to the network")
				}
				response := addressResponse(query, "192.0.2.90")
				response.Authoritative = true
				return response, nil
			}
			for _, query := range []struct {
				name       string
				recordType uint16
				want       string
			}{
				{"example.test.", dns.TypeA, "example.test.\t300\tIN\tA\t192.0.2.40"},
				{"local.example.test.", dns.TypeA, "local.example.test.\t300\tIN\tA\t192.0.2.14"},
				{"local.example.test.", dns.TypeAAAA, "local.example.test.\t300\tIN\tAAAA\t2001:db8::14"},
				{"local.example.test.", dns.TypeTXT, "local.example.test.\t300\tIN\tTXT\t\"local verification\""},
				{"example.test.", dns.TypeMX, "example.test.\t300\tIN\tMX\t10 mail.example.test."},
				{"alias.example.test.", dns.TypeA, "local.example.test.\t300\tIN\tA\t192.0.2.14"},
				{"alias.example.test.", dns.TypeTXT, "local.example.test.\t300\tIN\tTXT\t\"local verification\""},
			} {
				request := new(dns.Msg)
				request.SetQuestion(query.name, query.recordType)
				result := handler.resolve(request, runtime)
				if !result.response.Authoritative || calls != 0 {
					t.Fatalf("override lost: %+v calls=%d", result.response, calls)
				}
				matched := false
				for _, answer := range result.response.Answer {
					matched = matched || answer.String() == query.want
				}
				if !matched {
					t.Fatalf("missing local answer %q: %+v", query.want, result.response)
				}
			}
			request := new(dns.Msg)
			request.SetQuestion("missing.example.test.", dns.TypeA)
			request.RecursionDesired = true
			result := handler.resolve(request, runtime)
			if calls == 0 || result.response.Rcode != dns.RcodeSuccess || len(result.response.Answer) == 0 {
				t.Fatalf("fallback failed: %+v calls=%d", result.response, calls)
			}
		})
	}
}

func TestSecondaryForwarderRefreshUsesAXFRAndRejectsRollback(t *testing.T) {
	runtime, err := Compile(testRuntimeConfig())
	if err != nil {
		t.Fatal(err)
	}
	handler := NewHandler(runtime)
	serial := uint32(2)
	calls := 0
	handler.zoneTransfer = func(_ context.Context, name, primary, protocol string, _ transferAuth, _ time.Duration) ([]dns.RR, error) {
		calls++
		if name != "example.test" || primary != "192.0.2.53:53" || protocol != "tcp" {
			t.Fatal("transfer settings changed")
		}
		soa, err := dns.NewRR(fmt.Sprintf("example.test. 300 IN SOA ns.example.test. hostmaster.example.test. %d 60 10 600 300", serial))
		if err != nil {
			t.Fatal(err)
		}
		fwd, err := dns.NewRR(`example.test. 300 IN TYPE65281 \# 16 000b746869732d736572766572010000`)
		if err != nil {
			t.Fatal(err)
		}
		return []dns.RR{soa, fwd, soa}, nil
	}
	current := []ZoneRecord{{Name: "@", Type: "SOA", TTL: 300, Value: "ns.example.test. hostmaster.example.test. 1 60 10 600 300"}, {Name: "@", Type: "FWD", TTL: 300, Value: "udp 0 this-server"}}
	records, changed, err := handler.RefreshZone(context.Background(), "example.test", "secondary_forwarder", []string{"192.0.2.53:53"}, "tcp", "", current)
	if err != nil || !changed || calls != 1 || len(records) != 2 || records[1].Type != "TYPE65281" {
		t.Fatalf("AXFR: %+v %v %v", records, changed, err)
	}
	serial = 0
	if _, _, err := handler.RefreshZone(context.Background(), "example.test", "secondary_forwarder", []string{"192.0.2.53:53"}, "tcp", "", current); err == nil {
		t.Fatal("older source snapshot accepted")
	}
}

func TestSecondaryForwarderNotifyAndExpiry(t *testing.T) {
	configuration := testRuntimeConfig()
	configuration.Zones = []AuthoritativeZone{{Name: "example.test", Type: "secondary_forwarder", PrimaryServers: []string{"192.0.2.53:53"}, PrimaryProtocol: "tcp", Records: []ZoneRecord{
		{Name: "@", Type: "SOA", TTL: 300, Value: "ns.example.test. hostmaster.example.test. 1 60 10 600 300"},
		{Name: "@", Type: "FWD", TTL: 300, Value: "udp 0 this-server"},
		{Name: "local", Type: "TXT", TTL: 300, Value: `"local answer"`},
	}}}
	runtime, err := Compile(configuration)
	if err != nil {
		t.Fatal(err)
	}
	handler := NewHandler(runtime)
	notify := new(dns.Msg)
	notify.SetNotify("example.test.")
	for _, test := range []struct {
		source string
		code   int
	}{{"192.0.2.53", dns.RcodeSuccess}, {"198.51.100.9", dns.RcodeRefused}} {
		response := &transferCapture{remote: &net.UDPAddr{IP: net.ParseIP(test.source), Port: 53000}}
		handler.ServeDNS(response, notify)
		if len(response.messages) != 1 || response.messages[0].Rcode != test.code {
			t.Fatalf("NOTIFY authorization: %+v", response.messages)
		}
	}
	handler.SetZoneExpired("example.test", true)
	for _, name := range []string{"local.example.test.", "missing.example.test."} {
		query := new(dns.Msg)
		query.SetQuestion(name, dns.TypeTXT)
		response := new(responseCapture)
		handler.ServeDNS(response, query)
		if response.message == nil || response.message.Rcode != dns.RcodeServerFailure {
			t.Fatalf("expired forwarder answered: %+v", response.message)
		}
	}
	handler.SetZoneExpired("example.test", false)
	query := new(dns.Msg)
	query.SetQuestion("local.example.test.", dns.TypeTXT)
	response := new(responseCapture)
	handler.ServeDNS(response, query)
	if response.message == nil || len(response.message.Answer) != 1 {
		t.Fatal("recovered override missing")
	}
}
