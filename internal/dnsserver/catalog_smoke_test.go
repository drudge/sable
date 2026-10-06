//go:build catalog

package dnsserver_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/drudge/sable/internal/blocking"
	"github.com/drudge/sable/internal/dnsserver"
	"github.com/drudge/sable/internal/querylog"
)

// referenceResolver answers the same questions Sable does. When a list can't
// be fetched through it either, the list's own site is down, not Sable.
const referenceResolver = "1.1.1.1:53"

// catalogSentinels are names no catalog list may block. Blocking one means
// the parser misread a rule, as when ||google.com/adsense/... blocked all of
// google.com and ||pl.ua^$badfilter blocked a public suffix. Each catalog
// list's own host is added too, since blocking it stops the list updating.
var catalogSentinels = []string{
	"google.com", "www.google.com", "youtube.com", "github.com", "wikipedia.org",
	"en.wikipedia.org", "apple.com", "microsoft.com", "cloudflare.com", "amazon.com",
	"sable-sentinel.com", "sable-sentinel.net", "sable-sentinel.org",
	"sable-sentinel.co.uk", "sable-sentinel.pl.ua", "sable-sentinel.github.io",
}

// TestCatalogListsSurviveSable resolves, downloads, and compiles every
// catalog list through Sable, recursive and forwarding, with DNSSEC
// validation on: the setup where a validator bug turned the OISD downloads
// into SERVFAIL. Run it with go tool mage catalogSmoke.
func TestCatalogListsSurviveSable(t *testing.T) {
	checkClock(t)
	floors := catalogFloors(t)
	for _, entry := range blocking.Catalog {
		if _, found := floors[entry.Name]; !found {
			t.Errorf("catalog list %q has no floor in testdata/catalog_floors.json", entry.Name)
		}
	}
	modes := []struct {
		name      string
		configure func(*dnsserver.RuntimeConfig)
	}{
		{"recursive", func(configuration *dnsserver.RuntimeConfig) { configuration.Mode = "recursive" }},
		{"forward", func(configuration *dnsserver.RuntimeConfig) {
			configuration.Mode = "forward"
			configuration.Forwarders = []string{"1.1.1.1:53", "9.9.9.9:53"}
		}},
	}
	for _, mode := range modes {
		t.Run(mode.name, func(t *testing.T) {
			configuration := dnsserver.RuntimeConfig{
				Recursion: "allow", Timeout: 5 * time.Second, CacheSize: 10_000,
				DNSSECValidation: true,
			}
			mode.configure(&configuration)
			sable := serveSable(t, configuration)
			checkCatalog(t, sable, floors)
		})
	}
}

func checkCatalog(t *testing.T, sable string, floors map[string]int) {
	directory := t.TempDir()
	through, reference := clientVia(sable), clientVia(referenceResolver)
	var sources []blocking.Source
	for _, entry := range blocking.Catalog {
		host := hostOf(t, entry.URL)
		if problem := lookupProblem(sable, host); problem != "" {
			t.Errorf("%s: Sable can't resolve %s: %s", entry.Name, host, problem)
			continue
		}
		path := filepath.Join(directory, fmt.Sprintf("%x.txt", len(sources)))
		if err := download(through, entry.URL, path); err != nil {
			if referenceErr := download(reference, entry.URL, path+".reference"); referenceErr != nil {
				t.Logf("%s: skipped, the list's site is failing for everyone: %v", entry.Name, referenceErr)
				continue
			}
			t.Errorf("%s: downloads through %s but not through Sable: %v", entry.Name, referenceResolver, err)
			continue
		}
		source := blocking.Source{Name: entry.Name, Path: path, Format: blocking.FormatAuto}
		stats, err := blocking.ReadSource(directory, source, func(string) {})
		if err != nil {
			t.Errorf("%s: %v", entry.Name, err)
			continue
		}
		t.Logf("%s: %d lines, %d accepted, %d exceptions, %d unsupported, %d invalid", entry.Name, stats.Lines, stats.Accepted, stats.Exceptions, stats.Unsupported, stats.Invalid)
		if floor := floors[entry.Name]; stats.Accepted < floor {
			t.Errorf("%s: accepted %d domains, below its floor of %d", entry.Name, stats.Accepted, floor)
		}
		sources = append(sources, source)
	}
	compiled, err := blocking.Compile(directory, nil, sources)
	if err != nil {
		t.Fatal(err)
	}
	policy, err := dnsserver.Compile(dnsserver.RuntimeConfig{
		Recursion: "allow", Forwarders: []string{"127.0.0.1:1"}, Timeout: time.Second, CacheSize: 1, Blocking: true,
		BlockedDomains: compiled.Domains, BlockedDomainOwners: compiled.Owners, BlockedDomainOwnerSets: compiled.OwnerSets,
		ExceptionDomains: compiled.Exceptions, ExceptionDomainOwners: compiled.ExceptionOwners, ImportantBlockedDomains: compiled.Important,
	})
	if err != nil {
		t.Fatal(err)
	}
	handler := dnsserver.NewHandler(policy)
	sentinels := append([]string(nil), catalogSentinels...)
	for _, entry := range blocking.Catalog {
		sentinels = append(sentinels, hostOf(t, entry.URL))
	}
	for _, name := range sentinels {
		if decision := handler.DomainPolicy(name); decision.Decision == querylog.PolicyBlocked {
			t.Errorf("%s is blocked by rule %s on %s", name, decision.Rule, strings.Join(decision.Sources, ", "))
		}
	}
}

// checkClock stops early on a skewed clock, which fails DNSSEC validation for
// everything (RFC 4035 section 5.3.1) and would look like a Sable bug.
func checkClock(t *testing.T) {
	t.Helper()
	response, err := http.Head("https://www.cloudflare.com/")
	if err != nil {
		t.Logf("couldn't check the clock: %v", err)
		return
	}
	response.Body.Close()
	remote, err := http.ParseTime(response.Header.Get("Date"))
	if err != nil {
		return
	}
	if skew := time.Since(remote); skew > 5*time.Minute || skew < -5*time.Minute {
		t.Fatalf("this machine's clock is off by %s; DNSSEC validation needs the right time", skew.Round(time.Second))
	}
}

// serveSable runs a resolver on loopback, as when Sable is the host's own
// resolver, and returns its address.
func serveSable(t *testing.T, configuration dnsserver.RuntimeConfig) string {
	t.Helper()
	runtime, err := dnsserver.Compile(configuration)
	if err != nil {
		t.Fatal(err)
	}
	handler := dnsserver.NewHandler(runtime)
	packet, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp", packet.LocalAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	for _, server := range []*dns.Server{{PacketConn: packet, Handler: handler}, {Listener: listener, Handler: handler}} {
		go func() { _ = server.ActivateAndServe() }()
		t.Cleanup(func() { _ = server.Shutdown() })
	}
	return packet.LocalAddr().String()
}

// lookupProblem asks Sable for a host's addresses the way a validating stub
// would, and describes a failure: SERVFAIL with its EDE, or an answer the
// reference resolver validates but Sable doesn't.
func lookupProblem(sable, host string) string {
	ask := func(server string) (*dns.Msg, error) {
		request := new(dns.Msg)
		request.SetQuestion(dns.Fqdn(host), dns.TypeA)
		request.SetEdns0(1232, true)
		request.AuthenticatedData = true
		client := &dns.Client{Timeout: 10 * time.Second}
		var response *dns.Msg
		var err error
		for range 3 {
			if response, _, err = client.Exchange(request, server); err == nil {
				break
			}
		}
		return response, err
	}
	response, err := ask(sable)
	if err != nil {
		return err.Error()
	}
	reference, referenceErr := ask(referenceResolver)
	if response.Rcode != dns.RcodeSuccess {
		problem := dns.RcodeToString[response.Rcode]
		if option := response.IsEdns0(); option != nil {
			for _, extended := range option.Option {
				if ede, ok := extended.(*dns.EDNS0_EDE); ok {
					problem += fmt.Sprintf(" (EDE %d %s)", ede.InfoCode, ede.ExtraText)
				}
			}
		}
		if referenceErr == nil {
			problem += fmt.Sprintf("; %s answered %s", referenceResolver, dns.RcodeToString[reference.Rcode])
		}
		return problem
	}
	if referenceErr == nil && reference.AuthenticatedData && !response.AuthenticatedData {
		return fmt.Sprintf("%s validates it but Sable doesn't set AD", referenceResolver)
	}
	return ""
}

// clientVia downloads with every name resolved by the DNS server at address.
func clientVia(address string) *http.Client {
	resolver := &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
		var dialer net.Dialer
		return dialer.DialContext(ctx, network, address)
	}}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.DialContext = (&net.Dialer{Resolver: resolver, Timeout: 30 * time.Second}).DialContext
	return &http.Client{Transport: transport, Timeout: 2 * time.Minute}
}

func download(client *http.Client, address, path string) error {
	var lastErr error
	for attempt := range 3 {
		if attempt > 0 {
			time.Sleep(time.Duration(attempt) * 5 * time.Second)
		}
		if lastErr = downloadOnce(client, address, path); lastErr == nil {
			return nil
		}
	}
	return lastErr
}

func downloadOnce(client *http.Client, address, path string) error {
	request, err := http.NewRequest(http.MethodGet, address, nil)
	if err != nil {
		return err
	}
	request.Header.Set("User-Agent", "Sable DNS block-list updater")
	response, err := client.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return errors.New(response.Status)
	}
	file, err := os.Create(path)
	if err != nil {
		return err
	}
	defer file.Close()
	_, err = io.Copy(file, response.Body)
	return err
}

func hostOf(t *testing.T, address string) string {
	t.Helper()
	parsed, err := url.Parse(address)
	if err != nil {
		t.Fatal(err)
	}
	return parsed.Hostname()
}

// catalogFloors reads the fewest domains each list may yield: about half of
// what it gave when the floor was set, so a list's normal churn passes but a
// parser that drops most of a list fails.
func catalogFloors(t *testing.T) map[string]int {
	t.Helper()
	contents, err := os.ReadFile("testdata/catalog_floors.json")
	if err != nil {
		t.Fatal(err)
	}
	floors := map[string]int{}
	if err := json.Unmarshal(contents, &floors); err != nil {
		t.Fatal(err)
	}
	return floors
}
