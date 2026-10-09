package dnsserver

import (
	"slices"
	"testing"

	"github.com/miekg/dns"

	"github.com/drudge/sable/internal/querylog"
)

func TestResponseCacheRemoveNameDropsEveryType(t *testing.T) {
	t.Parallel()
	cache := NewResponseCache(4096)
	for _, name := range []string{"app.example.", "other.example."} {
		for _, recordType := range []uint16{dns.TypeA, dns.TypeAAAA} {
			request := cacheRequest(name, 1)
			request.Question[0].Qtype = recordType
			response := positiveResponse(cacheRequest(name, 1), 60)
			response.Question[0].Qtype = recordType
			if !cache.Set(request, response, true) {
				t.Fatalf("Set(%s, %d) = false", name, recordType)
			}
		}
	}
	if removed := cache.RemoveName("APP.example"); removed != 2 {
		t.Fatalf("RemoveName() = %d, want 2", removed)
	}
	if _, found := cache.Get(cacheRequest("app.example.", 2)); found {
		t.Fatal("removed name is still cached")
	}
	if _, found := cache.Get(cacheRequest("other.example.", 2)); !found {
		t.Fatal("another name was removed")
	}
	if cache.Len() != 2 {
		t.Fatalf("Len() = %d, want 2", cache.Len())
	}
	if removed := cache.RemoveName("app.example."); removed != 0 {
		t.Fatalf("second RemoveName() = %d, want 0", removed)
	}
}

func TestHandlerDomainPolicyExplainsDecision(t *testing.T) {
	t.Parallel()
	configuration := testRuntimeConfig()
	configuration.Blocking = true
	configuration.BlockedDomains = []string{"ads.example"}
	configuration.AllowedDomains = []string{"ok.ads.example"}
	runtime, err := Compile(configuration)
	if err != nil {
		t.Fatal(err)
	}
	handler := NewHandler(runtime)
	for name, want := range map[string]querylog.PolicyDecision{
		"pixel.ads.example": querylog.PolicyBlocked,
		"ok.ads.example":    querylog.PolicyAllowed,
		"example.org":       querylog.PolicyNoMatch,
	} {
		if got := handler.DomainPolicy(name, "", ""); got.Decision != want {
			t.Errorf("DomainPolicy(%s) = %+v, want %s", name, got, want)
		}
	}
	if got := handler.DomainPolicy("pixel.ads.example", "", ""); got.Rule != "ads.example" {
		t.Fatalf("blocked rule = %q", got.Rule)
	}
	handler.PauseBlocking(60_000_000_000)
	if got := handler.DomainPolicy("ads.example", "", ""); got.Decision != querylog.PolicyPaused {
		t.Fatalf("paused decision = %s", got.Decision)
	}
}

// An @@ exception on one block list lifts another list's block for the host
// and its subdomains, as in AdGuard Home and Technitium, and names the list
// that carries it. A $important block and the operator's own blocked domains
// stay blocked.
func TestBlockListExceptionOverridesAnotherListsBlock(t *testing.T) {
	t.Parallel()
	configuration := testRuntimeConfig()
	configuration.Blocking = true
	configuration.BlockedDomains = []string{"cdn.example", "mine.cdn.example", "tracker.example", "pixel.example"}
	configuration.BlockedDomainOwnerSets = [][]string{nil, {"EasyPrivacy"}, {"Custom blocked domains"}, {"EasyList"}, {"AdGuard DNS Filter"}}
	configuration.BlockedDomainOwners = []uint32{1, 2, 1, 3}
	configuration.ExceptionDomains = []string{"cdn.example", "pixel.example"}
	configuration.ExceptionDomainOwners = []uint32{4, 4}
	configuration.ImportantBlockedDomains = []string{"mine.cdn.example", "pixel.example"}
	runtime, err := Compile(configuration)
	if err != nil {
		t.Fatal(err)
	}
	handler := NewHandler(runtime)
	for _, test := range []struct {
		name     string
		decision querylog.PolicyDecision
		rule     string
		sources  []string
	}{
		{"cdn.example", querylog.PolicyAllowed, "cdn.example", []string{"AdGuard DNS Filter"}},
		{"img.cdn.example", querylog.PolicyAllowed, "cdn.example", []string{"AdGuard DNS Filter"}},
		{"mine.cdn.example", querylog.PolicyBlocked, "mine.cdn.example", []string{"Custom blocked domains"}},
		{"pixel.example", querylog.PolicyBlocked, "pixel.example", []string{"EasyList"}},
		{"tracker.example", querylog.PolicyBlocked, "tracker.example", []string{"EasyPrivacy"}},
	} {
		got := handler.DomainPolicy(test.name, "", "")
		if got.Decision != test.decision || got.Rule != test.rule || !slices.Equal(got.Sources, test.sources) {
			t.Errorf("DomainPolicy(%s) = %+v, want %s %s from %v", test.name, got, test.decision, test.rule, test.sources)
		}
	}
	// The operator's allow list still comes first, without list attribution.
	configuration.AllowedDomains = []string{"tracker.example"}
	runtime, err = Compile(configuration)
	if err != nil {
		t.Fatal(err)
	}
	if got := NewHandler(runtime).DomainPolicy("tracker.example", "", ""); got.Decision != querylog.PolicyAllowed || len(got.Sources) != 0 {
		t.Fatalf("allow-listed DomainPolicy = %+v", got)
	}
}

func TestHandlerLookupAnswersLikeAClientWithoutLogging(t *testing.T) {
	t.Parallel()
	configuration := testRuntimeConfig()
	configuration.Forwarders = []string{"127.0.0.1:1"}
	configuration.Blocking = true
	configuration.BlockedDomains = []string{"ads.example"}
	configuration.Zones = []AuthoritativeZone{testAuthoritativeZone("zone.test", "192.0.2.10")}
	runtime, err := Compile(configuration)
	if err != nil {
		t.Fatal(err)
	}
	handler := NewHandler(runtime)
	recorder := &recordingObserver{}
	handler.SetQueryObserver(recorder)

	answered, err := handler.Lookup("www.zone.test", dns.TypeA)
	if err != nil {
		t.Fatal(err)
	}
	if answered.Source != querylog.SourceAuthoritative || len(answered.Response.Answer) == 0 {
		t.Fatalf("zone lookup = %s %v", answered.Source, answered.Response)
	}
	blocked, err := handler.Lookup("pixel.ads.example", dns.TypeA)
	if err != nil {
		t.Fatal(err)
	}
	if blocked.Source != querylog.SourceBlocked || blocked.Decision.PolicyRule != "ads.example" {
		t.Fatalf("blocked lookup = %s %+v", blocked.Source, blocked.Decision)
	}
	if events := recorder.events(); len(events) != 0 {
		t.Fatalf("lookups reached the query log: %v", events)
	}
}
