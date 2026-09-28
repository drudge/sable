package dnsserver

import (
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
		if got := handler.DomainPolicy(name); got.Decision != want {
			t.Errorf("DomainPolicy(%s) = %+v, want %s", name, got, want)
		}
	}
	if got := handler.DomainPolicy("pixel.ads.example"); got.Rule != "ads.example" {
		t.Fatalf("blocked rule = %q", got.Rule)
	}
	handler.PauseBlocking(60_000_000_000)
	if got := handler.DomainPolicy("ads.example"); got.Decision != querylog.PolicyPaused {
		t.Fatalf("paused decision = %s", got.Decision)
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
