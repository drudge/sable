package store

import (
	"context"
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/drudge/sable/internal/querylog"
)

// Only lookups the recursion policy refused are read, newest first. A
// refusal for load, and anything older than the window, are left out.
func TestRefusedLookupsReadsOnlyRecursionRefusals(t *testing.T) {
	t.Parallel()
	now := time.Now().UTC().Truncate(time.Second)
	refused := func(at time.Time, client, name string, resolver querylog.ResolverDecision) querylog.Event {
		event := blockingEvent(at, client, name, querylog.SourceError)
		event.ResponseCode = dns.RcodeRefused
		event.Decision = querylog.Decision{Policy: querylog.PolicyNotEvaluated, Resolver: resolver}
		return event
	}
	opened := openQueryLogStore(t, []querylog.Event{
		refused(now.Add(-2*time.Hour), "2001:db8:1234:1500::7", "ping.example.", querylog.ResolverNotAllowed),
		refused(now.Add(-time.Hour), "2001:db8:1234:1500::7", "sync.example.", querylog.ResolverNotAllowed),
		refused(now.Add(-time.Hour), "10.0.7.20", "busy.example.", querylog.ResolverError),
		refused(now.Add(-30*time.Hour), "2001:db8:1234:1500::7", "old.example.", querylog.ResolverNotAllowed),
		blockingEvent(now.Add(-time.Hour), "10.0.7.20", "fine.example.", querylog.SourceUpstream),
	})
	lookups, err := opened.RefusedLookups(context.Background(), now.Add(-24*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if len(lookups) != 2 || lookups[0].Name != "sync.example." || lookups[1].Name != "ping.example." ||
		lookups[0].Client != "2001:db8:1234:1500::7" || !lookups[0].At.Equal(now.Add(-time.Hour)) {
		t.Fatalf("refused lookups = %+v", lookups)
	}
}
