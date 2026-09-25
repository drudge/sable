package store

import (
	"context"
	"testing"
	"time"

	"github.com/drudge/sable/internal/querylog"
)

func TestRepeatedLookupsKeepsNamesOnlyOneClientUses(t *testing.T) {
	t.Parallel()

	now := time.Now().UTC().Truncate(time.Second)
	events := make([]querylog.Event, 0)
	for index := range 30 {
		at := now.Add(-time.Duration(index) * 10 * time.Minute)
		events = append(events,
			blockingEvent(at, "10.0.0.42", "beacon.example.net.", querylog.SourceUpstream),
			// Two devices share this name, so it is not one device's check-in.
			blockingEvent(at, "10.0.0.5", "shared.example.com.", querylog.SourceUpstream),
			blockingEvent(at.Add(time.Second), "10.0.0.6", "shared.example.com.", querylog.SourceUpstream),
		)
	}
	// Too few lookups to show a schedule.
	events = append(events, blockingEvent(now.Add(-time.Hour), "10.0.0.42", "rare.example.", querylog.SourceUpstream))
	opened := openQueryLogStore(t, events)

	lookups, err := opened.RepeatedLookups(context.Background(), now.Add(-24*time.Hour), now.Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if len(lookups) != 1 || lookups[0].Client != "10.0.0.42" || lookups[0].Name != "beacon.example.net" || len(lookups[0].Times) != 30 {
		t.Fatalf("lookups = %+v", lookups)
	}
	if !lookups[0].Times[0].Before(lookups[0].Times[29]) {
		t.Fatal("lookup times are not oldest first")
	}
}
