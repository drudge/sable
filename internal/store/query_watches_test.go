package store

import (
	"context"
	"testing"
	"time"

	"github.com/drudge/sable/internal/querylog"
)

// A watch reads only the rows logged since its last reading, finds names
// under its domains whatever case they were asked in, and never names a
// look-alike that only ends in the same letters.
func TestWatchedLookupsReadOnlyNewRowsUnderTheDomains(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Second)
	opened := openQueryLogStore(t, []querylog.Event{
		blockingEvent(now.Add(-time.Hour), "10.0.0.5", "discord.com.", querylog.SourceUpstream),
	})
	start, err := opened.LatestQueryID(ctx)
	if err != nil || start == 0 {
		t.Fatalf("latest = %d, %v", start, err)
	}
	if err := opened.WriteQueryEvents(ctx, []querylog.Event{
		blockingEvent(now, "10.0.0.5", "Gateway.Discord.COM.", querylog.SourceCache),
		blockingEvent(now, "10.0.0.6", "notdiscord.com.", querylog.SourceUpstream),
		blockingEvent(now, "10.0.0.7", "roblox.com.", querylog.SourceBlocked),
		blockingEvent(now, "10.0.0.8", "example.net.", querylog.SourceUpstream),
	}); err != nil {
		t.Fatal(err)
	}
	lookups, next, err := opened.WatchedLookups(ctx, start, []string{"discord.com", "roblox.com"}, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(lookups) != 2 || lookups[0].Name != "gateway.discord.com" || lookups[0].Blocked || lookups[0].ClientIP != "10.0.0.5" ||
		lookups[1].Name != "roblox.com" || !lookups[1].Blocked {
		t.Fatalf("lookups = %+v", lookups)
	}
	latest, _ := opened.LatestQueryID(ctx)
	if next != latest {
		t.Fatalf("next = %d, want the newest row %d", next, latest)
	}
	if again, after, err := opened.WatchedLookups(ctx, next, []string{"discord.com"}, 10); err != nil || len(again) != 0 || after != next {
		t.Fatalf("second reading = %+v, %d, %v", again, after, err)
	}
	// A full page leaves the rest for the next reading.
	first, cut, err := opened.WatchedLookups(ctx, start, []string{"discord.com", "roblox.com"}, 1)
	if err != nil || len(first) != 1 || cut != first[0].ID {
		t.Fatalf("limited reading = %+v, %d, %v", first, cut, err)
	}
	rest, _, err := opened.WatchedLookups(ctx, cut, []string{"discord.com", "roblox.com"}, 10)
	if err != nil || len(rest) != 1 || rest[0].Name != "roblox.com" {
		t.Fatalf("rest = %+v, %v", rest, err)
	}
}
