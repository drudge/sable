package store

import (
	"context"
	"testing"
	"time"

	"github.com/drudge/sable/internal/querylog"
)

func TestClientActivityTracksSightingsNewDomainsAndBaseline(t *testing.T) {
	t.Parallel()

	now := time.Now().UTC().Truncate(time.Second)
	day := 24 * time.Hour
	events := []querylog.Event{
		// The laptop has been around for days and picks up one new name today.
		blockingEvent(now.Add(-6*day), "10.0.0.5", "mail.example.com.", querylog.SourceUpstream),
		blockingEvent(now.Add(-5*day), "10.0.0.5", "mail.example.com.", querylog.SourceUpstream),
		blockingEvent(now.Add(-3*time.Hour), "10.0.0.5", "mail.example.com.", querylog.SourceCache),
		blockingEvent(now.Add(-2*time.Hour), "10.0.0.5", "new.example.net.", querylog.SourceUpstream),
		blockingEvent(now.Add(-1*time.Hour), "10.0.0.5", "ads.example.", querylog.SourceBlocked),
		// The plug appears for the first time today.
		blockingEvent(now.Add(-30*time.Minute), "10.0.0.77", "iot.example.", querylog.SourceUpstream),
		// The camera was busy last week and has gone silent.
		blockingEvent(now.Add(-4*day), "10.0.0.9", "cam.example.", querylog.SourceUpstream),
		blockingEvent(now.Add(-3*day), "10.0.0.9", "cam.example.", querylog.SourceUpstream),
	}
	opened := openQueryLogStore(t, events)

	report, err := opened.ClientActivity(context.Background(), now.Add(-day), now)
	if err != nil {
		t.Fatal(err)
	}
	byClient := make(map[string]querylog.ClientActivity, len(report.Clients))
	for _, client := range report.Clients {
		byClient[client.Client] = client
	}
	laptop := byClient["10.0.0.5"]
	if laptop.Queries != 3 || laptop.Blocked != 1 || laptop.NewDomains != 2 || laptop.Recent != 3 || laptop.Baseline != 2 {
		t.Fatalf("laptop = %+v", laptop)
	}
	if !laptop.FirstSeen.Equal(now.Add(-6*day)) || !laptop.LastSeen.Equal(now.Add(-time.Hour)) {
		t.Fatalf("laptop seen %s to %s", laptop.FirstSeen, laptop.LastSeen)
	}
	if plug := byClient["10.0.0.77"]; !plug.FirstSeen.Equal(now.Add(-30*time.Minute)) || plug.NewDomains != 1 {
		t.Fatalf("plug = %+v", plug)
	}
	camera, found := byClient["10.0.0.9"]
	if !found || camera.Queries != 0 || camera.Recent != 0 || camera.Baseline != 2 {
		t.Fatalf("camera = %+v (found %t), want its quiet day reported against last week", camera, found)
	}
	if report.SeenSince.IsZero() {
		t.Fatal("report does not say when first-seen tracking began")
	}
}

func TestClientDomainsMatchTheQueryLog(t *testing.T) {
	t.Parallel()

	now := time.Now().UTC().Truncate(time.Second)
	opened := openQueryLogStore(t, []querylog.Event{
		blockingEvent(now.Add(-50*time.Minute), "10.0.0.5", "mail.example.com.", querylog.SourceUpstream),
		blockingEvent(now.Add(-40*time.Minute), "10.0.0.5", "Mail.Example.com", querylog.SourceCache),
		blockingEvent(now.Add(-30*time.Minute), "fd00::5", "mail.example.com.", querylog.SourceCache),
		blockingEvent(now.Add(-20*time.Minute), "10.0.0.5", "ads.example.", querylog.SourceBlocked),
		blockingEvent(now.Add(-10*time.Minute), "10.0.0.55", "mail.example.com.", querylog.SourceUpstream),
	})
	domains, err := opened.ClientTopDomains(context.Background(), []string{"10.0.0.5", "FD00::5"}, now.Add(-time.Hour), now, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(domains) != 2 || domains[0].Name != "mail.example.com" || domains[0].Queries != 3 || domains[1].Blocked != 1 {
		t.Fatalf("domains = %+v", domains)
	}
	page, err := opened.QueryEvents(context.Background(), querylog.Filter{
		ClientIP: "10.0.0.5", Name: "mail.example.com", Exact: true, Since: now.Add(-time.Hour), Until: now, PageSize: 50,
	})
	if err != nil {
		t.Fatal(err)
	}
	if page.TotalEntries != 2 {
		t.Fatalf("query log reports %d for one address, want 2", page.TotalEntries)
	}

	// fd00::5 met mail.example.com only after 10.0.0.5 had, so across the
	// device's two addresses there are two first-time names, not three.
	count, err := opened.ClientNewDomainCount(context.Background(), []string{"10.0.0.5", "fd00::5"}, now.Add(-time.Hour), now)
	if err != nil || count != 2 {
		t.Fatalf("device new domain count = %d, %v, want 2", count, err)
	}
	early, err := opened.ClientNewDomainCount(context.Background(), []string{"10.0.0.5", "fd00::5"}, now.Add(-35*time.Minute), now)
	if err != nil || early != 1 {
		t.Fatalf("new domains after the first sighting = %d, %v, want only ads.example", early, err)
	}

	fresh, err := opened.ClientNewDomains(context.Background(), []string{"10.0.0.5"}, now.Add(-time.Hour), now, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(fresh) != 2 || fresh[0].Name != "ads.example" || !fresh[0].FirstSeen.Equal(now.Add(-20*time.Minute)) {
		t.Fatalf("new domains = %+v, want newest first", fresh)
	}
}

func TestClientIdentitiesWidenTheirSpanAndPrune(t *testing.T) {
	t.Parallel()

	now := time.Now().UTC().Truncate(time.Second)
	opened := openQueryLogStore(t, nil)
	ctx := context.Background()
	record := func(at time.Time, hostname string) {
		t.Helper()
		if err := opened.RecordClientIdentities(ctx, []querylog.ClientIdentity{
			{Address: "10.0.0.5", MAC: "AA:BB:CC:00:11:22", Source: "neighbor", SeenAt: at},
			{Address: "10.0.0.5", MAC: "aa:bb:cc:00:11:22", Source: "unifi", Hostname: hostname, SeenAt: at},
			{Address: "", MAC: "ignored", Source: "neighbor", SeenAt: at},
		}); err != nil {
			t.Fatal(err)
		}
	}
	record(now.Add(-2*time.Hour), "old-name")
	record(now.Add(-time.Hour), "george-laptop")
	record(now.Add(-3*time.Hour), "older-name")

	identities, err := opened.ClientIdentities(ctx, now.Add(-24*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if len(identities) != 2 {
		t.Fatalf("identities = %+v", identities)
	}
	for _, identity := range identities {
		if identity.Source == "unifi" && identity.Hostname != "george-laptop" {
			t.Fatalf("hostname = %q, want the newest sighting's name", identity.Hostname)
		}
		if identity.MAC != "aa:bb:cc:00:11:22" || !identity.FirstSeen.Equal(now.Add(-3*time.Hour)) || !identity.LastSeen.Equal(now.Add(-time.Hour)) {
			t.Fatalf("identity = %+v", identity)
		}
	}

	if err := opened.PruneQueryEvents(ctx, now.Add(-30*time.Minute)); err != nil {
		t.Fatal(err)
	}
	if identities, err := opened.ClientIdentities(ctx, time.Time{}); err != nil || len(identities) != 0 {
		t.Fatalf("identities after prune = %+v, %v", identities, err)
	}
}

func TestClientDomainHistoryListsEveryNameAcrossAddresses(t *testing.T) {
	t.Parallel()

	now := time.Now().UTC().Truncate(time.Second)
	day := 24 * time.Hour
	opened := openQueryLogStore(t, []querylog.Event{
		blockingEvent(now.Add(-9*day), "10.0.0.5", "mail.example.com.", querylog.SourceUpstream),
		blockingEvent(now.Add(-2*day), "fd00::5", "mail.example.com.", querylog.SourceUpstream),
		blockingEvent(now.Add(-time.Hour), "fd00::5", "discord.com.", querylog.SourceUpstream),
		blockingEvent(now.Add(-time.Hour), "10.0.0.9", "other.example.", querylog.SourceUpstream),
	})
	history, err := opened.ClientDomainHistory(context.Background(), []string{"10.0.0.5", "FD00::5"}, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(history) != 2 || history[0].Name != "discord.com" || history[1].Name != "mail.example.com" || !history[1].FirstSeen.Equal(now.Add(-9*day)) {
		t.Fatalf("history = %+v", history)
	}
}

func TestClientNamesMatchingFindsSuffixesPerClient(t *testing.T) {
	t.Parallel()

	now := time.Now().UTC().Truncate(time.Second)
	opened := openQueryLogStore(t, []querylog.Event{
		blockingEvent(now.Add(-time.Hour), "10.0.0.46", "ws.ring.com.", querylog.SourceUpstream),
		blockingEvent(now.Add(-time.Hour), "10.0.0.46", "ring.com.", querylog.SourceUpstream),
		blockingEvent(now.Add(-time.Hour), "10.0.0.46", "notring.com.", querylog.SourceUpstream),
		blockingEvent(now.Add(-time.Hour), "10.0.0.5", "example.net.", querylog.SourceUpstream),
		blockingEvent(now.Add(-48*time.Hour), "10.0.0.9", "ring.com.", querylog.SourceUpstream),
	})
	matches, err := opened.ClientNamesMatching(context.Background(), now.Add(-24*time.Hour), []string{"ring.com"})
	if err != nil {
		t.Fatal(err)
	}
	if len(matches) != 1 || len(matches["10.0.0.46"]) != 2 {
		t.Fatalf("matches = %+v", matches)
	}
}
