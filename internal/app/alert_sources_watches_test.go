package app

import (
	"context"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/drudge/sable/internal/alerts"
	"github.com/drudge/sable/internal/config"
	"github.com/drudge/sable/internal/querylog"
)

// fakeWatchLog is one node's query log and the hardware addresses it knows.
type fakeWatchLog struct {
	lookups    []querylog.WatchedLookup
	identities []querylog.ClientIdentity
	reads      int
}

func (log *fakeWatchLog) add(at time.Time, client, name string, blocked bool) {
	log.lookups = append(log.lookups, querylog.WatchedLookup{
		ID: int64(len(log.lookups) + 1), OccurredAt: at, ClientIP: client, Name: name, Blocked: blocked,
	})
}

func (log *fakeWatchLog) LatestQueryID(context.Context) (int64, error) {
	return int64(len(log.lookups)), nil
}

func (log *fakeWatchLog) WatchedLookups(_ context.Context, after int64, domains []string, limit int) ([]querylog.WatchedLookup, int64, error) {
	log.reads++
	var found []querylog.WatchedLookup
	for _, lookup := range log.lookups {
		if lookup.ID <= after || len(found) == limit {
			continue
		}
		for _, domain := range domains {
			if lookup.Name == domain || strings.HasSuffix(lookup.Name, "."+domain) {
				found = append(found, lookup)
				break
			}
		}
	}
	return found, int64(len(log.lookups)), nil
}

func (log *fakeWatchLog) ClientIdentities(context.Context, time.Time) ([]querylog.ClientIdentity, error) {
	return log.identities, nil
}

// watchTestConfig watches discord.com and roblox.com for Emma's iPad, which
// the operator named by its hardware address.
func watchTestConfig(watch config.AlertWatch) func() config.Config {
	configuration := config.Defaults()
	if watch.ID == "" {
		watch = config.AlertWatch{
			ID: "kids", Name: "Kids' games", Domains: []string{"discord.com", "roblox.com"},
			Devices: []string{"mac:aa:bb:cc:dd:ee:ff"}, Enabled: true,
		}
	}
	watch.Normalize()
	configuration.Alerts.Watches = []config.AlertWatch{watch}
	configuration.Clients = []config.Client{{Name: "Emma's iPad", MAC: "aa:bb:cc:dd:ee:ff"}}
	return func() config.Config { return configuration }
}

func emmasIdentities() []querylog.ClientIdentity {
	return []querylog.ClientIdentity{
		{Address: "10.0.7.20", MAC: "aa:bb:cc:dd:ee:ff", Source: "neighbor"},
		{Address: "2001:db8::20", MAC: "aa:bb:cc:dd:ee:ff", Source: "neighbor"},
	}
}

func leading(lead bool) func() bool { return func() bool { return lead } }

// A device looking up a watched name alerts once, then stays quiet for the
// watch's quiet time however often it asks again, and alerts again after.
func TestAWatchAlertsOncePerDeviceInItsQuietWindow(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	log := &fakeWatchLog{identities: emmasIdentities()}
	log.add(alertTestNow.Add(-time.Hour), "10.0.7.20", "discord.com", false)
	source := newWatchSource(log, watchTestConfig(config.AlertWatch{}), alertTestNode(false), leading(true), nil)

	// The first reading starts at the newest row, so old lookups never alert.
	if found, err := source.Alerts(ctx, alertTestNow); err != nil || len(found) != 0 {
		t.Fatalf("first reading = %+v, %v", found, err)
	}
	first := alertTestNow.Add(10 * time.Second)
	log.add(first, "10.0.7.20", "gateway.discord.com", false)
	log.add(first.Add(20*time.Second), "2001:db8::20", "discord.com", true)
	log.add(first.Add(30*time.Second), "10.0.7.21", "discord.com", false)
	now := alertTestNow.Add(time.Minute)
	found, err := source.Alerts(ctx, now)
	if err != nil {
		t.Fatal(err)
	}
	checkAlerts(t, found, []wantAlert{{
		id: "watches:kids:mac:aa:bb:cc:dd:ee:ff:" + itoa(first.Unix()), group: config.AlertGroupWatches, kind: watchAlertKind,
		title: "Kids' games", subject: "Emma's iPad", tone: alerts.ToneAttention,
		path:    "/logs?client_ip=10.0.7.20&match=exact&name=gateway.discord.com&start=" + url.QueryEscape(first.Add(-time.Minute).Format(time.RFC3339)) + "&tab=queries",
		summary: "Emma's iPad looked up gateway.discord.com and 1 other name 2 times in under a minute. 1 was blocked.",
		reasons: []string{"Looked up gateway.discord.com and discord.com", "1 lookup blocked", "From 10.0.7.20 and 2001:db8::20"},
	}})
	if last := source.LastAlert()["kids"]; !last.Equal(now) {
		t.Fatalf("last alert = %v, want %v", last, now)
	}

	// Asking again inside the quiet hour keeps the same alert, which the
	// dispatcher has already sent.
	log.add(now.Add(10*time.Second), "10.0.7.20", "roblox.com", false)
	again, err := source.Alerts(ctx, now.Add(time.Minute))
	if err != nil || len(again) != 1 || again[0].ID != found[0].ID {
		t.Fatalf("inside the quiet time = %+v, %v", again, err)
	}

	// After the hour a new lookup alerts again, with a new ID.
	later := first.Add(time.Hour + time.Minute)
	for minute := time.Duration(2); minute <= 61; minute++ {
		if _, err := source.Alerts(ctx, alertTestNow.Add(minute*time.Minute)); err != nil {
			t.Fatal(err)
		}
	}
	log.add(later, "10.0.7.20", "roblox.com", false)
	next, err := source.Alerts(ctx, later.Add(30*time.Second))
	if err != nil || len(next) != 1 || next[0].ID == found[0].ID || next[0].Headline != "Emma's iPad looked up roblox.com" {
		t.Fatalf("after the quiet time = %+v, %v", next, err)
	}
	if next[0].Summary != "Emma's iPad looked up roblox.com. It was allowed." {
		t.Fatalf("summary = %q", next[0].Summary)
	}
}

// A replica hands its hits to the lead in its report; the lead weighs them
// with its own, so a device that asks both nodes alerts once, naming both.
func TestAWatchCountsLookupsOnEveryNodeOnce(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	configuration := watchTestConfig(config.AlertWatch{})
	replicaLog := &fakeWatchLog{identities: emmasIdentities()}
	replicaNode := func() alertNode { return alertNode{ID: "node-2", Name: "ns2", Clustered: true} }
	replica := newWatchSource(replicaLog, configuration, replicaNode, leading(false), nil)
	hits := alerts.Place(watchReplicaHits{replica}, alerts.OnEachNode)
	var reported []alerts.Alert
	leadLog := &fakeWatchLog{identities: emmasIdentities()}
	lead := newWatchSource(leadLog, configuration, alertTestNode(true), leading(true),
		func(time.Time) []alerts.Alert {
			return append(reported, alerts.Alert{ID: "other", Kind: "cluster.node-down"})
		})

	for _, step := range []func(time.Time) error{
		func(now time.Time) error { _, err := hits.Alerts(ctx, now); return err },
		func(now time.Time) error { _, err := lead.Alerts(ctx, now); return err },
	} {
		if err := step(alertTestNow); err != nil {
			t.Fatal(err)
		}
	}
	replicaLog.add(alertTestNow.Add(5*time.Second), "10.0.7.20", "discord.com", false)
	replicaLog.add(alertTestNow.Add(6*time.Second), "10.0.7.99", "discord.com", false)
	leadLog.add(alertTestNow.Add(15*time.Second), "10.0.7.20", "discord.com", false)
	now := alertTestNow.Add(time.Minute)
	var err error
	reported, err = hits.Alerts(ctx, now)
	if err != nil || len(reported) != 2 || reported[0].Kind != watchHitKind || reported[0].Watch == nil || reported[0].Watch.Node != "ns2" {
		t.Fatalf("replica report = %+v, %v", reported, err)
	}
	// The lead says nothing through the replica source; it reads its own hits
	// as the watch source.
	if own, err := (watchReplicaHits{lead}).Alerts(ctx, now); err != nil || len(own) != 0 {
		t.Fatalf("lead's own report = %+v, %v", own, err)
	}
	found, err := lead.Alerts(ctx, now)
	if err != nil || len(found) != 1 {
		t.Fatalf("lead alerts = %+v, %v", found, err)
	}
	alert := found[0]
	if !strings.HasSuffix(alert.ID, ":"+itoa(alertTestNow.Add(5*time.Second).Unix())) ||
		alert.Summary != "Emma's iPad looked up discord.com 2 times in under a minute. All were allowed." ||
		alert.Reasons[len(alert.Reasons)-1] != "Seen by ns1 and ns2" {
		t.Fatalf("alert = %+v", alert)
	}
	// The replica repeats its list each minute; the same hits never open a
	// second alert.
	again, err := lead.Alerts(ctx, now.Add(time.Minute))
	if err != nil || len(again) != 1 || again[0].ID != alert.ID {
		t.Fatalf("repeated report = %+v, %v", again, err)
	}
}

func TestAWatchOnlyAlertsOnTheResultItAsksFor(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	log := &fakeWatchLog{}
	watch := config.AlertWatch{ID: "bad", Domains: []string{"bad.example"}, Result: config.AlertWatchAllowed, Enabled: true}
	source := newWatchSource(log, watchTestConfig(watch), alertTestNode(false), leading(true), nil)
	if _, err := source.Alerts(ctx, alertTestNow); err != nil {
		t.Fatal(err)
	}
	log.add(alertTestNow.Add(time.Second), "10.0.7.30", "bad.example", true)
	found, err := source.Alerts(ctx, alertTestNow.Add(time.Minute))
	if err != nil || len(found) != 0 {
		t.Fatalf("a blocked lookup alerted an allowed-only watch: %+v, %v", found, err)
	}
	log.add(alertTestNow.Add(61*time.Second), "10.0.7.30", "cdn.bad.example", false)
	found, err = source.Alerts(ctx, alertTestNow.Add(2*time.Minute))
	if err != nil || len(found) != 1 || found[0].Title != "bad.example" || found[0].Subject != "10.0.7.30" ||
		!strings.HasPrefix(found[0].ID, "watches:bad:ip:10.0.7.30:") {
		t.Fatalf("an allowed lookup = %+v, %v", found, err)
	}
}

// A watch switched off, or a query log switched off, reads nothing, and a
// watch switched back on starts from then rather than catching up.
func TestAWatchThatIsOffReadsNothing(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	log := &fakeWatchLog{identities: emmasIdentities()}
	watch := config.AlertWatch{ID: "kids", Domains: []string{"discord.com"}}
	source := newWatchSource(log, watchTestConfig(watch), alertTestNode(false), leading(true), nil)
	log.add(alertTestNow, "10.0.7.20", "discord.com", false)
	for minute := range 3 {
		if found, err := source.Alerts(ctx, alertTestNow.Add(time.Duration(minute)*time.Minute)); err != nil || len(found) != 0 {
			t.Fatalf("an off watch = %+v, %v", found, err)
		}
	}
	if log.reads != 0 {
		t.Fatalf("an off watch read the query log %d times", log.reads)
	}
	configuration := watchTestConfig(config.AlertWatch{})()
	configuration.QueryLog.Enabled = false
	quiet := newWatchSource(log, func() config.Config { return configuration }, alertTestNode(false), leading(true), nil)
	for minute := range 3 {
		if found, err := quiet.Alerts(ctx, alertTestNow.Add(time.Duration(minute)*time.Minute)); err != nil || len(found) != 0 {
			t.Fatalf("with the query log off = %+v, %v", found, err)
		}
	}
	if log.reads != 0 {
		t.Fatalf("watches read a query log that is off %d times", log.reads)
	}
}

// A node that stopped reading for a while, as when alerts had nowhere to
// go, starts again from the newest row rather than sending old news.
func TestAWatchSkipsWhatItMissedWhileNotReading(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	log := &fakeWatchLog{identities: emmasIdentities()}
	source := newWatchSource(log, watchTestConfig(config.AlertWatch{}), alertTestNode(false), leading(true), nil)
	if _, err := source.Alerts(ctx, alertTestNow); err != nil {
		t.Fatal(err)
	}
	log.add(alertTestNow.Add(time.Minute), "10.0.7.20", "discord.com", false)
	found, err := source.Alerts(ctx, alertTestNow.Add(watchRestartAfter+time.Minute))
	if err != nil || len(found) != 0 {
		t.Fatalf("after a gap = %+v, %v", found, err)
	}
}

func itoa(value int64) string { return strconv.FormatInt(value, 10) }

// The lead sends what replicas report about themselves as it is, but a
// replica's watch hits are the watch source's to weigh, never sent as they
// are.
func TestTheLeadNeverSendsAReplicasWatchHits(t *testing.T) {
	t.Parallel()
	view := &fakeClusterView{reported: []alerts.Alert{
		{ID: "server.certificate-renewal:node-2", Kind: "server.certificate-renewal"},
		{ID: "watches.hit:node-2:kids:10.0.7.20:1", Kind: watchHitKind, Watch: &alerts.WatchHit{Watch: "kids"}},
	}}
	var sent []alerts.Alert
	for _, source := range clusterAlertSources(view) {
		if placed, ok := source.(alerts.Placed); ok && placed.Placement() != alerts.OnLead {
			continue
		}
		found, err := source.Alerts(context.Background(), alertTestNow)
		if err != nil {
			t.Fatal(err)
		}
		sent = append(sent, found...)
	}
	if len(sent) != 1 || sent[0].ID != "server.certificate-renewal:node-2" {
		t.Fatalf("sent = %+v", sent)
	}
}

// With Insights off Sable records no hardware, so a watch knows a client by
// its address alone: one picked by hardware address no longer matches, and
// one picked by address still does.
func TestWithInsightsOffAWatchKnowsClientsByAddress(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	log := &fakeWatchLog{identities: emmasIdentities()}
	configuration := watchTestConfig(config.AlertWatch{})()
	configuration.Insights.Enabled = false
	configuration.Alerts.Watches[0].Devices = append(configuration.Alerts.Watches[0].Devices, "10.0.7.30")
	source := newWatchSource(log, func() config.Config { return configuration }, alertTestNode(false), leading(true), nil)
	if _, err := source.Alerts(ctx, alertTestNow); err != nil {
		t.Fatal(err)
	}
	log.add(alertTestNow.Add(time.Second), "10.0.7.20", "discord.com", false)
	log.add(alertTestNow.Add(2*time.Second), "10.0.7.30", "discord.com", false)
	found, err := source.Alerts(ctx, alertTestNow.Add(time.Minute))
	if err != nil || len(found) != 1 || found[0].Subject != "10.0.7.30" || !strings.HasPrefix(found[0].ID, "watches:kids:ip:10.0.7.30:") {
		t.Fatalf("alerts = %+v, %v", found, err)
	}
}
