package alerts

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/drudge/sable/internal/config"
	"github.com/drudge/sable/internal/webpush"
)

func finding(id string) Alert {
	return Alert{ID: id, Group: config.AlertGroupInsights, Kind: "devices.went-quiet", Tone: ToneAttention,
		Title: "Went quiet", Subject: "Printer", Headline: "Printer went quiet", Summary: "No queries in 24 hours.",
		Path: "/insights", PathLabel: "Open Insights", ObservedAt: testNow}
}

func problem(id, group string) Alert {
	return Alert{ID: id, Group: group, Kind: group + ".failing", Problem: true, Tone: ToneAttention,
		Title: "Backup failed", Subject: "ns1", Summary: "The nightly backup failed.", ObservedAt: testNow}
}

func TestDispatcherTakesStockThenSendsEachAlertOnce(t *testing.T) {
	t.Parallel()
	hook := newRecordingHook(t)
	source := &staticSource{}
	source.set(finding("old"))
	dispatcher, sent, _ := newTestDispatcher(t, []config.AlertDestination{{ID: "hook", URL: hook.URL}}, source)
	ctx := context.Background()
	// The first round only takes stock of what is already news.
	if err := dispatcher.Tick(ctx, testNow, true); err != nil {
		t.Fatal(err)
	}
	if len(hook.received()) != 0 || !sent.has("hook", "old") {
		t.Fatalf("taking stock sent %d alerts", len(hook.received()))
	}
	source.set(finding("old"), finding("new"))
	if err := dispatcher.Tick(ctx, testNow.Add(time.Minute), true); err != nil {
		t.Fatal(err)
	}
	received := hook.received()
	if len(received) != 1 {
		t.Fatalf("received %d alerts, want the new one", len(received))
	}
	var payload webhookAlert
	if err := json.Unmarshal([]byte(received[0].body), &payload); err != nil {
		t.Fatal(err)
	}
	if payload.ID != "new" || payload.Event != "insight" || payload.Group != config.AlertGroupInsights || payload.Source != "sable" ||
		payload.Priority != "normal" || payload.Text != "Went quiet: Printer\nNo queries in 24 hours." || !strings.HasSuffix(payload.URL, "/insights") {
		t.Fatalf("payload = %+v", payload)
	}
	// It is not sent twice.
	if err := dispatcher.Tick(ctx, testNow.Add(2*time.Minute), true); err != nil {
		t.Fatal(err)
	}
	if len(hook.received()) != 1 {
		t.Fatalf("an alert went out %d times", len(hook.received()))
	}
	if status := dispatcher.Status()["hook"]; status.LastSentTitle != "Went quiet: Printer" || status.Failing() {
		t.Fatalf("status = %+v", status)
	}
}

// Alerts that come up while paused, or in a group a destination does not
// get, count as seen, so turning alerts back on never sends the backlog.
func TestPausedAndSwitchedOffAlertsAreNotedNotSent(t *testing.T) {
	t.Parallel()
	hook := newRecordingHook(t)
	cluster := newRecordingHook(t)
	source := &staticSource{}
	dispatcher, sent, configuration := newTestDispatcher(t, []config.AlertDestination{
		{ID: "all", URL: hook.URL},
		{ID: "cluster-only", URL: cluster.URL, Sends: []string{config.AlertGroupCluster}},
	}, source)
	ctx := context.Background()
	if err := dispatcher.Tick(ctx, testNow, true); err != nil {
		t.Fatal(err)
	}
	configuration.Alerts.Paused = true
	source.set(finding("while-paused"))
	if err := dispatcher.Tick(ctx, testNow.Add(time.Minute), true); err != nil {
		t.Fatal(err)
	}
	configuration.Alerts.Paused = false
	// Sign-in alerts are off by default; backups send only failures.
	finished := Alert{ID: "backup-done", Group: config.AlertGroupBackups, Title: "Backup finished", ObservedAt: testNow}
	source.set(finding("while-paused"), Alert{ID: "sign-ins", Group: config.AlertGroupSignIns, Title: "Failed sign-ins", ObservedAt: testNow},
		finished, problem("backup-failed", config.AlertGroupBackups), problem("node-down", config.AlertGroupCluster))
	if err := dispatcher.Tick(ctx, testNow.Add(2*time.Minute), true); err != nil {
		t.Fatal(err)
	}
	ids := func(requests []recordedRequest) []string {
		found := make([]string, 0)
		for _, request := range requests {
			var payload webhookAlert
			_ = json.Unmarshal([]byte(request.body), &payload)
			found = append(found, payload.ID)
		}
		return found
	}
	if got := strings.Join(ids(hook.received()), ","); got != "backup-failed,node-down" {
		t.Fatalf("the all-groups destination got %q", got)
	}
	if got := strings.Join(ids(cluster.received()), ","); got != "node-down" {
		t.Fatalf("the cluster-only destination got %q", got)
	}
	for _, id := range []string{"while-paused", "sign-ins", "backup-done"} {
		if !sent.has("all", id) || !sent.has("cluster-only", id) {
			t.Errorf("%s was not noted as seen", id)
		}
	}
	// Turning backup successes on later does not send the one already seen.
	configuration.Alerts.Send.Backups = config.AlertBackupsAll
	if err := dispatcher.Tick(ctx, testNow.Add(3*time.Minute), true); err != nil {
		t.Fatal(err)
	}
	if len(hook.received()) != 2 {
		t.Fatalf("turning a group on sent the backlog: %v", ids(hook.received()))
	}
}

func TestOneFailingDestinationDoesNotHoldUpTheRest(t *testing.T) {
	t.Parallel()
	broken := newRecordingHook(t)
	broken.answer(http.StatusBadGateway)
	working := newRecordingHook(t)
	source := &staticSource{}
	dispatcher, sent, _ := newTestDispatcher(t, []config.AlertDestination{
		{ID: "broken", Name: "Old server", URL: broken.URL},
		{ID: "working", URL: working.URL},
	}, source)
	ctx := context.Background()
	if err := dispatcher.Tick(ctx, testNow, true); err != nil {
		t.Fatal(err)
	}
	source.set(finding("one"), finding("two"))
	err := dispatcher.Tick(ctx, testNow.Add(time.Minute), true)
	if err == nil || !strings.Contains(err.Error(), "Old server") {
		t.Fatalf("round error = %v", err)
	}
	if len(working.received()) != 2 {
		t.Fatalf("the working destination got %d alerts", len(working.received()))
	}
	// The broken one stopped at its first failure and was not told it was sent.
	if len(broken.received()) != 1 || sent.has("broken", "one") || sent.has("broken", "two") {
		t.Fatalf("the broken destination got %d requests", len(broken.received()))
	}
	if status := dispatcher.Status()["broken"]; !status.Failing() || !strings.Contains(status.LastError, "502") {
		t.Fatalf("status = %+v", status)
	}
	// Once it answers again, it hears everything it missed.
	broken.answer(http.StatusOK)
	if err := dispatcher.Tick(ctx, testNow.Add(2*time.Minute), true); err != nil {
		t.Fatal(err)
	}
	if len(broken.received()) != 3 || dispatcher.Status()["broken"].Failing() {
		t.Fatalf("after recovering, the broken destination got %d requests", len(broken.received()))
	}
}

func TestAlertsAreForgottenOnlyAfterBeingGoneAWhile(t *testing.T) {
	t.Parallel()
	hook := newRecordingHook(t)
	source := &staticSource{}
	dispatcher, sent, _ := newTestDispatcher(t, []config.AlertDestination{{ID: "hook", URL: hook.URL}}, source)
	ctx := context.Background()
	if err := dispatcher.Tick(ctx, testNow, true); err != nil {
		t.Fatal(err)
	}
	source.set(finding("flicker"))
	if err := dispatcher.Tick(ctx, testNow.Add(time.Minute), true); err != nil {
		t.Fatal(err)
	}
	// Still news ten hours later: its record is renewed, not forgotten.
	if err := dispatcher.Tick(ctx, testNow.Add(10*time.Hour), true); err != nil {
		t.Fatal(err)
	}
	source.set()
	if err := dispatcher.Tick(ctx, testNow.Add(11*time.Hour), true); err != nil {
		t.Fatal(err)
	}
	if !sent.has("hook", "flicker") {
		t.Fatal("an alert gone for an hour was forgotten")
	}
	// A source that cannot be read forgets nothing.
	source.fail(errTestSource)
	if err := dispatcher.Tick(ctx, testNow.Add(20*time.Hour), true); err != nil {
		t.Fatal(err)
	}
	if !sent.has("hook", "flicker") {
		t.Fatal("a failed source made the dispatcher forget its alerts")
	}
	source.set()
	if err := dispatcher.Tick(ctx, testNow.Add(20*time.Hour), true); err != nil {
		t.Fatal(err)
	}
	if sent.has("hook", "flicker") {
		t.Fatal("an alert gone for hours was kept")
	}
	// Coming back after that is news again.
	source.set(finding("flicker"))
	if err := dispatcher.Tick(ctx, testNow.Add(21*time.Hour), true); err != nil {
		t.Fatal(err)
	}
	if len(hook.received()) != 2 {
		t.Fatalf("received %d alerts, want the first and its return", len(hook.received()))
	}
}

func TestProblemsGoOutAtHighPriority(t *testing.T) {
	t.Parallel()
	ntfy := newRecordingHook(t)
	plain := newRecordingHook(t)
	var pushover url.Values
	pushoverHook := newRecordingHook(t)
	pushoverHook.answer(http.StatusOK)
	source := &staticSource{}
	dispatcher, _, _ := newTestDispatcher(t, []config.AlertDestination{
		{ID: "ntfy", Format: config.AlertFormatText, URL: ntfy.URL},
		{ID: "plain", URL: plain.URL},
	}, source)
	ctx := context.Background()
	if err := dispatcher.Tick(ctx, testNow, true); err != nil {
		t.Fatal(err)
	}
	source.set(problem("down", config.AlertGroupCluster), finding("quiet"))
	if err := dispatcher.Tick(ctx, testNow.Add(time.Minute), true); err != nil {
		t.Fatal(err)
	}
	received := ntfy.received()
	if len(received) != 2 || received[0].header.Get("Priority") != "high" || received[1].header.Get("Priority") != "" ||
		received[0].header.Get("Title") != "Backup failed: ns1" {
		t.Fatalf("ntfy got %+v", received)
	}
	var payload webhookAlert
	if err := json.Unmarshal([]byte(plain.received()[0].body), &payload); err != nil || payload.Priority != "high" || payload.Event != config.AlertGroupCluster {
		t.Fatalf("the plain webhook got %+v (%v)", payload, err)
	}
	built, err := Build(config.AlertDestination{Format: config.AlertFormatPushover, PushoverToken: "app", PushoverUser: "user"},
		problem("down", config.AlertGroupCluster), Links{Base: "https://sable.example"})
	if err != nil {
		t.Fatal(err)
	}
	if pushover, err = url.ParseQuery(string(built.Body)); err != nil || pushover.Get("priority") != "1" || pushover.Get("url") != "https://sable.example/" {
		t.Fatalf("Pushover form = %v (%v)", pushover, err)
	}
}

func TestSourcesRunWhereTheyArePlaced(t *testing.T) {
	t.Parallel()
	hook := newRecordingHook(t)
	lead, eachNode, replicas := &staticSource{}, &staticSource{}, &staticSource{}
	lead.set(finding("lead"))
	eachNode.set(problem("backup", config.AlertGroupBackups))
	replicas.set(problem("lead-down", config.AlertGroupCluster))
	dispatcher, sent, _ := newTestDispatcher(t, []config.AlertDestination{{ID: "hook", URL: hook.URL}},
		lead, Place(eachNode, OnEachNode), Place(replicas, OnReplicas))
	ctx := context.Background()
	if err := dispatcher.Tick(ctx, testNow, true); err != nil {
		t.Fatal(err)
	}
	if !sent.has("hook", "lead") || !sent.has("hook", "backup") || sent.has("hook", "lead-down") {
		t.Fatalf("the lead ran the wrong sources: %+v", sent.sent)
	}
	replica, replicaSent, _ := newTestDispatcher(t, []config.AlertDestination{{ID: "hook", URL: hook.URL}},
		lead, Place(eachNode, OnEachNode), Place(replicas, OnReplicas))
	if err := replica.Tick(ctx, testNow, false); err != nil {
		t.Fatal(err)
	}
	if replicaSent.has("hook", "lead") || replicaSent.has("hook", "backup") || !replicaSent.has("hook", "lead-down") {
		t.Fatalf("the replica ran the wrong sources: %+v", replicaSent.sent)
	}
	// A replica hands its own problems to the lead instead.
	local, err := replica.Local(ctx, testNow)
	if err != nil || len(local) != 1 || local[0].ID != "backup" {
		t.Fatalf("local alerts = %+v, %v", local, err)
	}
}

func TestTestSendsASampleEvenWhilePaused(t *testing.T) {
	t.Parallel()
	hook := newRecordingHook(t)
	dispatcher, _, configuration := newTestDispatcher(t, []config.AlertDestination{{ID: "hook", Format: config.AlertFormatText, URL: hook.URL}})
	configuration.Alerts.Paused = true
	destination, _, err := dispatcher.Test(context.Background(), "hook", testNow)
	if err != nil || destination.URL != hook.URL {
		t.Fatalf("test = %+v, %v", destination, err)
	}
	if received := hook.received(); len(received) != 1 || received[0].header.Get("Title") != "Test alert: Sable" ||
		!strings.Contains(received[0].body, "/settings?tab=alerts") {
		t.Fatalf("received = %+v", received)
	}
	if _, _, err := dispatcher.Test(context.Background(), "gone", testNow); err != ErrNoDestination {
		t.Fatalf("testing a missing destination = %v", err)
	}
}

func TestBrowsersGetPushesAndGoneOnesAreForgotten(t *testing.T) {
	t.Parallel()
	key, err := webpush.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	service := newPushService(t)
	subscriptions := &memorySubscriptions{}
	dispatcher, _, _ := newTestDispatcher(t, []config.AlertDestination{{ID: config.AlertFormatBrowser, Format: config.AlertFormatBrowser}})
	dispatcher.Browsers = &Browsers{Keys: fixedPushKeys{key}, Store: subscriptions, Client: service.Client()}
	ctx := context.Background()
	if _, _, err := dispatcher.Test(ctx, config.AlertFormatBrowser, testNow); err != ErrNoBrowsers {
		t.Fatalf("testing with no browsers = %v", err)
	}
	subscriptions.subscriptions = []webpush.Subscription{browserSubscriptionFor(t, service.URL+"/push/one")}
	_, receipt, err := dispatcher.Test(ctx, config.AlertFormatBrowser, testNow)
	if err != nil || receipt.Browsers != 1 || len(service.received()) != 1 {
		t.Fatalf("test = %+v, %v; %d pushes", receipt, err, len(service.received()))
	}
	if push := service.received()[0]; push.Header.Get("Content-Encoding") != "aes128gcm" || push.Header.Get("TTL") != "86400" ||
		push.Header.Get("Urgency") != "normal" || !strings.HasPrefix(push.Header.Get("Authorization"), "vapid t=") {
		t.Fatalf("push headers = %v", push.Header)
	}
	if _, err := dispatcher.Deliver(ctx, config.AlertDestination{Format: config.AlertFormatBrowser}, problem("down", config.AlertGroupCluster)); err != nil {
		t.Fatal(err)
	}
	if urgency := service.received()[1].Header.Get("Urgency"); urgency != "high" {
		t.Fatalf("a problem was pushed with urgency %q", urgency)
	}
	service.goAway()
	if _, _, err := dispatcher.Test(ctx, config.AlertFormatBrowser, testNow); err != ErrNoBrowsers {
		t.Fatalf("testing a gone browser = %v", err)
	}
	if remaining, _ := subscriptions.PushSubscriptions(ctx); len(remaining) != 0 {
		t.Fatalf("a gone browser was kept: %+v", remaining)
	}
}

// A replica keeps its own record of what each destination was sent, and it
// never ran the lead's sources. When it becomes the lead, the old lead already
// told every destination what is news, so its first round only takes stock.
func TestANewLeadTakesStockInsteadOfSendingAgain(t *testing.T) {
	t.Parallel()
	hook := newRecordingHook(t)
	source := &staticSource{}
	source.set(finding("already-sent-by-the-old-lead"))
	dispatcher, sent, _ := newTestDispatcher(t, []config.AlertDestination{{ID: "hook", URL: hook.URL}}, source)
	ctx := context.Background()
	if err := dispatcher.Tick(ctx, testNow, false); err != nil {
		t.Fatal(err)
	}
	if err := dispatcher.Tick(ctx, testNow.Add(time.Minute), true); err != nil {
		t.Fatal(err)
	}
	if len(hook.received()) != 0 || !sent.has("hook", "already-sent-by-the-old-lead") {
		t.Fatalf("the new lead sent %d alerts the old lead had already sent", len(hook.received()))
	}
	source.set(finding("already-sent-by-the-old-lead"), finding("new"))
	if err := dispatcher.Tick(ctx, testNow.Add(2*time.Minute), true); err != nil {
		t.Fatal(err)
	}
	if len(hook.received()) != 1 {
		t.Fatalf("the new lead sent %d alerts, want the one that is new", len(hook.received()))
	}
}
