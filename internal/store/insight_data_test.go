package store

import (
	"context"
	"testing"
	"time"

	"github.com/drudge/sable/internal/insights"
	"github.com/drudge/sable/internal/querylog"
)

func countRows(t *testing.T, opened *Store, table string) int {
	t.Helper()
	var count int
	if err := opened.database.QueryRowContext(context.Background(), "SELECT COUNT(*) FROM "+table).Scan(&count); err != nil {
		t.Fatalf("count %s: %v", table, err)
	}
	return count
}

func TestClientTrackingOffKeepsNothingAboutDevices(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Second)
	opened := openQueryLogStore(t, nil)
	if err := opened.StopClientTracking(ctx); err != nil {
		t.Fatal(err)
	}
	if err := opened.WriteQueryEvents(ctx, []querylog.Event{
		blockingEvent(now, "10.0.0.5", "mail.example.com.", querylog.SourceUpstream),
	}); err != nil {
		t.Fatal(err)
	}
	if err := opened.RecordClientIdentities(ctx, []querylog.ClientIdentity{
		{Address: "10.0.0.5", MAC: "aa:bb:cc:dd:ee:ff", Source: "neighbor", SeenAt: now},
	}); err != nil {
		t.Fatal(err)
	}
	// The query log itself keeps writing.
	if got := countRows(t, opened, "sable_query_log"); got != 1 {
		t.Fatalf("query log rows = %d, want 1", got)
	}
	for _, table := range []string{"sable_client_seen", "sable_client_domain_seen", "sable_client_identity"} {
		if got := countRows(t, opened, table); got != 0 {
			t.Errorf("%s kept %d rows with tracking off", table, got)
		}
	}
	// Turning tracking off settles the fill from history, so it never runs
	// once tracking is back on.
	if filled, err := opened.BackfillClientSightings(ctx); err != nil || filled {
		t.Fatalf("BackfillClientSightings = %t, %v; want nothing filled", filled, err)
	}
}

func TestResumeClientTrackingStartsFresh(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Second)
	day := 24 * time.Hour
	opened := openQueryLogStore(t, []querylog.Event{
		blockingEvent(now.Add(-9*day), "10.0.0.5", "mail.example.com.", querylog.SourceUpstream),
	})
	if err := opened.StopClientTracking(ctx); err != nil {
		t.Fatal(err)
	}
	if err := opened.ResumeClientTracking(ctx, now); err != nil {
		t.Fatal(err)
	}
	if !opened.ClientTracking() {
		t.Fatal("tracking is still off after resuming")
	}
	since, _, err := opened.rollupMarker(ctx, clientSeenSinceKey)
	if err != nil || !since.Equal(now) {
		t.Fatalf("tracking marker = %s, %v; want %s", since, err, now)
	}
	if filled, err := opened.BackfillClientSightings(ctx); err != nil || filled {
		t.Fatalf("BackfillClientSightings = %t, %v; want no fill from the old query log", filled, err)
	}
	if err := opened.WriteQueryEvents(ctx, []querylog.Event{
		blockingEvent(now, "10.0.0.9", "cam.example.", querylog.SourceUpstream),
	}); err != nil {
		t.Fatal(err)
	}
	if got := countRows(t, opened, "sable_client_seen"); got != 2 {
		t.Fatalf("client sightings = %d, want the old one and the new one", got)
	}
}

func TestDeleteInsightDataKeepsTheAlertLedger(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Second)
	opened := openQueryLogStore(t, []querylog.Event{
		blockingEvent(now.Add(-48*time.Hour), "10.0.0.5", "mail.example.com.", querylog.SourceUpstream),
		blockingEvent(now, "10.0.0.9", "cam.example.", querylog.SourceUpstream),
	})
	if err := opened.RecordClientIdentities(ctx, []querylog.ClientIdentity{
		{Address: "10.0.0.5", MAC: "aa:bb:cc:dd:ee:ff", Source: "neighbor", SeenAt: now},
	}); err != nil {
		t.Fatal(err)
	}
	if err := opened.SetInsightFeedback(ctx, insights.Feedback{
		FindingID: "new-device:10.0.0.9", Action: insights.FeedbackNormal, CreatedAt: now,
	}); err != nil {
		t.Fatal(err)
	}
	if err := opened.MarkAlertsSent(ctx, "destination", []string{"update:1.5.1"}, now); err != nil {
		t.Fatal(err)
	}

	summary, err := opened.InsightDataSummary(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if summary.Addresses != 2 || summary.Hardware != 1 || !summary.Since.Equal(now.Add(-48*time.Hour)) {
		t.Fatalf("summary = %+v", summary)
	}

	if err := opened.DeleteInsightData(ctx, now); err != nil {
		t.Fatal(err)
	}
	for _, table := range []string{"sable_client_seen", "sable_client_domain_seen", "sable_client_identity", "sable_insight_feedback"} {
		if got := countRows(t, opened, table); got != 0 {
			t.Errorf("%s kept %d rows after the delete", table, got)
		}
	}
	if got := countRows(t, opened, "sable_insight_notified"); got != 1 {
		t.Errorf("alert ledger rows = %d, want the one sent alert kept", got)
	}
	if got := countRows(t, opened, "sable_query_log"); got != 2 {
		t.Errorf("query log rows = %d, want both kept", got)
	}
	if summary, err := opened.InsightDataSummary(ctx); err != nil || summary != (InsightData{}) {
		t.Fatalf("summary after delete = %+v, %v", summary, err)
	}
	deletedAt, found, err := opened.InsightDataDeletedAt(ctx)
	if err != nil || !found || !deletedAt.Equal(now) {
		t.Fatalf("deleted at = %s, %t, %v", deletedAt, found, err)
	}
	if filled, err := opened.BackfillClientSightings(ctx); err != nil || filled {
		t.Fatalf("BackfillClientSightings = %t, %v; want no fill after a delete", filled, err)
	}
}
