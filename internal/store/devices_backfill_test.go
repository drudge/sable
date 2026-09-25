package store

import (
	"context"
	"testing"
	"time"

	"github.com/drudge/sable/internal/querylog"
)

func TestBackfillClientSightingsLearnsWhoWasAlreadyHere(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Second)
	day := 24 * time.Hour
	opened := openQueryLogStore(t, []querylog.Event{
		blockingEvent(now.Add(-9*day), "10.0.0.5", "mail.example.com.", querylog.SourceUpstream),
		blockingEvent(now.Add(-2*day), "10.0.0.5", "news.example.", querylog.SourceUpstream),
		blockingEvent(now.Add(-3*day), "10.0.0.9", "cam.example.", querylog.SourceUpstream),
	})
	// Pretend the history predates tracking: no spans, and tracking began now.
	for _, statement := range []string{"DELETE FROM sable_client_seen", "DELETE FROM sable_client_domain_seen"} {
		if _, err := opened.database.ExecContext(ctx, statement); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := opened.database.ExecContext(ctx, "UPDATE sable_metadata SET value = "+opened.placeholder(1)+" WHERE key = "+opened.placeholder(2),
		now.Add(-day).Format(time.RFC3339Nano), clientSeenSinceKey); err != nil {
		t.Fatal(err)
	}

	filled, err := opened.BackfillClientSightings(ctx)
	if err != nil || !filled {
		t.Fatalf("BackfillClientSightings = %t, %v", filled, err)
	}
	seen, err := opened.clientSightings(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if span := seen["10.0.0.5"]; !span.first.Equal(now.Add(-9*day)) || !span.last.Equal(now.Add(-2*day)) {
		t.Fatalf("laptop span = %s to %s", span.first, span.last)
	}
	if span := seen["10.0.0.9"]; !span.first.Equal(now.Add(-3 * day)) {
		t.Fatalf("camera span = %+v", span)
	}
	since, _, err := opened.rollupMarker(ctx, clientSeenSinceKey)
	if err != nil || !since.Equal(now.Add(-9*day)) {
		t.Fatalf("tracking marker = %s, %v; want the oldest query", since, err)
	}
	var pairs int
	if err := opened.database.QueryRowContext(ctx, "SELECT COUNT(*) FROM sable_client_domain_seen").Scan(&pairs); err != nil || pairs != 3 {
		t.Fatalf("client-domain spans = %d, %v", pairs, err)
	}

	// A second run is a no-op.
	if filled, err := opened.BackfillClientSightings(ctx); err != nil || filled {
		t.Fatalf("second BackfillClientSightings = %t, %v", filled, err)
	}
}
