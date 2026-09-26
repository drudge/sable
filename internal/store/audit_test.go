package store

import (
	"context"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/drudge/sable/internal/auth"
)

func TestListAuditRecordsSinceFiltersByActionAndTime(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	opened, err := Open(ctx, "sqlite", filepath.Join(t.TempDir(), "sable.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { opened.Close() })
	now := time.Date(2026, 9, 25, 12, 0, 0, 0, time.UTC)
	casey, err := opened.CreateUser(ctx, "casey", "Casey", "casey@example.test", "hashed", []string{"Operator"}, now)
	if err != nil {
		t.Fatal(err)
	}
	for _, event := range []auth.AuditEvent{
		{OccurredAt: now.Add(-3 * time.Hour), Action: auth.ActionLoginFailed, ClientIP: "192.0.2.1", Details: "invalid credentials; username=old"},
		{OccurredAt: now.Add(-40 * time.Minute), Action: auth.ActionLoginFailed, ClientIP: "192.0.2.2", Details: "invalid credentials; username=root"},
		{OccurredAt: now.Add(-30 * time.Minute), Action: "auth.login", UserID: &casey.ID, ClientIP: "192.0.2.3", Details: "session created"},
		{OccurredAt: now.Add(-20 * time.Minute), Action: auth.ActionFederatedDenied, UserID: &casey.ID, ClientIP: "192.0.2.4", Details: "account cannot sign in"},
		{OccurredAt: now.Add(-10 * time.Minute), Action: auth.ActionLoginLocked, ClientIP: "192.0.2.2", Details: "too many failed sign-ins; username=root"},
	} {
		if err := opened.RecordAuditEvent(ctx, event); err != nil {
			t.Fatal(err)
		}
	}

	for _, testCase := range []struct {
		name    string
		actions []string
		since   time.Time
		limit   int
		// want lists the client addresses of the records returned, which
		// tell them apart, in the order they come back.
		want []string
	}{
		{
			name: "only the actions asked for, newest first", actions: auth.FailedSignInActions(),
			since: now.Add(-time.Hour), limit: 100, want: []string{"192.0.2.2", "192.0.2.4", "192.0.2.2"},
		},
		{
			name: "nothing before since", actions: auth.FailedSignInActions(),
			since: now.Add(-15 * time.Minute), limit: 100, want: []string{"192.0.2.2"},
		},
		{
			name: "a limit keeps the newest", actions: auth.FailedSignInActions(),
			since: now.Add(-24 * time.Hour), limit: 2, want: []string{"192.0.2.2", "192.0.2.4"},
		},
		{
			name: "one action", actions: []string{auth.ActionLoginFailed},
			since: now.Add(-24 * time.Hour), limit: 100, want: []string{"192.0.2.2", "192.0.2.1"},
		},
		{name: "no actions", since: now.Add(-24 * time.Hour), limit: 100, want: []string{}},
		{name: "no room", actions: auth.FailedSignInActions(), since: now.Add(-24 * time.Hour), want: []string{}},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()
			records, err := opened.ListAuditRecordsSince(ctx, testCase.actions, testCase.since, testCase.limit)
			if err != nil {
				t.Fatal(err)
			}
			addresses := make([]string, 0, len(records))
			for _, record := range records {
				addresses = append(addresses, record.ClientIP)
			}
			if !slices.Equal(addresses, testCase.want) {
				t.Fatalf("records = %+v, want addresses %v", records, testCase.want)
			}
		})
	}

	records, err := opened.ListAuditRecordsSince(ctx, auth.FailedSignInActions(), now.Add(-time.Hour), 100)
	if err != nil {
		t.Fatal(err)
	}
	// A record that names an account carries its username; one that names none
	// carries no username at all, rather than passing for the system.
	if records[1].Username != "casey" || records[0].Username != "" || records[2].Username != "" {
		t.Fatalf("usernames = %q, %q, %q, want \"\", casey, \"\"", records[0].Username, records[1].Username, records[2].Username)
	}
	if got := records[0]; got.Action != auth.ActionLoginLocked || got.Details != "too many failed sign-ins; username=root" ||
		!got.OccurredAt.Equal(now.Add(-10*time.Minute)) {
		t.Fatalf("newest record = %+v", got)
	}
}
