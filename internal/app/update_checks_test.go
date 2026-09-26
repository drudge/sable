package app

import (
	"context"
	"log/slog"
	"slices"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/drudge/sable/internal/config"
	"github.com/drudge/sable/internal/update"
)

// fakeAutomaticUpdates stands in for the update manager. A check records the
// channel it ran on and stamps the status the way the manager does.
type fakeAutomaticUpdates struct {
	mu     sync.Mutex
	status update.Status
	checks []bool
}

func (updates *fakeAutomaticUpdates) Status() update.Status {
	updates.mu.Lock()
	defer updates.mu.Unlock()
	return updates.status
}

func (updates *fakeAutomaticUpdates) CheckAutomatically(_ context.Context, includePreRelease bool) (update.Status, error) {
	updates.mu.Lock()
	defer updates.mu.Unlock()
	updates.checks = append(updates.checks, includePreRelease)
	updates.status.CheckedAt, updates.status.IncludePreRelease = time.Now(), includePreRelease
	return updates.status, nil
}

func (updates *fakeAutomaticUpdates) checked() []bool {
	updates.mu.Lock()
	defer updates.mu.Unlock()
	return slices.Clone(updates.checks)
}

type updateCheckTestConfiguration struct{ updates config.Updates }

func (configuration updateCheckTestConfiguration) Current() config.Snapshot {
	return config.Snapshot{Config: config.Config{Updates: configuration.updates}}
}

func TestDailyUpdateCheckAsksOnlyWhenDue(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 9, 25, 12, 0, 0, 0, time.UTC)
	consent := config.Updates{CheckOnLogin: true}
	for _, test := range []struct {
		name        string
		preferences config.Updates
		replica     bool
		status      update.Status
		// want lists the channel of each check: true includes pre-releases.
		want []bool
	}{
		{name: "a node that never checked asks now", preferences: consent, want: []bool{false}},
		{name: "a check a day ago is due again", preferences: consent, status: update.Status{CheckedAt: now.Add(-updateCheckEvery)}, want: []bool{false}},
		{name: "a sign-in check this morning is fresh enough", preferences: consent, status: update.Status{CheckedAt: now.Add(-5 * time.Hour)}},
		{name: "a check just under a day ago waits", preferences: consent, status: update.Status{CheckedAt: now.Add(-updateCheckEvery + time.Minute)}},
		{name: "without consent it never asks GitHub", preferences: config.Updates{}},
		{name: "a replica leaves checking to the lead", preferences: consent, replica: true},
		{name: "a development build never asks", preferences: consent, status: update.Status{Development: true}},
		{name: "a check already running is not doubled", preferences: consent, status: update.Status{Phase: update.PhaseChecking}},
		{name: "an installed release waits for its restart", preferences: consent, status: update.Status{Installed: true, CheckedAt: now.Add(-2 * updateCheckEvery)}},
		{name: "a cluster rollout holds the updater", preferences: consent, status: update.Status{ClusterUpdate: true}},
		{
			name:        "a switch to pre-releases asks on the new channel",
			preferences: config.Updates{CheckOnLogin: true, PreRelease: true},
			status:      update.Status{CheckedAt: now.Add(-time.Hour)},
			want:        []bool{true},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			updates := &fakeAutomaticUpdates{status: test.status}
			check := newDailyUpdateCheck(updates, updateCheckTestConfiguration{updates: test.preferences},
				func() bool { return !test.replica }, slog.New(slog.DiscardHandler))
			check.now = func() time.Time { return now }

			check.runOnce(t.Context())

			if got := updates.checked(); !slices.Equal(got, test.want) {
				t.Fatalf("checks = %v, want %v", got, test.want)
			}
		})
	}
}

// Left running for three days, the lead asks GitHub once a day, and a replica
// never does.
func TestDailyUpdateCheckAsksOncePerDayWhileRunning(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name    string
		leading bool
		want    int
	}{
		{name: "the lead asks once a day", leading: true, want: 3},
		{name: "a replica never asks", leading: false, want: 0},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			synctest.Test(t, func(t *testing.T) {
				updates := &fakeAutomaticUpdates{}
				check := newDailyUpdateCheck(updates, updateCheckTestConfiguration{updates: config.Updates{CheckOnLogin: true}},
					func() bool { return test.leading }, slog.New(slog.DiscardHandler))
				ctx, cancel := context.WithCancel(t.Context())
				stopped := make(chan struct{})
				go func() {
					defer close(stopped)
					check.Run(ctx)
				}()

				time.Sleep(3 * updateCheckEvery)
				synctest.Wait()
				if got := len(updates.checked()); got != test.want {
					t.Errorf("checks in three days = %d, want %d", got, test.want)
				}
				cancel()
				<-stopped
			})
		})
	}
}
