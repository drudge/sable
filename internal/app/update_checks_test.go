package app

import (
	"cmp"
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

// fakeScheduledUpdates stands in for the update manager. A check records the
// channel it ran on and when, and stamps the status the way the manager does.
type fakeScheduledUpdates struct {
	mu     sync.Mutex
	status update.Status
	checks []bool
	times  []string
}

func (updates *fakeScheduledUpdates) Status() update.Status {
	updates.mu.Lock()
	defer updates.mu.Unlock()
	return updates.status
}

func (updates *fakeScheduledUpdates) CheckOnSchedule(_ context.Context, includePreRelease bool) (update.Status, error) {
	updates.mu.Lock()
	defer updates.mu.Unlock()
	updates.checks = append(updates.checks, includePreRelease)
	updates.times = append(updates.times, time.Now().UTC().Format("Mon Jan 2 15:04"))
	updates.status.CheckedAt, updates.status.IncludePreRelease = time.Now(), includePreRelease
	return updates.status, nil
}

func (updates *fakeScheduledUpdates) checked() []bool {
	updates.mu.Lock()
	defer updates.mu.Unlock()
	return slices.Clone(updates.checks)
}

func (updates *fakeScheduledUpdates) checkedAt() []string {
	updates.mu.Lock()
	defer updates.mu.Unlock()
	return slices.Clone(updates.times)
}

type updateCheckTestConfiguration struct{ updates config.Updates }

func (configuration updateCheckTestConfiguration) Current() config.Snapshot {
	return config.Snapshot{Config: config.Config{Updates: configuration.updates}}
}

// updateSchedule is consent to check, on the given schedule at 09:00, and on
// Mondays for a weekly one.
func updateSchedule(schedule string) config.Updates {
	return config.Updates{CheckOnLogin: true, CheckSchedule: schedule, CheckAt: "09:00", CheckDay: "monday"}
}

func TestScheduledUpdateCheckAsksOnlyWhenDue(t *testing.T) {
	t.Parallel()
	// Friday, September 25, 2026 at noon.
	now := time.Date(2026, 9, 25, 12, 0, 0, 0, time.UTC)
	checkedAt := func(month time.Month, day, hour, minute int) update.Status {
		return update.Status{CheckedAt: time.Date(2026, month, day, hour, minute, 30, 0, time.UTC)}
	}
	hourly, daily, weekly := updateSchedule(config.UpdateCheckHourly), updateSchedule(config.UpdateCheckDaily), updateSchedule(config.UpdateCheckWeekly)
	fridays := weekly
	fridays.CheckDay = "friday"
	for _, test := range []struct {
		name        string
		preferences config.Updates
		// location is the node's time zone, UTC unless it says otherwise.
		location *time.Location
		replica  bool
		status   update.Status
		// want lists the channel of each check: true includes pre-releases.
		want []bool
	}{
		{name: "a node that never checked asks now", preferences: daily, want: []bool{false}},
		{name: "an hourly check asks an hour on", preferences: hourly, status: checkedAt(9, 25, 10, 59), want: []bool{false}},
		{name: "an hourly check waits out its hour", preferences: hourly, status: checkedAt(9, 25, 11, 1)},
		{name: "a daily check asks once its time passes", preferences: daily, status: checkedAt(9, 24, 9, 0), want: []bool{false}},
		{name: "a daily check that ran this morning waits for tomorrow", preferences: daily, status: checkedAt(9, 25, 9, 0)},
		{name: "a sign-in before the time does not skip the day's check", preferences: daily, status: checkedAt(9, 25, 8, 0), want: []bool{false}},
		{
			name: "a daily check keeps to the node's time zone", preferences: daily, location: time.FixedZone("EDT", -4*60*60),
			status: checkedAt(9, 24, 13, 0),
		},
		{name: "a weekly check waits for its day", preferences: weekly, status: checkedAt(9, 21, 9, 0)},
		{name: "a weekly check asks on its day", preferences: fridays, status: checkedAt(9, 18, 9, 0), want: []bool{false}},
		{name: "a weekly check missed while the node was down asks now", preferences: weekly, status: checkedAt(9, 14, 9, 0), want: []bool{false}},
		{name: "without consent it never asks GitHub", preferences: config.Updates{CheckSchedule: config.UpdateCheckHourly}},
		{name: "a replica leaves checking to the lead", preferences: hourly, replica: true},
		{name: "a development build never asks", preferences: hourly, status: update.Status{Development: true}},
		{name: "a check already running is not doubled", preferences: hourly, status: update.Status{Phase: update.PhaseChecking}},
		{name: "an installed release waits for its restart", preferences: hourly, status: update.Status{Installed: true, CheckedAt: now.Add(-48 * time.Hour)}},
		{name: "a cluster rollout holds the updater", preferences: hourly, status: update.Status{ClusterUpdate: true}},
		{
			name:        "a switch to pre-releases asks on the new channel",
			preferences: config.Updates{CheckOnLogin: true, CheckSchedule: config.UpdateCheckWeekly, CheckAt: "09:00", CheckDay: "monday", PreRelease: true},
			status:      checkedAt(9, 25, 11, 0),
			want:        []bool{true},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			updates := &fakeScheduledUpdates{status: test.status}
			check := newScheduledUpdateCheck(updates, updateCheckTestConfiguration{updates: test.preferences},
				func() bool { return !test.replica }, slog.New(slog.DiscardHandler))
			check.now, check.location = func() time.Time { return now }, cmp.Or(test.location, time.UTC)

			check.runOnce(t.Context())

			if got := updates.checked(); !slices.Equal(got, test.want) {
				t.Fatalf("checks = %v, want %v", got, test.want)
			}
		})
	}
}

// Left running, the lead asks GitHub when its schedule says, and a replica
// never does. The test clock starts at midnight on Saturday, January 1, 2000,
// and a node that has never checked asks at the first poll, a minute in.
func TestScheduledUpdateCheckKeepsToItsSchedule(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name     string
		schedule string
		leading  bool
		run      time.Duration
		want     []string
	}{
		{
			name: "hourly asks every hour", schedule: config.UpdateCheckHourly, leading: true, run: 4 * time.Hour,
			want: []string{"Sat Jan 1 00:01", "Sat Jan 1 01:01", "Sat Jan 1 02:01", "Sat Jan 1 03:01"},
		},
		{
			name: "daily asks at its time each day", schedule: config.UpdateCheckDaily, leading: true, run: 3 * 24 * time.Hour,
			want: []string{"Sat Jan 1 00:01", "Sat Jan 1 09:00", "Sun Jan 2 09:00", "Mon Jan 3 09:00"},
		},
		{
			name: "weekly asks on its day", schedule: config.UpdateCheckWeekly, leading: true, run: 3 * 7 * 24 * time.Hour,
			want: []string{"Sat Jan 1 00:01", "Mon Jan 3 09:00", "Mon Jan 10 09:00", "Mon Jan 17 09:00"},
		},
		{name: "a replica never asks", schedule: config.UpdateCheckHourly, leading: false, run: 4 * time.Hour},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			synctest.Test(t, func(t *testing.T) {
				updates := &fakeScheduledUpdates{}
				check := newScheduledUpdateCheck(updates, updateCheckTestConfiguration{updates: updateSchedule(test.schedule)},
					func() bool { return test.leading }, slog.New(slog.DiscardHandler))
				check.location = time.UTC
				ctx, cancel := context.WithCancel(t.Context())
				stopped := make(chan struct{})
				go func() {
					defer close(stopped)
					check.Run(ctx)
				}()

				time.Sleep(test.run)
				synctest.Wait()
				if got := updates.checkedAt(); !slices.Equal(got, test.want) {
					t.Errorf("checks = %q, want %q", got, test.want)
				}
				cancel()
				<-stopped
			})
		})
	}
}
