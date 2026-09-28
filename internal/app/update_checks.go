package app

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"github.com/drudge/sable/internal/config"
	"github.com/drudge/sable/internal/update"
)

// updateCheckPoll is how often the scheduled check asks whether it is due. A
// check that is not due costs nothing, and a short poll keeps a check close to
// its time and lets a new lead or a changed setting take hold soon.
const updateCheckPoll = time.Minute

// scheduledUpdateChecker is the update manager as the scheduled check uses it.
type scheduledUpdateChecker interface {
	Status() update.Status
	CheckOnSchedule(context.Context, bool) (update.Status, error)
}

// updateCheckConfiguration reads this node's update preferences.
type updateCheckConfiguration interface {
	Current() config.Snapshot
}

// scheduledUpdateCheck looks for a newer Sable release hourly, daily, or
// weekly, as updates.check_schedule says, on the node leading the cluster, or
// on a node alone, so news of a release does not wait for a sign-in. It runs
// only while updates.check_on_login is on, because that setting is the
// operator's consent to ask GitHub.
type scheduledUpdateCheck struct {
	updates       scheduledUpdateChecker
	configuration updateCheckConfiguration
	// leading reports whether this node leads the cluster; a node alone leads.
	leading func() bool
	logger  *slog.Logger
	now     func() time.Time
	// location is the time zone daily and weekly checks keep to: this node's
	// local time, as for scheduled backups.
	location *time.Location
	poll     time.Duration
}

func newScheduledUpdateCheck(
	updates scheduledUpdateChecker,
	configuration updateCheckConfiguration,
	leading func() bool,
	logger *slog.Logger,
) *scheduledUpdateCheck {
	return &scheduledUpdateCheck{
		updates:       updates,
		configuration: configuration,
		leading:       leading,
		logger:        logger,
		now:           time.Now,
		location:      time.Local,
		poll:          updateCheckPoll,
	}
}

// Run checks whenever a check is due, until ctx ends.
func (check *scheduledUpdateCheck) Run(ctx context.Context) {
	ticker := time.NewTicker(check.poll)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			check.runOnce(ctx)
		}
	}
}

// runOnce asks GitHub for the newest release when a check is due.
func (check *scheduledUpdateCheck) runOnce(ctx context.Context) {
	preferences := check.configuration.Current().Config.Updates
	if !check.due(preferences) {
		return
	}
	_, err := check.updates.CheckOnSchedule(ctx, preferences.PreRelease)
	if err != nil && ctx.Err() == nil && !errors.Is(err, update.ErrUpdateInProgress) {
		check.logger.Warn("check for Sable updates", "error", err)
	}
}

// due reports whether this node should look for a release now. A check is
// due at the first scheduled time after the last one, whether that ran here
// or at a sign-in, and straight away on a node that has never found a release
// or on a release channel the operator just switched to. A check or
// installation under way, a restart into an installed release, and a cluster
// rollout holding the updater all come first.
func (check *scheduledUpdateCheck) due(preferences config.Updates) bool {
	if !preferences.CheckOnLogin || (check.leading != nil && !check.leading()) {
		return false
	}
	status := check.updates.Status()
	if status.Development || status.Busy() || status.Installed || status.ClusterUpdate {
		return false
	}
	return !status.Checked() || status.IncludePreRelease != preferences.PreRelease ||
		!check.now().Before(nextUpdateCheck(preferences, status.CheckedAt.In(check.location)))
}

// nextUpdateCheck is when the scheduled check after last falls due. An hourly
// check comes an hour after the last one. A daily one comes at check_at, and a
// weekly one at check_at on check_day, both in last's time zone.
func nextUpdateCheck(preferences config.Updates, last time.Time) time.Time {
	if preferences.CheckSchedule == config.UpdateCheckHourly {
		return last.Add(time.Hour)
	}
	clock, err := time.Parse("15:04", preferences.CheckAt)
	if err != nil {
		// Saved settings always have a time. Without one, check a day on.
		return last.AddDate(0, 0, 1)
	}
	days, step := 0, 1
	if preferences.CheckSchedule == config.UpdateCheckWeekly {
		days, step = (int(preferences.CheckWeekday())-int(last.Weekday())+7)%7, 7
	}
	at := func(day int) time.Time {
		return time.Date(last.Year(), last.Month(), last.Day()+day, clock.Hour(), clock.Minute(), 0, 0, last.Location())
	}
	if next := at(days); next.After(last) {
		return next
	}
	return at(days + step)
}
