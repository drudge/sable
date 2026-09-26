package app

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"github.com/drudge/sable/internal/config"
	"github.com/drudge/sable/internal/update"
)

const (
	// updateCheckEvery is how often the lead looks for a newer Sable release
	// on its own, so an update alert does not wait for someone to sign in.
	updateCheckEvery = 24 * time.Hour
	// updateCheckPoll is how often the daily check asks whether it is due. A
	// check that is not due costs nothing, and a short poll lets a new lead or
	// a changed setting take hold soon.
	updateCheckPoll = 15 * time.Minute
)

// automaticUpdateChecker is the update manager as the daily check uses it.
type automaticUpdateChecker interface {
	Status() update.Status
	CheckAutomatically(context.Context, bool) (update.Status, error)
}

// updateCheckConfiguration reads this node's update preferences.
type updateCheckConfiguration interface {
	Current() config.Snapshot
}

// dailyUpdateCheck looks for a newer Sable release once a day on the node
// leading the cluster, or on a node alone, so news of a release does not wait
// for a sign-in. It runs only while updates.check_on_login is on, because that
// setting is the operator's consent to ask GitHub. It goes through the same
// cached check as a sign-in, so the two never ask twice within the cache's
// six hours.
type dailyUpdateCheck struct {
	updates       automaticUpdateChecker
	configuration updateCheckConfiguration
	// leading reports whether this node leads the cluster; a node alone leads.
	leading func() bool
	logger  *slog.Logger
	now     func() time.Time
	poll    time.Duration
}

func newDailyUpdateCheck(
	updates automaticUpdateChecker,
	configuration updateCheckConfiguration,
	leading func() bool,
	logger *slog.Logger,
) *dailyUpdateCheck {
	return &dailyUpdateCheck{
		updates:       updates,
		configuration: configuration,
		leading:       leading,
		logger:        logger,
		now:           time.Now,
		poll:          updateCheckPoll,
	}
}

// Run checks whenever a check is due, until ctx ends.
func (check *dailyUpdateCheck) Run(ctx context.Context) {
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
func (check *dailyUpdateCheck) runOnce(ctx context.Context) {
	preferences := check.configuration.Current().Config.Updates
	if !check.due(preferences) {
		return
	}
	_, err := check.updates.CheckAutomatically(ctx, preferences.PreRelease)
	if err != nil && ctx.Err() == nil && !errors.Is(err, update.ErrUpdateInProgress) {
		check.logger.Warn("check for Sable updates", "error", err)
	}
}

// due reports whether this node should look for a release now. A check is
// due a day after the last one, whether that ran here or at a sign-in, and
// straight away on a release channel the operator just switched to. A check
// or installation under way, a restart into an installed release, and a
// cluster rollout holding the updater all come first.
func (check *dailyUpdateCheck) due(preferences config.Updates) bool {
	if !preferences.CheckOnLogin || (check.leading != nil && !check.leading()) {
		return false
	}
	status := check.updates.Status()
	if status.Development || status.Busy() || status.Installed || status.ClusterUpdate {
		return false
	}
	return !status.Checked() || check.now().Sub(status.CheckedAt) >= updateCheckEvery ||
		status.IncludePreRelease != preferences.PreRelease
}
