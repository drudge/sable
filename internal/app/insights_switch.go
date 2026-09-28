package app

import (
	"context"
	"fmt"
	"time"
)

// clientTracker is the store's switch for recording which clients were seen
// and what hardware they are.
type clientTracker interface {
	StopClientTracking(context.Context) error
	ResumeClientTracking(context.Context, time.Time) error
}

// switchInsights follows the Insights switch into the store. Turning it off
// stops every sighting and identity from being kept; turning it back on
// starts fresh from now, with nothing filled in from the query log.
func switchInsights(ctx context.Context, tracker clientTracker, was, enabled bool, now time.Time) error {
	switch {
	case !enabled:
		if err := tracker.StopClientTracking(ctx); err != nil {
			return fmt.Errorf("stop Insights tracking: %w", err)
		}
	case !was:
		if err := tracker.ResumeClientTracking(ctx, now); err != nil {
			return fmt.Errorf("resume Insights tracking: %w", err)
		}
	}
	return nil
}
