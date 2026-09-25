package app

import (
	"context"
	"log/slog"
	"time"
)

// backfillClientSightings fills device first-seen history from query logs
// written before Sable tracked it, once per database. It runs as a background
// worker so a large history never delays DNS startup.
func backfillClientSightings(ctx context.Context, backfill func(context.Context) (bool, error), logger *slog.Logger) {
	filled, err := backfill(ctx)
	switch {
	case err != nil && ctx.Err() == nil:
		logger.Warn("fill device history from the query log", "error", err)
	case filled:
		logger.Info("filled device history from the existing query log")
	}
}

// backfillBlockedClientRollups counts the blocked queries each client made
// before per-client blocked rollups existed, once per database, so Insights
// stops recounting that history from the raw log on every visit.
func backfillBlockedClientRollups(ctx context.Context, backfill func(context.Context) (bool, error), logger *slog.Logger) {
	filled, err := backfill(ctx)
	switch {
	case err != nil && ctx.Err() == nil:
		logger.Warn("count blocked queries per client from the query log", "error", err)
	case filled:
		logger.Info("counted blocked queries per client from the existing query log")
	}
}

// rollupCompactionInterval is how often settled query log minutes are summed
// into hours and days.
const rollupCompactionInterval = 5 * time.Minute

// compactQueryLogRollups keeps the hourly and daily query log rollups filled
// until the runtime stops. The first pass sums the history already there, which
// takes a while on a large database; later passes add only what has settled.
func compactQueryLogRollups(ctx context.Context, compact func(context.Context, time.Time) error, every time.Duration, logger *slog.Logger) {
	ticker := time.NewTicker(every)
	defer ticker.Stop()
	for {
		if err := compact(ctx, time.Now()); err != nil && ctx.Err() == nil {
			logger.Warn("sum query log history into hours and days", "error", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}
