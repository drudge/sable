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

// backfillAppRollups counts the queries each client made to each app before
// the app rollups existed, once per database, so the Insights Apps tab covers
// the whole retained history from the first upgrade.
func backfillAppRollups(ctx context.Context, backfill func(context.Context) (bool, error), logger *slog.Logger) {
	filled, err := backfill(ctx)
	switch {
	case err != nil && ctx.Err() == nil:
		logger.Warn("count app queries from the query log", "error", err)
	case filled:
		logger.Info("counted app queries from the existing query log")
	}
}

// queryLogSearchInterval is how often the query log search index drops the
// entries of pruned rows.
const queryLogSearchInterval = 15 * time.Minute

// maintainQueryLogSearch keeps the query log search index whole until the
// runtime stops. The first pass indexes any log written without it, such as
// the log from before an upgrade, which takes a while on a large database;
// searches read the whole log until it is done. Later passes clear entries
// for rows that retention pruned.
func maintainQueryLogSearch(ctx context.Context, build func(context.Context) (bool, error), every time.Duration, logger *slog.Logger) {
	ticker := time.NewTicker(every)
	defer ticker.Stop()
	for {
		if ctx.Err() != nil {
			return
		}
		built, err := build(ctx)
		switch {
		case err != nil && ctx.Err() == nil:
			logger.Warn("index the query log for search", "error", err)
		case built:
			logger.Info("indexed the query log for search")
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
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
		// A tick and the shutdown can arrive together, and select picks
		// between them at random, so check again before starting a pass.
		if ctx.Err() != nil {
			return
		}
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
