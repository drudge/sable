package app

import (
	"context"
	"log/slog"
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
