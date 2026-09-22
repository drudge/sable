package app

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"github.com/drudge/sable/internal/neighbors"
	"github.com/drudge/sable/internal/querylog"
)

const (
	// neighborIdentitySource labels identities read from the host's neighbor
	// table.
	neighborIdentitySource = "neighbor"
	// neighborSampleInterval is how often the neighbor table is read. Kernel
	// entries age out after a few minutes of silence, so a minute catches
	// every active device without measurable cost.
	neighborSampleInterval = time.Minute
)

// runNeighborSampler records the host's IP-to-hardware mappings once a minute.
// It never touches the DNS request path: it reads a kernel table and writes a
// small batch through the same store the query log uses.
func runNeighborSampler(
	ctx context.Context,
	read func() ([]neighbors.Entry, error),
	record func(context.Context, []querylog.ClientIdentity) error,
	logger *slog.Logger,
) {
	ticker := time.NewTicker(neighborSampleInterval)
	defer ticker.Stop()
	reported := false
	for {
		if err := sampleNeighbors(ctx, read, record, time.Now()); err != nil {
			if errors.Is(err, neighbors.ErrUnsupported) {
				logger.Info("neighbor table is not available; devices are named from UniFi, client names, and reverse DNS only")
				return
			}
			// A host with no access to its neighbor table fails the same way
			// every minute, so the first failure is enough to explain it.
			if !reported {
				logger.Warn("read neighbor table", "error", err)
				reported = true
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

func sampleNeighbors(
	ctx context.Context,
	read func() ([]neighbors.Entry, error),
	record func(context.Context, []querylog.ClientIdentity) error,
	now time.Time,
) error {
	entries, err := read()
	if err != nil {
		return err
	}
	identities := make([]querylog.ClientIdentity, 0, len(entries))
	for _, entry := range entries {
		identities = append(identities, querylog.ClientIdentity{
			Address: entry.Address.String(), MAC: entry.MAC.String(),
			Source: neighborIdentitySource, SeenAt: now,
		})
	}
	return record(ctx, identities)
}
