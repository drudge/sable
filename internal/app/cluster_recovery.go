package app

import (
	"context"

	"github.com/drudge/sable/internal/zone"
)

// recoverySerialGap is how far a recovery promotion moves every SOA serial
// Sable issues. The failed primary may have handed out serials for changes no
// replica received, about a second of changes. Jumping past them keeps
// secondaries from seeing a serial reused for different content, and keeps
// the former primary's serial from going backward when it steps down.
const recoverySerialGap = 100

// PrepareRecovery advances the serial of every zone whose serial Sable owns
// before this replica takes over for an unavailable primary.
func (replicator *clusterStateReplicator) PrepareRecovery(ctx context.Context) error {
	return replicator.zones.UpdateZones(ctx, func(candidate *[]zone.Zone) error {
		for index := range *candidate {
			if zone.OwnsSerial((*candidate)[index]) {
				zone.AdvanceSerialBy(&(*candidate)[index], recoverySerialGap)
			}
		}
		return nil
	})
}
