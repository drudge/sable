package cluster

import "time"

// rolloutLagAllowance is how long a node may take to apply a generation the
// primary published before a rollout waits on it. Replicas pull once a
// second, so under steady writes a replica is usually a generation behind at
// any instant, and requiring none behind would stall a rollout for as long
// as the writes last. A node still missing what the primary published this
// long ago is not keeping up.
const rolloutLagAllowance = heartbeatFreshness

// primaryRestartLagAllowance bounds how far peers may trail before the
// primary itself restarts. If the primary does not come back, a recovery
// promotion keeps only what a replica had applied, and the documented loss
// window is about the last second, so peers must hold everything the primary
// published two sync intervals ago.
const primaryRestartLagAllowance = 2 * syncInterval

// generationSample is the primary's generation as of a moment.
type generationSample struct {
	at         time.Time
	generation uint64
}

// generationHistory remembers when the primary reached its recent
// generations, so a rollout can tell a replica that is keeping up from one
// that has fallen behind.
type generationHistory struct {
	samples []generationSample
}

// record notes the generation the primary holds at now, and drops samples
// settled can no longer need.
func (history *generationHistory) record(now time.Time, generation uint64) {
	if count := len(history.samples); count == 0 || history.samples[count-1].generation != generation {
		history.samples = append(history.samples, generationSample{at: now, generation: generation})
	}
	cutoff, keep := now.Add(-rolloutLagAllowance), 0
	for index, sample := range history.samples {
		if !sample.at.After(cutoff) {
			keep = index
		}
	}
	history.samples = history.samples[keep:]
}

// settled returns the newest generation the primary had reached allowance
// before now, for an allowance up to rolloutLagAllowance. With no sample that
// old it returns current, so a node must have applied everything.
func (history *generationHistory) settled(now time.Time, current uint64, allowance time.Duration) uint64 {
	cutoff, settled := now.Add(-allowance), current
	for _, sample := range history.samples {
		if sample.at.After(cutoff) {
			break
		}
		settled = sample.generation
	}
	return min(settled, current)
}

// rolloutNodeFollowing reports whether a node is online and applying the
// primary's state, however far it trails.
func rolloutNodeFollowing(node Node) bool {
	return node.State == StateOnline && (node.SyncState == SyncCurrent || node.SyncState == SyncBehind)
}

// rolloutNodeReadyLocked reports whether a node is online and keeping up:
// it has applied every generation the primary published at least
// rolloutLagAllowance ago. The caller holds service.updates.mu.
func (service *Service) rolloutNodeReadyLocked(state State, node Node) bool {
	return service.rolloutNodeWithinLocked(state, node, rolloutLagAllowance)
}

// rolloutPeersReadyLocked reports whether every node other than the one
// about to restart is keeping up, holding peers to the tighter
// primaryRestartLagAllowance when that node is the primary. The caller holds
// service.updates.mu.
func (service *Service) rolloutPeersReadyLocked(state State, restarting string) bool {
	allowance := rolloutLagAllowance
	if restarting == state.PrimaryID {
		allowance = primaryRestartLagAllowance
	}
	for _, peer := range state.Nodes {
		if peer.ID != restarting && !service.rolloutNodeWithinLocked(state, peer, allowance) {
			return false
		}
	}
	return true
}

func (service *Service) rolloutNodeWithinLocked(state State, node Node, allowance time.Duration) bool {
	settled := service.updates.generations.settled(service.clock(), state.Generation, allowance)
	return rolloutNodeFollowing(node) && node.AppliedGeneration >= settled
}
