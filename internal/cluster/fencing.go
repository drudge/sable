package cluster

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"slices"
	"time"
)

const (
	// peerProbeInterval is how often a primary asks the other members which
	// primary they follow, so a stale primary learns it was replaced.
	peerProbeInterval = 10 * time.Second
	// peerProbeTimeout bounds one member's answer, so an offline member
	// cannot hold up the rest of a round.
	peerProbeTimeout = 5 * time.Second
	// primaryClaimFreshness is how long another primary's claim counts as a
	// conflict after it was last seen.
	primaryClaimFreshness = 3 * peerProbeInterval
)

// PrimaryClaim is what a probing primary says about its own term.
type PrimaryClaim struct {
	Term uint64 `json:"term"`
}

// PrimaryConflict is another node that accepts changes in this primary's
// term. Promoting this node again resolves it in this node's favor.
type PrimaryConflict struct {
	NodeID     string    `json:"node_id"`
	Name       string    `json:"name"`
	Term       uint64    `json:"term"`
	Generation uint64    `json:"generation"`
	ObservedAt time.Time `json:"observed_at"`
}

type primaryClaim struct {
	term       uint64
	generation uint64
	received   time.Time
}

// manifestOlder reports whether candidate is older than active: from an
// earlier primary term, or from the same term at a lower generation.
func manifestOlder(candidate, active *manifest) bool {
	if candidate.Term != active.Term {
		return candidate.Term < active.Term
	}
	return candidate.Generation < active.Generation
}

// probePeers is the primary's side of fencing. Every round it asks each
// other member for its manifest. A newer term anywhere makes this node step
// down to it; another primary in this node's term is a conflict to show.
func (service *Service) probePeers(ctx context.Context) {
	ticker := time.NewTicker(peerProbeInterval)
	defer ticker.Stop()
	for {
		service.probePeersOnce(ctx)
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		case <-service.probeNow:
		}
	}
}

func (service *Service) probePeersOnce(ctx context.Context) {
	service.mu.RLock()
	if service.manifest == nil || service.manifest.PrimaryID != service.nodeID {
		service.mu.RUnlock()
		return
	}
	targets := slices.DeleteFunc(slices.Clone(service.manifest.Nodes), func(node member) bool {
		return node.ID == service.nodeID || node.AdvertiseURL == ""
	})
	service.mu.RUnlock()
	for _, target := range targets {
		configuration, err := service.probePeer(ctx, target)
		if err != nil {
			if service.logger != nil && ctx.Err() == nil {
				service.logger.Debug("cluster primary probe failed", "node_id", target.ID, "error", err)
			}
			continue
		}
		if service.considerPeerManifest(ctx, target, configuration) {
			return
		}
	}
}

// probePeer sends target a signed heartbeat that claims this node's term and
// returns the manifest target holds.
func (service *Service) probePeer(ctx context.Context, target member) (SyncConfiguration, error) {
	service.mu.RLock()
	if service.manifest == nil || service.manifest.PrimaryID != service.nodeID {
		service.mu.RUnlock()
		return SyncConfiguration{}, ErrNotPrimary
	}
	heartbeat, _, _ := service.primaryHeartbeatLocked(nil, member{}, false)
	heartbeat.Primary = &PrimaryClaim{Term: service.manifest.Term}
	statusKey := service.manifest.StatusKey
	service.mu.RUnlock()
	probeContext, cancel := context.WithTimeout(ctx, peerProbeTimeout)
	defer cancel()
	response, err := service.sendPrimaryHeartbeat(probeContext, target, target.AdvertiseURL, statusKey, heartbeat)
	if err != nil {
		return SyncConfiguration{}, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		// A 410 says the member does not list this node, but not from which
		// generation, so it is no reason to give up the cluster.
		return SyncConfiguration{}, fmt.Errorf("cluster member refused primary probe: %s", response.Status)
	}
	var configuration SyncConfiguration
	if err := json.NewDecoder(io.LimitReader(response.Body, maximumSyncBytes)).Decode(&configuration); err != nil {
		return SyncConfiguration{}, fmt.Errorf("decode cluster probe response: %w", err)
	}
	if err := validateSyncConfiguration(configuration); err != nil {
		return SyncConfiguration{}, err
	}
	return configuration, nil
}

// considerPeerManifest acts on the manifest a member returned and reports
// whether this node stopped being the primary.
func (service *Service) considerPeerManifest(ctx context.Context, target member, configuration SyncConfiguration) bool {
	candidate := manifestFromJoinConfiguration(JoinConfiguration(configuration))
	service.mu.Lock()
	active := service.manifest
	if active == nil || active.PrimaryID != service.nodeID || candidate.ClusterID != active.ClusterID {
		service.mu.Unlock()
		return false
	}
	if candidate.Term == active.Term {
		// Only a member's claim about itself counts. A lagging replica may
		// still name a primary from earlier in a term that predates terms.
		if candidate.PrimaryID == target.ID {
			service.primaryClaims[target.ID] = primaryClaim{term: candidate.Term, generation: candidate.Generation, received: service.clock()}
		}
		service.mu.Unlock()
		return false
	}
	activeTerm, activeGeneration := active.Term, active.Generation
	service.mu.Unlock()
	if candidate.Term < activeTerm {
		return false
	}
	return service.stepDown(ctx, target, configuration, activeTerm, activeGeneration)
}

// stepDown makes this stale primary follow the newer term a member reported.
// The member checked that it lists this node before answering, so the
// manifest always keeps this node as a replica. Its own state is replaced by
// the newer primary's, so changes it accepted after it was replaced are lost,
// as they would be after any failover.
func (service *Service) stepDown(ctx context.Context, target member, configuration SyncConfiguration, staleTerm, staleGeneration uint64) bool {
	if err := service.adoptSyncConfiguration(ctx, target, configuration); err != nil {
		if service.logger != nil {
			service.logger.Error("stale cluster primary could not step down", "primary_id", configuration.PrimaryID, "error", err)
		}
		return false
	}
	service.mu.Lock()
	clear(service.primaryClaims)
	clear(service.reportedAlerts)
	clear(service.reportedLookups)
	service.mu.Unlock()
	if service.logger != nil {
		service.logger.Warn("stale cluster primary stepped down",
			"primary_id", configuration.PrimaryID,
			"term", configuration.Term,
			"generation", configuration.Generation,
			"local_term", staleTerm,
			"local_generation", staleGeneration,
		)
	}
	return true
}

// answerPrimaryProbeLocked answers another primary's probe with this node's
// manifest. It notes the claim, to spot two primaries in one term, and never
// records the sender's identity or reports: those would publish a new
// generation on the strength of a node that may itself be stale.
func (service *Service) answerPrimaryProbeLocked(heartbeat Heartbeat, now time.Time) (SyncConfiguration, error) {
	if previous, seen := service.probeSeen[heartbeat.NodeID]; seen && !heartbeat.SentAt.After(previous) {
		return SyncConfiguration{}, errors.New("synchronization heartbeat is stale or replayed")
	}
	service.probeSeen[heartbeat.NodeID] = heartbeat.SentAt
	service.primaryClaims[heartbeat.NodeID] = primaryClaim{term: heartbeat.Primary.Term, generation: heartbeat.AppliedGeneration, received: now}
	if service.manifest.PrimaryID == service.nodeID && heartbeat.Primary.Term > service.manifest.Term {
		// A newer primary exists. Ask it for its manifest now rather than at
		// the next round.
		select {
		case service.probeNow <- struct{}{}:
		default:
		}
	}
	return service.syncConfigurationLocked(heartbeat.NodeID, heartbeat.StateDigest, now, false)
}

// primaryConflictLocked returns the node that most recently claimed the
// primary role in this primary's own term, if one did lately.
func (service *Service) primaryConflictLocked(now time.Time) (PrimaryConflict, bool) {
	if service.manifest == nil || service.manifest.PrimaryID != service.nodeID {
		return PrimaryConflict{}, false
	}
	var conflict PrimaryConflict
	found := false
	for nodeID, claim := range service.primaryClaims {
		if nodeID == service.nodeID || claim.term != service.manifest.Term || now.Sub(claim.received) > primaryClaimFreshness {
			continue
		}
		if found && !claim.received.After(conflict.ObservedAt) {
			continue
		}
		name := nodeID
		if node, ok := manifestMember(service.manifest, nodeID); ok {
			name = node.Name
		}
		conflict = PrimaryConflict{NodeID: nodeID, Name: name, Term: claim.term, Generation: claim.generation, ObservedAt: claim.received}
		found = true
	}
	return conflict, found
}

// applyPrimaryConflict marks this node and the other primary as conflicting
// in a snapshot.
func applyPrimaryConflict(state *State, conflict PrimaryConflict) {
	state.Conflict = &conflict
	for index := range state.Nodes {
		node := &state.Nodes[index]
		switch node.ID {
		case state.NodeID:
			if node.SyncState == SyncCurrent {
				state.Synchronized--
			}
			node.SyncState = SyncConflict
		case conflict.NodeID:
			if node.State != StateOnline {
				state.Connected++
			} else if node.SyncState == SyncCurrent {
				state.Synchronized--
			}
			node.Role = RolePrimary
			node.State = StateOnline
			node.SyncState = SyncConflict
			node.LastContact = conflict.ObservedAt
			node.AppliedGeneration = conflict.Generation
			node.Lag = 0
		}
	}
}
