package cluster

import (
	"context"
	"encoding/json"
	"slices"
	"sync"
	"time"

	"github.com/drudge/sable/internal/querylog"
)

const (
	// identityShareInterval is how often the lead gathers its recent client
	// identities, and how often each replica is handed them.
	identityShareInterval = time.Minute
	// identityRecentWindow is how far back each regular batch reaches. It
	// spans several intervals, so a replica that missed a few synchronizations
	// still hears every address the lead saw meanwhile.
	identityRecentWindow = 15 * time.Minute
	// identityFullEvery is how often each replica is handed everything the
	// lead knows within the lookback, which also heals a batch that was lost.
	identityFullEvery = 12 * time.Hour
	// identityFullFreshness is how old a gathered full batch may be when it is
	// handed over. An older one would leave a gap before the recent window.
	identityFullFreshness = 3 * identityShareInterval
	// identityGatherTimeout bounds one read of the store.
	identityGatherTimeout = 30 * time.Second
	// maximumSharedIdentities keeps a full batch to a few megabytes, well
	// inside what a replica reads from one synchronization.
	maximumSharedIdentities = 50_000
)

// ClientIdentities reads and records this node's address-to-hardware
// sightings. The lead hands its own to every replica, so a replica that cannot
// see the network's hardware addresses, such as one in a container or on
// another network, still ties addresses to devices. Lookback is how far back a
// full batch reaches.
type ClientIdentities struct {
	Read     func(context.Context, time.Time) ([]querylog.ClientIdentity, error)
	Record   func(context.Context, []querylog.ClientIdentity) error
	Lookback time.Duration
}

// sharedIdentity is one sighting as it crosses to a replica. It keeps its
// source, so a replica reads a UniFi name or type exactly as the lead does.
type sharedIdentity struct {
	Address        string    `json:"address"`
	MAC            string    `json:"mac"`
	Source         string    `json:"source"`
	Hostname       string    `json:"hostname,omitempty"`
	Kind           string    `json:"kind,omitempty"`
	KindConfidence int       `json:"kind_confidence,omitempty"`
	KindSet        bool      `json:"kind_set,omitempty"`
	LastSeen       time.Time `json:"last_seen"`
}

// identitySharer is what the lead gathered to hand to replicas, and when each
// replica was last handed a batch.
type identitySharer struct {
	mu         sync.Mutex
	recent     json.RawMessage
	full       json.RawMessage
	fullAt     time.Time
	wantFull   bool
	sentRecent map[string]time.Time
	sentFull   map[string]time.Time
}

// identityRecorder writes batches a replica received one at a time, apart
// from the synchronization that carried them.
type identityRecorder struct {
	mu sync.Mutex
}

// SetClientIdentities has the lead hand its client identities to every
// replica, and a replica record what it is handed.
func (service *Service) SetClientIdentities(identities ClientIdentities) {
	service.mu.Lock()
	defer service.mu.Unlock()
	service.clientIdentities = identities
}

// gatherClientIdentities gathers the lead's client identities every minute,
// apart from the heartbeat, so reading the store never delays one.
func (service *Service) gatherClientIdentities(ctx context.Context) {
	ticker := time.NewTicker(identityShareInterval)
	defer ticker.Stop()
	for {
		service.gatherClientIdentitiesOnce(ctx, time.Now())
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

func (service *Service) gatherClientIdentitiesOnce(ctx context.Context, now time.Time) {
	service.mu.RLock()
	identities := service.clientIdentities
	leads := service.manifest != nil && service.manifest.PrimaryID == service.nodeID
	service.mu.RUnlock()
	if identities.Read == nil || !leads {
		// What a node gathered while it led is dropped once it steps down, so
		// it never hands over a stale view.
		service.identityShare.reset()
		return
	}
	read := func(since time.Time) (json.RawMessage, bool) {
		readContext, cancel := context.WithTimeout(ctx, identityGatherTimeout)
		defer cancel()
		found, err := identities.Read(readContext, since)
		if err != nil {
			if ctx.Err() == nil && service.logger != nil {
				service.logger.Warn("read client identities to share", "error", err)
			}
			return nil, false
		}
		return encodeSharedIdentities(found), true
	}
	if recent, ok := read(now.Add(-identityRecentWindow)); ok {
		service.identityShare.setRecent(recent)
	}
	if service.identityShare.fullWanted() && identities.Lookback > 0 {
		if full, ok := read(now.Add(-identities.Lookback)); ok {
			service.identityShare.setFull(full, now)
		}
	}
}

// due returns the batch to hand a replica in this synchronization, if one is
// due: a full batch when the replica has never had one or its last is twelve
// hours old, and otherwise the recent batch once a minute. A full batch not
// gathered in the last few minutes is asked for instead of sent.
func (sharer *identitySharer) due(nodeID string, now time.Time) json.RawMessage {
	sharer.mu.Lock()
	defer sharer.mu.Unlock()
	if sharer.sentRecent == nil {
		sharer.sentRecent, sharer.sentFull = make(map[string]time.Time), make(map[string]time.Time)
	}
	if last, sent := sharer.sentFull[nodeID]; !sent || now.Sub(last) >= identityFullEvery {
		if sharer.full != nil && now.Sub(sharer.fullAt) < identityFullFreshness {
			sharer.sentFull[nodeID], sharer.sentRecent[nodeID] = now, now
			return slices.Clone(sharer.full)
		}
		sharer.wantFull = true
	}
	if sharer.recent != nil && now.Sub(sharer.sentRecent[nodeID]) >= identityShareInterval {
		sharer.sentRecent[nodeID] = now
		return slices.Clone(sharer.recent)
	}
	return nil
}

func (sharer *identitySharer) setRecent(encoded json.RawMessage) {
	sharer.mu.Lock()
	defer sharer.mu.Unlock()
	sharer.recent = encoded
}

func (sharer *identitySharer) setFull(encoded json.RawMessage, at time.Time) {
	sharer.mu.Lock()
	defer sharer.mu.Unlock()
	sharer.full, sharer.fullAt, sharer.wantFull = encoded, at, false
}

func (sharer *identitySharer) fullWanted() bool {
	sharer.mu.Lock()
	defer sharer.mu.Unlock()
	return sharer.wantFull
}

// reset forgets what was gathered and sent, so a node that leads again starts
// every replica over with a full batch.
func (sharer *identitySharer) reset() {
	sharer.mu.Lock()
	defer sharer.mu.Unlock()
	sharer.recent, sharer.full, sharer.fullAt, sharer.wantFull = nil, nil, time.Time{}, false
	sharer.sentRecent, sharer.sentFull = nil, nil
}

// forget drops what was sent to a node, so it gets a full batch if it rejoins.
func (sharer *identitySharer) forget(nodeID string) {
	sharer.mu.Lock()
	defer sharer.mu.Unlock()
	delete(sharer.sentRecent, nodeID)
	delete(sharer.sentFull, nodeID)
}

// encodeSharedIdentities encodes sightings for a replica, newest first, and
// leaves out any past the limit, which are the oldest.
func encodeSharedIdentities(found []querylog.ClientIdentity) json.RawMessage {
	shared := make([]sharedIdentity, 0, min(len(found), maximumSharedIdentities))
	for _, identity := range found {
		if len(shared) == maximumSharedIdentities {
			break
		}
		shared = append(shared, sharedIdentity{
			Address: identity.Address, MAC: identity.MAC, Source: identity.Source, Hostname: identity.Hostname,
			Kind: identity.Kind, KindConfidence: identity.KindConfidence, KindSet: identity.KindSet,
			LastSeen: identity.LastSeen.UTC(),
		})
	}
	encoded, err := json.Marshal(shared)
	if err != nil {
		return nil
	}
	return encoded
}

// recordSharedIdentities stores a batch the lead handed over. It runs apart
// from the synchronization, one batch at a time, so a slow write never delays
// a heartbeat. A batch that cannot be read is dropped; the next one covers it.
func (service *Service) recordSharedIdentities(ctx context.Context, encoded json.RawMessage) {
	service.mu.RLock()
	record := service.clientIdentities.Record
	service.mu.RUnlock()
	if record == nil || len(encoded) == 0 {
		return
	}
	var shared []sharedIdentity
	if err := json.Unmarshal(encoded, &shared); err != nil {
		if service.logger != nil {
			service.logger.Warn("read client identities from the cluster primary", "error", err)
		}
		return
	}
	identities := make([]querylog.ClientIdentity, 0, len(shared))
	for _, identity := range shared {
		if identity.Address == "" || identity.MAC == "" || identity.Source == "" || identity.LastSeen.IsZero() {
			continue
		}
		identities = append(identities, querylog.ClientIdentity{
			Address: identity.Address, MAC: identity.MAC, Source: identity.Source, Hostname: identity.Hostname,
			Kind: identity.Kind, KindConfidence: identity.KindConfidence, KindSet: identity.KindSet,
			SeenAt: identity.LastSeen,
		})
	}
	if len(identities) == 0 {
		return
	}
	go func() {
		service.identityRecording.mu.Lock()
		defer service.identityRecording.mu.Unlock()
		if err := record(ctx, identities); err != nil && ctx.Err() == nil && service.logger != nil {
			service.logger.Warn("record client identities from the cluster primary", "error", err)
		}
	}()
}
