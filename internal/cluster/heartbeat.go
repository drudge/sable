package cluster

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"reflect"
	"slices"
	"strings"
	"time"
)

const (
	syncPath           = "/api/v1/cluster/sync"
	syncInterval       = time.Second
	heartbeatFreshness = 5 * time.Second
	heartbeatClockSkew = 30 * time.Second
	maximumSyncBytes   = 64 << 20
)

type Heartbeat struct {
	NodeID            string    `json:"node_id"`
	Name              string    `json:"name,omitempty"`
	AdvertiseURL      string    `json:"advertise_url,omitempty"`
	TrustAnchor       string    `json:"trust_anchor,omitempty"`
	Version           string    `json:"version,omitempty"`
	Addresses         []string  `json:"addresses,omitempty"`
	AppliedGeneration uint64    `json:"applied_generation"`
	StateDigest       string    `json:"state_digest,omitempty"`
	UpSince           time.Time `json:"up_since"`
	SentAt            time.Time `json:"sent_at"`
}

type SyncConfiguration struct {
	FormatVersion int       `json:"format_version"`
	ClusterID     string    `json:"cluster_id"`
	ClusterDomain string    `json:"cluster_domain"`
	Generation    uint64    `json:"generation"`
	UpdatedAt     time.Time `json:"updated_at"`
	PrimaryID     string    `json:"primary_id"`
	StatusKey     string    `json:"status_key"`
	StateDigest   string    `json:"state_digest,omitempty"`
	StateSnapshot []byte    `json:"state_snapshot,omitempty"`
	Members       []Member  `json:"members"`
}

type nodeTelemetry struct {
	heartbeat Heartbeat
	received  time.Time
}

func (service *Service) StartMonitoring(ctx context.Context) {
	service.monitorOnce.Do(func() {
		monitorContext, cancel := context.WithCancel(ctx)
		done := make(chan struct{})
		service.monitorLifecycleMu.Lock()
		service.monitorCancel = cancel
		service.monitorDone = done
		service.monitorLifecycleMu.Unlock()
		go func() {
			defer close(done)
			service.monitorPrimary(monitorContext)
		}()
	})
}

// Synchronize records member health and returns this node's current manifest.
// A recently demoted primary continues serving this signed convergence
// endpoint so replicas can learn a planned primary handoff without a push
// connection from the former primary.
func (service *Service) Synchronize(ctx context.Context, heartbeat Heartbeat, signature string) (SyncConfiguration, error) {
	if err := service.refreshPrimaryState(ctx); err != nil && !errors.Is(err, ErrNotInitialized) {
		return SyncConfiguration{}, err
	}
	service.mu.Lock()
	defer service.mu.Unlock()
	now := time.Now()
	if heartbeat.SentAt.Before(now.Add(-heartbeatClockSkew)) || heartbeat.SentAt.After(now.Add(heartbeatClockSkew)) {
		return SyncConfiguration{}, errors.New("synchronization timestamp is outside the accepted clock window")
	}
	if service.heartbeatRevoked(heartbeat, signature) {
		return SyncConfiguration{}, ErrNodeRemoved
	}
	if service.manifest == nil {
		return SyncConfiguration{}, ErrNotInitialized
	}
	if heartbeat.NodeID == service.nodeID {
		return SyncConfiguration{}, errors.New("synchronization node must be remote")
	}
	if !validHeartbeatSignature(service.manifest.StatusKey, heartbeat, signature) {
		return SyncConfiguration{}, errors.New("synchronization signature is invalid")
	}
	memberIndex := slices.IndexFunc(service.manifest.Nodes, func(node member) bool { return node.ID == heartbeat.NodeID })
	if memberIndex < 0 {
		return SyncConfiguration{}, ErrNodeRemoved
	}
	localIsPrimary := service.manifest.PrimaryID == service.nodeID
	if heartbeat.AdvertiseURL != "" && localIsPrimary {
		name, advertiseURL, trustAnchor, version, addresses, err := validateHeartbeatIdentity(heartbeat)
		if err != nil {
			return SyncConfiguration{}, err
		}
		for _, node := range service.manifest.Nodes {
			if node.ID != heartbeat.NodeID && node.AdvertiseURL == advertiseURL {
				return SyncConfiguration{}, errors.New("another cluster member uses this advertised URL")
			}
		}
		current := service.manifest.Nodes[memberIndex]
		if current.Name != name || current.AdvertiseURL != advertiseURL || current.TrustAnchor != trustAnchor || current.Version != version || !slices.Equal(current.Addresses, addresses) {
			candidate := cloneManifest(service.manifest)
			candidate.Generation++
			candidate.UpdatedAt = now
			candidate.Nodes[memberIndex].Name = name
			candidate.Nodes[memberIndex].AdvertiseURL = advertiseURL
			candidate.Nodes[memberIndex].TrustAnchor = trustAnchor
			candidate.Nodes[memberIndex].Version = version
			candidate.Nodes[memberIndex].Addresses = addresses
			if err := writeManifest(service.directory, candidate); err != nil {
				return SyncConfiguration{}, err
			}
			service.manifest = candidate
			service.clientsMu.Lock()
			clear(service.memberClients)
			service.clientsMu.Unlock()
		}
	}
	previous, previouslyObserved := service.telemetry[heartbeat.NodeID]
	if previouslyObserved && !heartbeat.SentAt.After(previous.heartbeat.SentAt) {
		return SyncConfiguration{}, errors.New("synchronization heartbeat is stale or replayed")
	}
	service.telemetry[heartbeat.NodeID] = nodeTelemetry{heartbeat: heartbeat, received: now}
	if service.logger != nil && (!previouslyObserved || previous.heartbeat.AppliedGeneration != heartbeat.AppliedGeneration) {
		syncState := "behind"
		if heartbeat.AppliedGeneration == service.manifest.Generation && heartbeat.StateDigest == service.manifest.StateDigest {
			syncState = SyncCurrent
		}
		service.logger.Info("cluster replica synchronization observed",
			"node_id", heartbeat.NodeID,
			"node_name", heartbeat.Name,
			"applied_generation", heartbeat.AppliedGeneration,
			"current_generation", service.manifest.Generation,
			"sync_state", syncState,
		)
	}
	var stateSnapshot []byte
	if heartbeat.StateDigest != service.manifest.StateDigest {
		var err error
		stateSnapshot, err = readStateSnapshot(service.directory, service.manifest.StateDigest)
		if err != nil {
			return SyncConfiguration{}, err
		}
	}
	configuration := joinConfiguration(service.manifest, stateSnapshot)
	return SyncConfiguration(configuration), nil
}

func (service *Service) monitorPrimary(ctx context.Context) {
	ticker := time.NewTicker(syncInterval)
	defer ticker.Stop()
	for {
		service.recordSynchronizationResult(service.syncFromPrimary(ctx))
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

func (service *Service) recordSynchronizationResult(err error) {
	if service.logger == nil {
		return
	}
	service.monitorMu.Lock()
	defer service.monitorMu.Unlock()
	if err == nil {
		if service.monitorError != "" {
			service.logger.Info("cluster synchronization recovered")
			service.monitorError = ""
		}
		return
	}
	message := err.Error()
	if message == service.monitorError {
		return
	}
	service.monitorError = message
	service.logger.Warn("cluster synchronization failed", "error", err)
}

func (service *Service) syncFromPrimary(ctx context.Context) error {
	service.mu.RLock()
	if service.manifest == nil {
		service.mu.RUnlock()
		return nil
	}
	if service.manifest.PrimaryID == service.nodeID {
		service.mu.RUnlock()
		return service.refreshPrimaryState(ctx)
	}
	primaryURL := memberAdvertiseURL(service.manifest, service.manifest.PrimaryID)
	primary, found := manifestMember(service.manifest, service.manifest.PrimaryID)
	heartbeat := Heartbeat{
		NodeID: service.nodeID, Name: service.nodeName, AdvertiseURL: service.advertiseURL,
		TrustAnchor: string(service.localTrustAnchorPEM), Version: service.version,
		Addresses:         effectiveDNSAddresses(service.manifest.Nodes[slices.IndexFunc(service.manifest.Nodes, func(node member) bool { return node.ID == service.nodeID })].Addresses, service.dnsListeners),
		AppliedGeneration: service.manifest.Generation,
		StateDigest:       service.manifest.StateDigest,
		UpSince:           service.startedAt, SentAt: time.Now(),
	}
	statusKey := service.manifest.StatusKey
	service.mu.RUnlock()
	if primaryURL == "" {
		return errors.New("cluster primary has no advertised URL")
	}
	if !found {
		return errors.New("cluster primary is not present in the member manifest")
	}
	client, err := service.httpClientForMember(primary)
	if err != nil {
		return err
	}
	endpoint, err := url.Parse(strings.TrimRight(primaryURL, "/") + syncPath)
	if err != nil {
		return fmt.Errorf("parse cluster primary URL: %w", err)
	}
	contents, err := json.Marshal(heartbeat)
	if err != nil {
		return fmt.Errorf("encode cluster synchronization heartbeat: %w", err)
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint.String(), bytes.NewReader(contents))
	if err != nil {
		return fmt.Errorf("create cluster synchronization request: %w", err)
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("X-Sable-Cluster-Signature", heartbeatSignature(statusKey, heartbeat))
	response, err := client.Do(request)
	if err != nil {
		return fmt.Errorf("synchronize with cluster primary: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode == http.StatusGone {
		if err := service.applyMembershipRemoval(); err != nil {
			return err
		}
		return nil
	}
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("cluster primary rejected synchronization: %s", response.Status)
	}
	var configuration SyncConfiguration
	if err := json.NewDecoder(io.LimitReader(response.Body, maximumSyncBytes)).Decode(&configuration); err != nil {
		return fmt.Errorf("decode cluster synchronization response: %w", err)
	}
	if err := validateSyncConfiguration(configuration); err != nil {
		return err
	}
	candidate := manifestFromJoinConfiguration(JoinConfiguration(configuration))
	if candidate.ClusterID == "" || !manifestContainsNode(candidate, service.nodeID) {
		return errors.New("cluster primary returned an invalid member manifest")
	}
	service.mu.RLock()
	active := service.manifest
	if active == nil || candidate.ClusterID != active.ClusterID || candidate.Generation < active.Generation {
		service.mu.RUnlock()
		return nil
	}
	stateChanged := candidate.StateDigest != active.StateDigest
	previousGeneration := active.Generation
	service.mu.RUnlock()
	if stateChanged {
		if len(configuration.StateSnapshot) == 0 {
			return errors.New("cluster primary omitted the required state snapshot")
		}
		if err := service.applyState(ctx, candidate.StateDigest, configuration.StateSnapshot); err != nil {
			return err
		}
	}
	service.mu.Lock()
	defer service.mu.Unlock()
	if service.manifest == nil || candidate.ClusterID != service.manifest.ClusterID || candidate.Generation < service.manifest.Generation {
		return nil
	}
	manifestChanged := !reflect.DeepEqual(candidate, service.manifest)
	if manifestChanged {
		if err := writeManifest(service.directory, candidate); err != nil {
			return err
		}
		service.manifest = candidate
		if err := cleanupStateSnapshots(service.directory, candidate.StateDigest); err != nil {
			return err
		}
	}
	firstSuccessfulSync := service.lastSuccessfulSync.IsZero()
	service.lastSuccessfulSync = time.Now()
	service.telemetry[candidate.PrimaryID] = nodeTelemetry{
		heartbeat: Heartbeat{
			NodeID: candidate.PrimaryID, AppliedGeneration: candidate.Generation,
			UpSince: time.Time{}, SentAt: time.Now(),
		},
		received: time.Now(),
	}
	if service.logger != nil {
		switch {
		case manifestChanged:
			service.logger.Info("cluster synchronization applied",
				"primary_id", candidate.PrimaryID,
				"from_generation", previousGeneration,
				"generation", candidate.Generation,
				"state_updated", stateChanged,
				"members", len(candidate.Nodes),
			)
		case firstSuccessfulSync:
			service.logger.Info("cluster synchronization established",
				"primary_id", candidate.PrimaryID,
				"generation", candidate.Generation,
				"members", len(candidate.Nodes),
			)
		}
	}
	return nil
}

func validateHeartbeatIdentity(heartbeat Heartbeat) (string, string, string, string, []string, error) {
	name := strings.TrimSpace(heartbeat.Name)
	advertiseURL := strings.TrimRight(strings.TrimSpace(heartbeat.AdvertiseURL), "/")
	trustAnchor := strings.TrimSpace(heartbeat.TrustAnchor)
	version := strings.TrimSpace(heartbeat.Version)
	if name == "" || len(name) > 128 {
		return "", "", "", "", nil, errors.New("cluster member name must contain 1 to 128 characters")
	}
	if _, err := validatePrimaryURL(advertiseURL); err != nil {
		return "", "", "", "", nil, fmt.Errorf("cluster member advertise URL: %w", err)
	}
	if trustAnchor != "" {
		if len(trustAnchor) > maximumTrustAnchorBytes {
			return "", "", "", "", nil, errors.New("cluster member trust anchor is too large")
		}
		if err := validateClusterTrustAnchor([]byte(trustAnchor)); err != nil {
			return "", "", "", "", nil, fmt.Errorf("cluster member trust anchor: %w", err)
		}
	}
	addresses, err := normalizeAddresses(heartbeat.Addresses)
	if err != nil || len(addresses) == 0 {
		return "", "", "", "", nil, errors.New("cluster member must advertise at least one valid DNS service address")
	}
	return name, advertiseURL, trustAnchor, version, addresses, nil
}

func (service *Service) applyRemoteTelemetry(state *State, now time.Time) {
	for index := range state.Nodes {
		node := &state.Nodes[index]
		if node.ID == service.nodeID {
			continue
		}
		observed, found := service.telemetry[node.ID]
		if !found || now.Sub(observed.received) > heartbeatFreshness {
			if found {
				node.State = "unreachable"
				node.LastContact = observed.received
			}
			continue
		}
		node.State = StateOnline
		node.UpSince = observed.heartbeat.UpSince
		node.LastContact = observed.received
		node.AppliedGeneration = observed.heartbeat.AppliedGeneration
		if state.Generation >= node.AppliedGeneration {
			node.Lag = state.Generation - node.AppliedGeneration
		}
		state.Connected++
		if node.Lag == 0 {
			node.SyncState = SyncCurrent
			node.LastSync = observed.received
			state.Synchronized++
		} else {
			node.SyncState = "behind"
		}
	}
}

func heartbeatSignature(key string, heartbeat Heartbeat) string {
	contents, _ := json.Marshal(heartbeat)
	mac := hmac.New(sha256.New, []byte(key))
	mac.Write(contents)
	return hex.EncodeToString(mac.Sum(nil))
}

func validHeartbeatSignature(key string, heartbeat Heartbeat, signature string) bool {
	provided, err := hex.DecodeString(strings.TrimSpace(signature))
	if err != nil {
		return false
	}
	expected, _ := hex.DecodeString(heartbeatSignature(key, heartbeat))
	return hmac.Equal(provided, expected)
}

func newStatusKey() (string, error) {
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(secret), nil
}

func memberAdvertiseURL(value *manifest, nodeID string) string {
	for _, node := range value.Nodes {
		if node.ID == nodeID {
			return node.AdvertiseURL
		}
	}
	return ""
}

func manifestMember(value *manifest, nodeID string) (member, bool) {
	for _, node := range value.Nodes {
		if node.ID == nodeID {
			return node, true
		}
	}
	return member{}, false
}

func validateSyncConfiguration(configuration SyncConfiguration) error {
	if configuration.FormatVersion != manifestVersion || !validID(configuration.ClusterID) || !validID(configuration.PrimaryID) || configuration.Generation == 0 || configuration.StatusKey == "" || (configuration.StateDigest != "" && !validStateDigest(configuration.StateDigest)) {
		return fmt.Errorf("invalid cluster synchronization response")
	}
	if len(configuration.StateSnapshot) > 0 && stateDigest(configuration.StateSnapshot) != configuration.StateDigest {
		return fmt.Errorf("invalid cluster state snapshot")
	}
	if err := validateMemberTrust(configuration.Members); err != nil {
		return fmt.Errorf("invalid cluster member trust: %w", err)
	}
	return nil
}
