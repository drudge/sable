package cluster

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/drudge/sable/internal/dnsname"
)

const (
	identityFileName = "node-id"
	manifestFileName = "cluster.json"
	manifestVersion  = 1

	RolePrimary = "primary"
	RoleReplica = "replica"
	StateOnline = "online"
	SyncCurrent = "current"
)

var (
	ErrAlreadyInitialized = errors.New("cluster is already initialized")
	ErrNotInitialized     = errors.New("cluster is not initialized")
	ErrNotPrimary         = errors.New("cluster operation must be sent to the primary node")
	ErrNodeRemoved        = errors.New("cluster membership was removed by the primary")
)

// Options contains only node-local settings. Cluster membership is stored in
// the durable manifest and synchronized from the primary.
type Options struct {
	DataDirectory   string
	NodeName        string
	AdvertiseURL    string
	HTTPSListen     string
	DNSListeners    []string
	TrustAnchorFile string
	HTTPClient      *http.Client
	Logger          *slog.Logger
	Replicator      StateReplicator
	Version         string
	StartedAt       time.Time
}

type LocalConfiguration struct {
	DataDirectory   string
	NodeName        string
	AdvertiseURL    string
	HTTPSListen     string
	TrustAnchorFile string
}

type Node struct {
	ID                string    `json:"id"`
	Name              string    `json:"name"`
	AdvertiseURL      string    `json:"advertise_url,omitempty"`
	Addresses         []string  `json:"addresses"`
	Role              string    `json:"role"`
	State             string    `json:"state"`
	Version           string    `json:"version"`
	CreatedAt         time.Time `json:"created_at"`
	UpSince           time.Time `json:"up_since"`
	LastContact       time.Time `json:"last_contact"`
	LastSync          time.Time `json:"last_sync"`
	CurrentGeneration uint64    `json:"current_generation"`
	AppliedGeneration uint64    `json:"applied_generation"`
	Lag               uint64    `json:"lag"`
	SyncState         string    `json:"sync_state"`
}

type State struct {
	Initialized   bool      `json:"initialized"`
	NetworkReady  bool      `json:"network_ready"`
	NodeID        string    `json:"node_id"`
	ClusterID     string    `json:"cluster_id,omitempty"`
	ClusterDomain string    `json:"cluster_domain,omitempty"`
	Generation    uint64    `json:"generation"`
	Mode          string    `json:"mode"`
	LocalRole     string    `json:"local_role,omitempty"`
	PrimaryID     string    `json:"primary_id,omitempty"`
	PrimaryURL    string    `json:"primary_url,omitempty"`
	UpdatedAt     time.Time `json:"updated_at,omitempty"`
	ObservedAt    time.Time `json:"observed_at"`
	Connected     int       `json:"connected"`
	Synchronized  int       `json:"synchronized"`
	Nodes         []Node    `json:"nodes"`
}

type member struct {
	ID           string    `json:"id"`
	Name         string    `json:"name"`
	AdvertiseURL string    `json:"advertise_url,omitempty"`
	TrustAnchor  string    `json:"trust_anchor,omitempty"`
	Addresses    []string  `json:"addresses"`
	Role         string    `json:"role"`
	Version      string    `json:"version"`
	CreatedAt    time.Time `json:"created_at"`
}

type manifest struct {
	FormatVersion int       `json:"format_version"`
	ClusterID     string    `json:"cluster_id"`
	ClusterDomain string    `json:"cluster_domain"`
	Generation    uint64    `json:"generation"`
	UpdatedAt     time.Time `json:"updated_at"`
	PrimaryID     string    `json:"primary_id"`
	StatusKey     string    `json:"status_key"`
	StateDigest   string    `json:"state_digest,omitempty"`
	Nodes         []member  `json:"nodes"`
}

type Service struct {
	mu                        sync.RWMutex
	directory                 string
	nodeID                    string
	nodeName                  string
	configuredName            string
	advertiseURL              string
	httpsListen               string
	dnsListeners              []string
	configuredTrustAnchorFile string
	trustAnchorFile           string
	trustAnchorPEM            []byte
	localTrustAnchorPEM       []byte
	version                   string
	startedAt                 time.Time
	manifest                  *manifest
	revocations               []revokedCluster
	httpClient                *http.Client
	baseHTTPClient            *http.Client
	replicator                StateReplicator
	joining                   bool
	telemetry                 map[string]nodeTelemetry
	monitorOnce               sync.Once
	monitorLifecycleMu        sync.Mutex
	monitorCancel             context.CancelFunc
	monitorDone               <-chan struct{}
	monitorMu                 sync.Mutex
	monitorError              string
	lastSuccessfulSync        time.Time
	logger                    *slog.Logger
	clientsMu                 sync.Mutex
	memberClients             map[string]*http.Client
}

func Open(options Options) (*Service, error) {
	if strings.TrimSpace(options.DataDirectory) == "" {
		return nil, errors.New("cluster data directory is required")
	}
	if options.StartedAt.IsZero() {
		options.StartedAt = time.Now()
	}
	if err := os.MkdirAll(options.DataDirectory, 0o700); err != nil {
		return nil, fmt.Errorf("create cluster data directory: %w", err)
	}
	nodeID, err := loadOrCreateIdentity(options.DataDirectory)
	if err != nil {
		return nil, err
	}
	trustAnchorFile, trustAnchorPEM, err := loadPersistedClusterTrustAnchor(options.DataDirectory)
	if err != nil {
		return nil, err
	}
	localTrustAnchorPEM, err := readConfiguredTrustAnchor(options.TrustAnchorFile)
	if err != nil {
		return nil, err
	}
	baseHTTPClient, err := httpClientWithClusterTrust(options.HTTPClient, nil)
	if err != nil {
		return nil, err
	}
	service := &Service{
		directory: options.DataDirectory, nodeID: nodeID,
		nodeName: strings.TrimSpace(options.NodeName), configuredName: strings.TrimSpace(options.NodeName),
		advertiseURL:              strings.TrimRight(strings.TrimSpace(options.AdvertiseURL), "/"),
		httpsListen:               strings.TrimSpace(options.HTTPSListen),
		dnsListeners:              append([]string(nil), options.DNSListeners...),
		configuredTrustAnchorFile: strings.TrimSpace(options.TrustAnchorFile),
		trustAnchorFile:           trustAnchorFile, trustAnchorPEM: trustAnchorPEM,
		localTrustAnchorPEM: localTrustAnchorPEM,
		version:             options.Version, startedAt: options.StartedAt,
		telemetry: make(map[string]nodeTelemetry), httpClient: baseHTTPClient,
		baseHTTPClient: baseHTTPClient, memberClients: make(map[string]*http.Client), replicator: options.Replicator,
		logger: options.Logger,
	}
	if service.nodeName == "" {
		service.nodeName = nodeID[:8]
	}
	service.httpClient, err = httpClientWithClusterTrust(service.httpClient, trustAnchorPEM)
	if err != nil {
		return nil, err
	}
	service.manifest, err = loadManifest(filepath.Join(options.DataDirectory, manifestFileName))
	if err != nil {
		return nil, err
	}
	service.revocations, err = loadRevocations(options.DataDirectory)
	if err != nil {
		return nil, err
	}
	if service.manifest != nil && service.manifest.StateDigest != "" {
		if _, err := readStateSnapshot(service.directory, service.manifest.StateDigest); err != nil {
			return nil, err
		}
	}
	return service, nil
}

func (service *Service) clock() time.Time { return time.Now() }

func (service *Service) Snapshot() State {
	service.mu.RLock()
	defer service.mu.RUnlock()
	now := time.Now()
	state := State{
		NodeID: service.nodeID, NetworkReady: strings.HasPrefix(service.advertiseURL, "https://"),
		Mode: "not-configured", ObservedAt: now, Nodes: []Node{},
	}
	if service.manifest == nil {
		return state
	}
	state.Initialized = true
	state.ClusterID = service.manifest.ClusterID
	state.ClusterDomain = service.manifest.ClusterDomain
	state.Generation = service.manifest.Generation
	state.Mode = "primary-replica"
	state.PrimaryID = service.manifest.PrimaryID
	state.UpdatedAt = service.manifest.UpdatedAt
	state.PrimaryURL = memberAdvertiseURL(service.manifest, service.manifest.PrimaryID)
	state.Nodes = make([]Node, 0, len(service.manifest.Nodes))
	for _, stored := range service.manifest.Nodes {
		node := Node{
			ID: stored.ID, Name: stored.Name, AdvertiseURL: stored.AdvertiseURL,
			Addresses: append([]string(nil), stored.Addresses...), Role: stored.Role,
			Version: stored.Version, CreatedAt: stored.CreatedAt, State: "unknown", SyncState: "unknown",
			CurrentGeneration: service.manifest.Generation,
		}
		if node.ID == service.nodeID {
			node.Name = service.nodeName
			node.AdvertiseURL = service.advertiseURL
			node.Version = service.version
			node.Addresses = effectiveDNSAddresses(node.Addresses, service.dnsListeners)
			node.State = StateOnline
			node.UpSince = service.startedAt
			node.LastContact = now
			node.AppliedGeneration = service.manifest.Generation
			state.LocalRole = node.Role
			state.Connected++
			if node.Role == RolePrimary {
				node.LastSync = now
				node.SyncState = SyncCurrent
				state.Synchronized++
			} else {
				node.LastSync = service.lastSuccessfulSync
				node.SyncState = "unverified"
			}
		}
		state.Nodes = append(state.Nodes, node)
	}
	service.applyRemoteTelemetry(&state, now)
	if state.LocalRole == RoleReplica && !service.lastSuccessfulSync.IsZero() {
		primaryCurrent := slices.ContainsFunc(state.Nodes, func(node Node) bool {
			return node.ID == state.PrimaryID && node.State == StateOnline && node.SyncState == SyncCurrent
		})
		if primaryCurrent {
			for index := range state.Nodes {
				if state.Nodes[index].ID == service.nodeID {
					state.Nodes[index].SyncState = SyncCurrent
					state.Synchronized++
					break
				}
			}
		}
	}
	sortClusterNodes(state.Nodes, state.PrimaryID)
	return state
}

func sortClusterNodes(nodes []Node, primaryID string) {
	slices.SortFunc(nodes, func(left, right Node) int {
		if left.ID == primaryID && right.ID != primaryID {
			return -1
		}
		if right.ID == primaryID && left.ID != primaryID {
			return 1
		}
		if comparison := strings.Compare(strings.ToLower(left.Name), strings.ToLower(right.Name)); comparison != 0 {
			return comparison
		}
		return strings.Compare(left.ID, right.ID)
	})
}

func (service *Service) LocalConfiguration() LocalConfiguration {
	service.mu.RLock()
	defer service.mu.RUnlock()
	return LocalConfiguration{DataDirectory: service.directory, NodeName: service.configuredName, AdvertiseURL: service.advertiseURL, HTTPSListen: service.httpsListen, TrustAnchorFile: service.configuredTrustAnchorFile}
}

func (service *Service) Initialize(ctx context.Context, domain string, addresses []string) error {
	normalizedDomain, err := dnsname.Normalize(domain)
	if err != nil {
		return fmt.Errorf("cluster domain: %w", err)
	}
	normalizedAddresses, err := normalizeAddresses(addresses)
	if err != nil {
		return err
	}
	if len(normalizedAddresses) == 0 {
		return errors.New("at least one node IP address is required")
	}
	normalizedAddresses = effectiveDNSAddresses(normalizedAddresses, service.dnsListeners)
	stateContents, stateDigest, err := service.captureState(ctx)
	if err != nil {
		return err
	}
	service.mu.Lock()
	defer service.mu.Unlock()
	if service.manifest != nil {
		return ErrAlreadyInitialized
	}
	clusterID, err := newID()
	if err != nil {
		return fmt.Errorf("generate cluster ID: %w", err)
	}
	statusKey, err := newStatusKey()
	if err != nil {
		return fmt.Errorf("generate cluster status key: %w", err)
	}
	now := service.clock()
	candidate := &manifest{
		FormatVersion: manifestVersion, ClusterID: clusterID, ClusterDomain: normalizedDomain,
		Generation: 1, UpdatedAt: now, PrimaryID: service.nodeID, StatusKey: statusKey, StateDigest: stateDigest,
		Nodes: []member{{
			ID: service.nodeID, Name: service.nodeName, AdvertiseURL: service.advertiseURL,
			TrustAnchor: string(service.localTrustAnchorPEM),
			Addresses:   normalizedAddresses, Role: RolePrimary, Version: service.version, CreatedAt: now,
		}},
	}
	if stateDigest != "" {
		if err := writeStateSnapshot(service.directory, stateDigest, stateContents); err != nil {
			return err
		}
	}
	if err := writeManifest(service.directory, candidate); err != nil {
		return err
	}
	service.manifest = candidate
	return nil
}

// Promote changes the writable primary. The current primary may perform a
// planned handoff to a replica; a replica may promote only itself for manual
// disaster recovery when the primary is unavailable.
func (service *Service) Promote(_ context.Context, nodeID string) error {
	service.mu.Lock()
	defer service.mu.Unlock()
	if service.manifest == nil {
		return ErrNotInitialized
	}
	nodeID = strings.TrimSpace(nodeID)
	if !manifestContainsNode(service.manifest, nodeID) {
		return errors.New("cluster node was not found")
	}
	if service.manifest.PrimaryID == nodeID {
		return nil
	}
	localIsPrimary := service.manifest.PrimaryID == service.nodeID
	if !localIsPrimary && nodeID != service.nodeID {
		return errors.New("only the current primary can promote another replica")
	}
	if localIsPrimary && nodeID != service.nodeID {
		observed, online := service.telemetry[nodeID]
		if !online || service.clock().Sub(observed.received) > heartbeatFreshness || observed.heartbeat.AppliedGeneration != service.manifest.Generation || observed.heartbeat.StateDigest != service.manifest.StateDigest {
			return errors.New("replica must be online and fully synchronized before primary handoff")
		}
	}
	candidate := cloneManifest(service.manifest)
	candidate.Generation++
	candidate.UpdatedAt = service.clock()
	candidate.PrimaryID = nodeID
	for index := range candidate.Nodes {
		if candidate.Nodes[index].ID == nodeID {
			candidate.Nodes[index].Role = RolePrimary
		} else {
			candidate.Nodes[index].Role = RoleReplica
		}
	}
	if err := writeManifest(service.directory, candidate); err != nil {
		return err
	}
	service.manifest = candidate
	clear(service.telemetry)
	return nil
}

func (service *Service) Remove(_ context.Context, nodeID string) error {
	service.mu.Lock()
	defer service.mu.Unlock()
	if service.manifest == nil {
		return ErrNotInitialized
	}
	if service.manifest.PrimaryID != service.nodeID {
		return ErrNotPrimary
	}
	nodeID = strings.TrimSpace(nodeID)
	if nodeID == "" {
		return errors.New("cluster node ID is required")
	}
	if nodeID == service.nodeID {
		return errors.New("the primary cannot remove itself")
	}
	if !manifestContainsNode(service.manifest, nodeID) {
		return errors.New("cluster node was not found")
	}
	candidate := cloneManifest(service.manifest)
	candidate.Generation++
	candidate.UpdatedAt = service.clock()
	candidate.Nodes = slices.DeleteFunc(candidate.Nodes, func(node member) bool { return node.ID == nodeID })
	if err := writeManifest(service.directory, candidate); err != nil {
		return err
	}
	service.manifest = candidate
	delete(service.telemetry, nodeID)
	return nil
}

func (service *Service) Delete(_ context.Context) error {
	service.mu.Lock()
	defer service.mu.Unlock()
	if service.manifest == nil {
		return ErrNotInitialized
	}
	if service.manifest.PrimaryID != service.nodeID {
		return errors.New("only the primary can delete the cluster; replicas must leave instead")
	}
	if err := service.recordClusterRevocation(service.manifest); err != nil {
		return err
	}
	return service.clearLocalMembership()
}

// Leave removes this replica's local cluster membership without changing the
// primary's member list. The replica keeps its stable node identity and the
// last synchronized DNS state so it can continue serving independently.
func (service *Service) Leave(_ context.Context) error {
	service.mu.Lock()
	defer service.mu.Unlock()
	if service.manifest == nil {
		return ErrNotInitialized
	}
	if service.manifest.PrimaryID == service.nodeID {
		return errors.New("the primary cannot leave its own cluster")
	}
	if err := service.clearLocalMembership(); err != nil {
		return err
	}
	if service.logger != nil {
		service.logger.Info("local replica left cluster", "node_id", service.nodeID)
	}
	return nil
}

func (service *Service) applyMembershipRemoval() error {
	service.mu.Lock()
	defer service.mu.Unlock()
	if service.manifest == nil {
		return nil
	}
	if err := service.clearLocalMembership(); err != nil {
		return err
	}
	if service.logger != nil {
		service.logger.Info("local cluster membership removed by primary", "node_id", service.nodeID)
	}
	return nil
}

// clearLocalMembership requires service.mu to be held by the caller.
func (service *Service) clearLocalMembership() error {
	if err := os.Remove(filepath.Join(service.directory, manifestFileName)); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("remove local cluster membership: %w", err)
	}
	if err := os.Remove(filepath.Join(service.directory, enrollmentFileName)); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("remove local cluster enrollment tokens: %w", err)
	}
	if err := os.Remove(filepath.Join(service.directory, persistedTrustAnchorFileName)); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("remove local cluster trust: %w", err)
	}
	if err := cleanupStateSnapshots(service.directory, ""); err != nil {
		return err
	}
	if err := syncDirectory(service.directory); err != nil {
		return err
	}
	service.manifest = nil
	service.trustAnchorFile = ""
	service.trustAnchorPEM = nil
	service.httpClient = service.baseHTTPClient
	service.lastSuccessfulSync = time.Time{}
	clear(service.telemetry)
	return nil
}

func (service *Service) Close(ctx context.Context) error {
	// Synchronize with a concurrent StartMonitoring call. Calling Close before
	// StartMonitoring permanently leaves monitoring disabled, which is the only
	// useful behavior for a service that is already shutting down.
	service.monitorOnce.Do(func() {})

	service.monitorLifecycleMu.Lock()
	cancel := service.monitorCancel
	done := service.monitorDone
	service.monitorLifecycleMu.Unlock()
	if cancel == nil || done == nil {
		return nil
	}
	cancel()
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func normalizeAddresses(addresses []string) ([]string, error) {
	result := make([]string, 0, len(addresses))
	for index, address := range addresses {
		address = strings.TrimSpace(address)
		if address == "" {
			continue
		}
		if parsed, err := netip.ParseAddr(address); err == nil && parsed.Zone() == "" {
			result = append(result, parsed.String())
			continue
		}
		if endpoint, err := netip.ParseAddrPort(address); err == nil && endpoint.Addr().Zone() == "" && endpoint.Port() != 0 {
			result = append(result, endpoint.String())
			continue
		}
		return nil, fmt.Errorf("node address %d must be an IPv4 or IPv6 address with an optional port", index+1)
	}
	slices.Sort(result)
	return slices.Compact(result), nil
}

// effectiveDNSAddresses preserves the advertised host while filling in a
// nonstandard port from this node's actual DNS listener. Cluster addresses
// without a port continue to mean the standard DNS port 53.
func effectiveDNSAddresses(addresses, listeners []string) []string {
	result := append([]string(nil), addresses...)
	parsedListeners := make([]netip.AddrPort, 0, len(listeners))
	for _, listener := range listeners {
		if parsed, err := netip.ParseAddrPort(strings.TrimSpace(listener)); err == nil && parsed.Port() != 0 {
			parsedListeners = append(parsedListeners, parsed)
		}
	}
	for index, address := range result {
		if _, err := netip.ParseAddrPort(address); err == nil {
			continue
		}
		advertised, err := netip.ParseAddr(address)
		if err != nil {
			continue
		}
		var port uint16 = 53
		for _, listener := range parsedListeners {
			if listener.Addr() == advertised || listener.Addr().IsUnspecified() {
				port = listener.Port()
				break
			}
		}
		if port == 53 && len(parsedListeners) == 1 {
			port = parsedListeners[0].Port()
		}
		if port != 53 {
			result[index] = netip.AddrPortFrom(advertised, port).String()
		}
	}
	slices.Sort(result)
	return slices.Compact(result)
}

func loadOrCreateIdentity(directory string) (string, error) {
	path := filepath.Join(directory, identityFileName)
	contents, err := os.ReadFile(path)
	if err == nil {
		identity := strings.TrimSpace(string(contents))
		if !validID(identity) {
			return "", errors.New("cluster node identity is invalid")
		}
		return identity, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return "", fmt.Errorf("read cluster node identity: %w", err)
	}
	identity, err := newID()
	if err != nil {
		return "", fmt.Errorf("generate cluster node identity: %w", err)
	}
	if err := writeExclusiveFile(path, []byte(identity+"\n"), 0o600); err != nil {
		if errors.Is(err, os.ErrExist) {
			return loadOrCreateIdentity(directory)
		}
		return "", fmt.Errorf("persist cluster node identity: %w", err)
	}
	if err := syncDirectory(directory); err != nil {
		return "", err
	}
	return identity, nil
}

func loadManifest(path string) (*manifest, error) {
	contents, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read cluster manifest: %w", err)
	}
	var loaded manifest
	if err := json.Unmarshal(contents, &loaded); err != nil {
		return nil, fmt.Errorf("decode cluster manifest: %w", err)
	}
	if loaded.FormatVersion != manifestVersion || !validID(loaded.ClusterID) || loaded.ClusterDomain == "" || loaded.Generation == 0 || !validID(loaded.PrimaryID) || loaded.StatusKey == "" || len(loaded.Nodes) == 0 || (loaded.StateDigest != "" && !validStateDigest(loaded.StateDigest)) {
		return nil, errors.New("cluster manifest is invalid or unsupported")
	}
	for _, node := range loaded.Nodes {
		if node.TrustAnchor != "" {
			if len(node.TrustAnchor) > maximumTrustAnchorBytes {
				return nil, fmt.Errorf("cluster member %q trust anchor is too large", node.Name)
			}
			if err := validateClusterTrustAnchor([]byte(node.TrustAnchor)); err != nil {
				return nil, fmt.Errorf("cluster member %q trust anchor: %w", node.Name, err)
			}
		}
	}
	return &loaded, nil
}

func writeManifest(directory string, value *manifest) error {
	contents, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return fmt.Errorf("encode cluster manifest: %w", err)
	}
	contents = append(contents, '\n')
	temporary, err := os.CreateTemp(directory, ".cluster-*.json")
	if err != nil {
		return fmt.Errorf("create temporary cluster manifest: %w", err)
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if err := temporary.Chmod(0o600); err != nil {
		temporary.Close()
		return fmt.Errorf("secure temporary cluster manifest: %w", err)
	}
	if _, err := temporary.Write(contents); err != nil {
		temporary.Close()
		return fmt.Errorf("write temporary cluster manifest: %w", err)
	}
	if err := temporary.Sync(); err != nil {
		temporary.Close()
		return fmt.Errorf("sync temporary cluster manifest: %w", err)
	}
	if err := temporary.Close(); err != nil {
		return fmt.Errorf("close temporary cluster manifest: %w", err)
	}
	if err := os.Rename(temporaryPath, filepath.Join(directory, manifestFileName)); err != nil {
		return fmt.Errorf("replace cluster manifest: %w", err)
	}
	return syncDirectory(directory)
}

func writeExclusiveFile(path string, contents []byte, mode os.FileMode) error {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return err
	}
	if _, err := file.Write(contents); err != nil {
		file.Close()
		return err
	}
	if err := file.Sync(); err != nil {
		file.Close()
		return err
	}
	return file.Close()
}

func syncDirectory(path string) error {
	directory, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("open cluster data directory for sync: %w", err)
	}
	defer directory.Close()
	if err := directory.Sync(); err != nil {
		return fmt.Errorf("sync cluster data directory: %w", err)
	}
	return nil
}

func newID() (string, error) {
	var value [16]byte
	if _, err := rand.Read(value[:]); err != nil {
		return "", err
	}
	value[6] = value[6]&0x0f | 0x40
	value[8] = value[8]&0x3f | 0x80
	encoded := hex.EncodeToString(value[:])
	return encoded[:8] + "-" + encoded[8:12] + "-" + encoded[12:16] + "-" + encoded[16:20] + "-" + encoded[20:], nil
}

func validID(value string) bool {
	if len(value) != 36 || value[8] != '-' || value[13] != '-' || value[18] != '-' || value[23] != '-' {
		return false
	}
	_, err := hex.DecodeString(strings.ReplaceAll(value, "-", ""))
	return err == nil
}

func cloneManifest(source *manifest) *manifest {
	if source == nil {
		return nil
	}
	cloned := *source
	cloned.Nodes = make([]member, len(source.Nodes))
	copy(cloned.Nodes, source.Nodes)
	for index := range cloned.Nodes {
		cloned.Nodes[index].Addresses = append([]string(nil), source.Nodes[index].Addresses...)
	}
	return &cloned
}

func manifestContainsNode(value *manifest, nodeID string) bool {
	return value != nil && slices.ContainsFunc(value.Nodes, func(node member) bool { return node.ID == nodeID })
}
