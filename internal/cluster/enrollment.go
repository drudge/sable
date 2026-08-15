package cluster

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"
)

const (
	enrollmentFileName     = "enrollment-tokens.json"
	defaultEnrollmentTTL   = 15 * time.Minute
	maximumEnrollmentTTL   = 24 * time.Hour
	maximumEnrollmentBytes = 64 << 20
	enrollmentPath         = "/api/v1/cluster/enroll"
)

var (
	ErrNetworkUnavailable = errors.New("cluster replication requires an HTTPS advertised URL")
	ErrInvalidEnrollment  = errors.New("cluster enrollment token is invalid, expired, or already used")
)

type EnrollmentToken struct {
	Token     string    `json:"token"`
	ExpiresAt time.Time `json:"expires_at"`
}

type JoinRequest struct {
	Token        string   `json:"token"`
	NodeID       string   `json:"node_id"`
	Name         string   `json:"name"`
	AdvertiseURL string   `json:"advertise_url"`
	TrustAnchor  string   `json:"trust_anchor,omitempty"`
	Addresses    []string `json:"addresses"`
	Version      string   `json:"version"`
}

type JoinOptions struct {
	PrimaryURL string
	Token      string
	Addresses  []string
}

type Member struct {
	ID           string    `json:"id"`
	Name         string    `json:"name"`
	AdvertiseURL string    `json:"advertise_url,omitempty"`
	TrustAnchor  string    `json:"trust_anchor,omitempty"`
	Addresses    []string  `json:"addresses"`
	Role         string    `json:"role"`
	Version      string    `json:"version"`
	CreatedAt    time.Time `json:"created_at"`
}

type JoinConfiguration struct {
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

type storedEnrollmentToken struct {
	Digest    string    `json:"digest"`
	ExpiresAt time.Time `json:"expires_at"`
}

type enrollmentTokenFile struct {
	Tokens []storedEnrollmentToken `json:"tokens"`
}

func (service *Service) CreateEnrollmentToken(_ context.Context, ttl time.Duration) (EnrollmentToken, error) {
	service.mu.Lock()
	defer service.mu.Unlock()
	if service.manifest == nil {
		return EnrollmentToken{}, ErrNotInitialized
	}
	if service.manifest.PrimaryID != service.nodeID {
		return EnrollmentToken{}, ErrNotPrimary
	}
	if !strings.HasPrefix(service.advertiseURL, "https://") {
		return EnrollmentToken{}, ErrNetworkUnavailable
	}
	if ttl == 0 {
		ttl = defaultEnrollmentTTL
	}
	if ttl < time.Minute || ttl > maximumEnrollmentTTL {
		return EnrollmentToken{}, errors.New("enrollment token lifetime must be between 1 minute and 24 hours")
	}
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		return EnrollmentToken{}, fmt.Errorf("generate enrollment token: %w", err)
	}
	token := base64.RawURLEncoding.EncodeToString(secret)
	expiresAt := time.Now().Add(ttl)
	stored, err := service.loadEnrollmentTokensLocked()
	if err != nil {
		return EnrollmentToken{}, err
	}
	stored = append(activeEnrollmentTokens(stored, time.Now()), storedEnrollmentToken{Digest: enrollmentDigest(token), ExpiresAt: expiresAt})
	if err := service.writeEnrollmentTokensLocked(stored); err != nil {
		return EnrollmentToken{}, err
	}
	bundledToken, err := encodeEnrollmentBundle(token, service.localTrustAnchorPEM)
	if err != nil {
		return EnrollmentToken{}, err
	}
	return EnrollmentToken{Token: bundledToken, ExpiresAt: expiresAt}, nil
}

func (service *Service) Enroll(ctx context.Context, request JoinRequest) (JoinConfiguration, error) {
	request, err := validateJoinRequest(request)
	if err != nil {
		return JoinConfiguration{}, err
	}
	if err := service.refreshPrimaryState(ctx); err != nil && !errors.Is(err, ErrNotInitialized) {
		return JoinConfiguration{}, err
	}
	service.mu.Lock()
	defer service.mu.Unlock()
	if service.manifest == nil {
		return JoinConfiguration{}, ErrNotInitialized
	}
	if service.manifest.PrimaryID != service.nodeID {
		return JoinConfiguration{}, ErrNotPrimary
	}
	if !strings.HasPrefix(service.advertiseURL, "https://") {
		return JoinConfiguration{}, ErrNetworkUnavailable
	}
	existingIndex := -1
	for index, existing := range service.manifest.Nodes {
		if existing.ID == request.NodeID {
			existingIndex = index
			continue
		}
		if existing.AdvertiseURL == request.AdvertiseURL {
			return JoinConfiguration{}, errors.New("a node with this advertised URL is already a cluster member")
		}
	}
	if err := service.consumeEnrollmentTokenLocked(request.Token); err != nil {
		return JoinConfiguration{}, err
	}
	now := time.Now()
	candidate := cloneManifest(service.manifest)
	candidate.Generation++
	candidate.UpdatedAt = now
	enrolled := member{
		ID: request.NodeID, Name: request.Name, AdvertiseURL: request.AdvertiseURL,
		TrustAnchor: request.TrustAnchor,
		Addresses:   request.Addresses, Role: RoleReplica, Version: request.Version, CreatedAt: now,
	}
	if existingIndex >= 0 {
		enrolled.CreatedAt = candidate.Nodes[existingIndex].CreatedAt
		candidate.Nodes[existingIndex] = enrolled
	} else {
		candidate.Nodes = append(candidate.Nodes, enrolled)
	}
	slices.SortFunc(candidate.Nodes, func(left, right member) int { return strings.Compare(left.ID, right.ID) })
	if err := writeManifest(service.directory, candidate); err != nil {
		return JoinConfiguration{}, err
	}
	service.manifest = candidate
	stateSnapshot, err := readStateSnapshot(service.directory, candidate.StateDigest)
	if err != nil {
		return JoinConfiguration{}, err
	}
	return joinConfiguration(candidate, stateSnapshot), nil
}

func (service *Service) Join(ctx context.Context, options JoinOptions) error {
	addresses, err := normalizeAddresses(options.Addresses)
	if err != nil {
		return err
	}
	if len(addresses) == 0 {
		return errors.New("at least one node IP address is required")
	}
	addresses = effectiveDNSAddresses(addresses, service.dnsListeners)
	primaryURL, err := validatePrimaryURL(options.PrimaryURL)
	if err != nil {
		return err
	}
	token, trustAnchor, err := decodeEnrollmentBundle(options.Token)
	if err != nil {
		return err
	}
	if token == "" {
		return errors.New("enrollment token is required")
	}
	enrollmentClient, err := httpClientWithClusterTrust(service.baseHTTPClient, trustAnchor)
	if err != nil {
		return fmt.Errorf("prepare cluster trust: %w", err)
	}
	service.mu.Lock()
	if service.manifest != nil || service.joining {
		service.mu.Unlock()
		return ErrAlreadyInitialized
	}
	if !strings.HasPrefix(service.advertiseURL, "https://") {
		service.mu.Unlock()
		return ErrNetworkUnavailable
	}
	service.joining = true
	request := JoinRequest{
		Token: token, NodeID: service.nodeID, Name: service.nodeName,
		AdvertiseURL: service.advertiseURL, TrustAnchor: string(service.localTrustAnchorPEM),
		Addresses: addresses, Version: service.version,
	}
	service.mu.Unlock()
	configuration, err := service.requestEnrollment(ctx, primaryURL, request, enrollmentClient)
	if err != nil {
		service.clearJoining()
		return err
	}
	joined := manifestFromJoinConfiguration(configuration)
	if !manifestContainsNode(joined, service.nodeID) {
		service.clearJoining()
		return errors.New("primary enrollment response does not contain this node")
	}
	if configuration.StateDigest != "" {
		if err := service.applyState(ctx, configuration.StateDigest, configuration.StateSnapshot); err != nil {
			service.clearJoining()
			return err
		}
	}
	service.mu.Lock()
	defer service.mu.Unlock()
	if len(trustAnchor) > 0 {
		trustAnchorFile, err := writeClusterTrustAnchor(service.directory, trustAnchor)
		if err != nil {
			service.joining = false
			return err
		}
		service.trustAnchorFile = trustAnchorFile
		service.trustAnchorPEM = append([]byte(nil), trustAnchor...)
		service.httpClient = enrollmentClient
	}
	if err := writeManifest(service.directory, joined); err != nil {
		service.joining = false
		return err
	}
	service.manifest = joined
	service.lastSuccessfulSync = time.Now()
	service.joining = false
	return nil
}

func (service *Service) clearJoining() {
	service.mu.Lock()
	service.joining = false
	service.mu.Unlock()
}

func (service *Service) requestEnrollment(ctx context.Context, primary *url.URL, request JoinRequest, client *http.Client) (JoinConfiguration, error) {
	contents, err := json.Marshal(request)
	if err != nil {
		return JoinConfiguration{}, fmt.Errorf("encode enrollment request: %w", err)
	}
	endpoint := *primary
	endpoint.Path = strings.TrimRight(endpoint.Path, "/") + enrollmentPath
	httpRequest, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint.String(), bytes.NewReader(contents))
	if err != nil {
		return JoinConfiguration{}, fmt.Errorf("create enrollment request: %w", err)
	}
	httpRequest.Header.Set("Content-Type", "application/json")
	response, err := client.Do(httpRequest)
	if err != nil {
		return JoinConfiguration{}, fmt.Errorf("contact cluster primary: %w", err)
	}
	defer response.Body.Close()
	limited := io.LimitReader(response.Body, maximumEnrollmentBytes)
	if response.StatusCode != http.StatusCreated {
		var failure struct {
			Error string `json:"error"`
		}
		if json.NewDecoder(limited).Decode(&failure) == nil && failure.Error != "" {
			return JoinConfiguration{}, errors.New(failure.Error)
		}
		return JoinConfiguration{}, fmt.Errorf("cluster primary rejected enrollment: %s", response.Status)
	}
	var configuration JoinConfiguration
	if err := json.NewDecoder(limited).Decode(&configuration); err != nil {
		return JoinConfiguration{}, fmt.Errorf("decode enrollment response: %w", err)
	}
	if configuration.FormatVersion != manifestVersion || !validID(configuration.ClusterID) || configuration.ClusterDomain == "" || !validID(configuration.PrimaryID) || configuration.StatusKey == "" || (configuration.StateDigest != "" && (!validStateDigest(configuration.StateDigest) || stateDigest(configuration.StateSnapshot) != configuration.StateDigest)) {
		return JoinConfiguration{}, errors.New("cluster primary returned an invalid enrollment configuration")
	}
	if err := validateMemberTrust(configuration.Members); err != nil {
		return JoinConfiguration{}, fmt.Errorf("cluster primary returned invalid member trust: %w", err)
	}
	return configuration, nil
}

func validateJoinRequest(request JoinRequest) (JoinRequest, error) {
	request.Token = strings.TrimSpace(request.Token)
	request.NodeID = strings.TrimSpace(request.NodeID)
	request.Name = strings.TrimSpace(request.Name)
	request.AdvertiseURL = strings.TrimRight(strings.TrimSpace(request.AdvertiseURL), "/")
	request.Version = strings.TrimSpace(request.Version)
	request.TrustAnchor = strings.TrimSpace(request.TrustAnchor)
	if request.Token == "" || !validID(request.NodeID) || request.Name == "" {
		return JoinRequest{}, errors.New("enrollment request is missing required node identity fields")
	}
	if _, err := validatePrimaryURL(request.AdvertiseURL); err != nil {
		return JoinRequest{}, fmt.Errorf("node advertise URL: %w", err)
	}
	addresses, err := normalizeAddresses(request.Addresses)
	if err != nil || len(addresses) == 0 {
		return JoinRequest{}, errors.New("enrollment request requires at least one valid node IP address")
	}
	request.Addresses = addresses
	if request.TrustAnchor != "" {
		if len(request.TrustAnchor) > maximumTrustAnchorBytes {
			return JoinRequest{}, errors.New("node trust anchor is too large")
		}
		if err := validateClusterTrustAnchor([]byte(request.TrustAnchor)); err != nil {
			return JoinRequest{}, fmt.Errorf("node trust anchor: %w", err)
		}
	}
	return request, nil
}

func validatePrimaryURL(value string) (*url.URL, error) {
	parsed, err := url.Parse(strings.TrimRight(strings.TrimSpace(value), "/"))
	if err != nil || parsed.Host == "" || parsed.Scheme != "https" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return nil, errors.New("primary URL must be an absolute HTTPS URL")
	}
	host := parsed.Hostname()
	if !validPrimaryHost(host) {
		return nil, errors.New("primary URL must use a valid hostname or IP address")
	}
	if net.ParseIP(host) != nil && net.ParseIP(host).IsUnspecified() {
		return nil, errors.New("primary URL must use a reachable host")
	}
	return parsed, nil
}

func validPrimaryHost(host string) bool {
	if host == "" {
		return false
	}
	if net.ParseIP(host) != nil {
		return true
	}
	if len(host) > 253 {
		return false
	}
	for _, label := range strings.Split(strings.TrimSuffix(host, "."), ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, character := range label {
			if (character < 'a' || character > 'z') && (character < 'A' || character > 'Z') && (character < '0' || character > '9') && character != '-' {
				return false
			}
		}
	}
	return true
}

func joinConfiguration(source *manifest, stateSnapshot []byte) JoinConfiguration {
	configuration := JoinConfiguration{
		FormatVersion: source.FormatVersion, ClusterID: source.ClusterID, ClusterDomain: source.ClusterDomain,
		Generation: source.Generation, UpdatedAt: source.UpdatedAt, PrimaryID: source.PrimaryID,
		StatusKey: source.StatusKey, StateDigest: source.StateDigest, StateSnapshot: stateSnapshot,
		Members: make([]Member, 0, len(source.Nodes)),
	}
	for _, node := range source.Nodes {
		configuration.Members = append(configuration.Members, Member{
			ID: node.ID, Name: node.Name, AdvertiseURL: node.AdvertiseURL,
			TrustAnchor: node.TrustAnchor,
			Addresses:   append([]string(nil), node.Addresses...), Role: node.Role,
			Version: node.Version, CreatedAt: node.CreatedAt,
		})
	}
	return configuration
}

func manifestFromJoinConfiguration(source JoinConfiguration) *manifest {
	result := &manifest{
		FormatVersion: source.FormatVersion, ClusterID: source.ClusterID, ClusterDomain: source.ClusterDomain,
		Generation: source.Generation, UpdatedAt: source.UpdatedAt, PrimaryID: source.PrimaryID,
		StatusKey: source.StatusKey, StateDigest: source.StateDigest, Nodes: make([]member, 0, len(source.Members)),
	}
	for _, node := range source.Members {
		result.Nodes = append(result.Nodes, member{
			ID: node.ID, Name: node.Name, AdvertiseURL: node.AdvertiseURL,
			TrustAnchor: node.TrustAnchor,
			Addresses:   append([]string(nil), node.Addresses...), Role: node.Role,
			Version: node.Version, CreatedAt: node.CreatedAt,
		})
	}
	return result
}

func validateMemberTrust(members []Member) error {
	for _, node := range members {
		if node.TrustAnchor == "" {
			continue
		}
		if len(node.TrustAnchor) > maximumTrustAnchorBytes {
			return fmt.Errorf("node %q trust anchor is too large", node.Name)
		}
		if err := validateClusterTrustAnchor([]byte(node.TrustAnchor)); err != nil {
			return fmt.Errorf("node %q: %w", node.Name, err)
		}
	}
	return nil
}

func enrollmentDigest(token string) string {
	digest := sha256.Sum256([]byte(token))
	return hex.EncodeToString(digest[:])
}

func activeEnrollmentTokens(tokens []storedEnrollmentToken, now time.Time) []storedEnrollmentToken {
	return slices.DeleteFunc(tokens, func(token storedEnrollmentToken) bool { return !token.ExpiresAt.After(now) })
}

func (service *Service) consumeEnrollmentTokenLocked(token string) error {
	tokens, err := service.loadEnrollmentTokensLocked()
	if err != nil {
		return err
	}
	digest := enrollmentDigest(strings.TrimSpace(token))
	found := false
	now := time.Now()
	tokens = slices.DeleteFunc(tokens, func(stored storedEnrollmentToken) bool {
		match := stored.Digest == digest && stored.ExpiresAt.After(now)
		found = found || match
		return match || !stored.ExpiresAt.After(now)
	})
	if !found {
		return ErrInvalidEnrollment
	}
	return service.writeEnrollmentTokensLocked(tokens)
}

func (service *Service) loadEnrollmentTokensLocked() ([]storedEnrollmentToken, error) {
	contents, err := os.ReadFile(filepath.Join(service.directory, enrollmentFileName))
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read enrollment tokens: %w", err)
	}
	var stored enrollmentTokenFile
	if err := json.Unmarshal(contents, &stored); err != nil {
		return nil, fmt.Errorf("decode enrollment tokens: %w", err)
	}
	return stored.Tokens, nil
}

func (service *Service) writeEnrollmentTokensLocked(tokens []storedEnrollmentToken) error {
	contents, err := json.MarshalIndent(enrollmentTokenFile{Tokens: tokens}, "", "  ")
	if err != nil {
		return fmt.Errorf("encode enrollment tokens: %w", err)
	}
	contents = append(contents, '\n')
	path := filepath.Join(service.directory, enrollmentFileName)
	temporary, err := os.CreateTemp(service.directory, ".enrollment-*.json")
	if err != nil {
		return fmt.Errorf("create enrollment token file: %w", err)
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if err := temporary.Chmod(0o600); err != nil {
		temporary.Close()
		return err
	}
	if _, err := temporary.Write(contents); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Sync(); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	if err := os.Rename(temporaryPath, path); err != nil {
		return fmt.Errorf("replace enrollment token file: %w", err)
	}
	return syncDirectory(service.directory)
}
