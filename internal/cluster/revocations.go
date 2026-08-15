package cluster

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"time"
)

const (
	revocationsFileName = "revoked-clusters.json"
	revocationsVersion  = 1
	maximumRevocations  = 32
)

// A destroyed cluster remains recognizable so replicas that were offline
// during destruction can be released when they next synchronize.
type revokedCluster struct {
	ClusterID string    `json:"cluster_id"`
	StatusKey string    `json:"status_key"`
	NodeIDs   []string  `json:"node_ids"`
	CreatedAt time.Time `json:"created_at"`
}

type revocationFile struct {
	FormatVersion int              `json:"format_version"`
	Clusters      []revokedCluster `json:"clusters"`
}

func loadRevocations(directory string) ([]revokedCluster, error) {
	contents, err := os.ReadFile(filepath.Join(directory, revocationsFileName))
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read destroyed cluster records: %w", err)
	}
	var stored revocationFile
	if err := json.Unmarshal(contents, &stored); err != nil {
		return nil, fmt.Errorf("decode destroyed cluster records: %w", err)
	}
	if stored.FormatVersion != revocationsVersion || len(stored.Clusters) > maximumRevocations {
		return nil, errors.New("destroyed cluster records are invalid or unsupported")
	}
	for _, cluster := range stored.Clusters {
		if !validID(cluster.ClusterID) || cluster.StatusKey == "" || cluster.CreatedAt.IsZero() || len(cluster.NodeIDs) == 0 {
			return nil, errors.New("destroyed cluster record is invalid")
		}
		for _, nodeID := range cluster.NodeIDs {
			if !validID(nodeID) {
				return nil, errors.New("destroyed cluster record contains an invalid node ID")
			}
		}
	}
	return stored.Clusters, nil
}

func writeRevocations(directory string, clusters []revokedCluster) error {
	contents, err := json.MarshalIndent(revocationFile{FormatVersion: revocationsVersion, Clusters: clusters}, "", "  ")
	if err != nil {
		return fmt.Errorf("encode destroyed cluster records: %w", err)
	}
	contents = append(contents, '\n')
	temporary, err := os.CreateTemp(directory, ".revoked-clusters-*.json")
	if err != nil {
		return fmt.Errorf("create temporary destroyed cluster records: %w", err)
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if err := temporary.Chmod(0o600); err != nil {
		temporary.Close()
		return fmt.Errorf("secure temporary destroyed cluster records: %w", err)
	}
	if _, err := temporary.Write(contents); err != nil {
		temporary.Close()
		return fmt.Errorf("write temporary destroyed cluster records: %w", err)
	}
	if err := temporary.Sync(); err != nil {
		temporary.Close()
		return fmt.Errorf("sync temporary destroyed cluster records: %w", err)
	}
	if err := temporary.Close(); err != nil {
		return fmt.Errorf("close temporary destroyed cluster records: %w", err)
	}
	if err := os.Rename(temporaryPath, filepath.Join(directory, revocationsFileName)); err != nil {
		return fmt.Errorf("replace destroyed cluster records: %w", err)
	}
	return syncDirectory(directory)
}

// recordClusterRevocation requires service.mu to be held by the caller.
func (service *Service) recordClusterRevocation(active *manifest) error {
	nodeIDs := make([]string, 0, len(active.Nodes)-1)
	for _, node := range active.Nodes {
		if node.ID != service.nodeID {
			nodeIDs = append(nodeIDs, node.ID)
		}
	}
	if len(nodeIDs) == 0 {
		return nil
	}
	candidate := slices.DeleteFunc(slices.Clone(service.revocations), func(stored revokedCluster) bool {
		return stored.ClusterID == active.ClusterID
	})
	candidate = append(candidate, revokedCluster{
		ClusterID: active.ClusterID,
		StatusKey: active.StatusKey,
		NodeIDs:   nodeIDs,
		CreatedAt: service.clock(),
	})
	if len(candidate) > maximumRevocations {
		candidate = slices.Clone(candidate[len(candidate)-maximumRevocations:])
	}
	if err := writeRevocations(service.directory, candidate); err != nil {
		return err
	}
	service.revocations = candidate
	return nil
}

// heartbeatRevoked requires service.mu to be held by the caller.
func (service *Service) heartbeatRevoked(heartbeat Heartbeat, signature string) bool {
	for _, destroyed := range service.revocations {
		if slices.Contains(destroyed.NodeIDs, heartbeat.NodeID) && validHeartbeatSignature(destroyed.StatusKey, heartbeat, signature) {
			return true
		}
	}
	return false
}
