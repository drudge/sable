package cluster

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
)

const (
	stateSnapshotPrefix = "state-"
	stateSnapshotSuffix = ".snapshot"
)

// StateReplicator captures and applies the application state governed by the
// cluster. Implementations must keep node-local listener, storage, and secret
// bootstrap settings outside the snapshot.
type StateReplicator interface {
	Capture(context.Context) ([]byte, error)
	Apply(context.Context, []byte) error
}

func (service *Service) refreshPrimaryState(ctx context.Context) error {
	contents, digest, err := service.captureState(ctx)
	if err != nil {
		return err
	}
	service.mu.Lock()
	defer service.mu.Unlock()
	if service.manifest == nil {
		return ErrNotInitialized
	}
	if service.manifest.PrimaryID != service.nodeID {
		return nil
	}
	memberIndex := slices.IndexFunc(service.manifest.Nodes, func(node member) bool { return node.ID == service.nodeID })
	localAddresses := []string(nil)
	if memberIndex >= 0 {
		localAddresses = effectiveDNSAddresses(service.manifest.Nodes[memberIndex].Addresses, service.dnsListeners)
	}
	identityChanged := memberIndex >= 0 && (service.manifest.Nodes[memberIndex].Name != service.nodeName ||
		service.manifest.Nodes[memberIndex].AdvertiseURL != service.advertiseURL ||
		service.manifest.Nodes[memberIndex].TrustAnchor != string(service.localTrustAnchorPEM) ||
		service.manifest.Nodes[memberIndex].Version != service.version ||
		!slices.Equal(service.manifest.Nodes[memberIndex].Addresses, localAddresses))
	// The primary must always carry the primary role in its own entry. Nothing
	// else restores it, so heal a role that was flipped out from under us (for
	// example by an enrollment that claimed this node id) rather than leaving the
	// node blocked from its own control plane.
	roleChanged := memberIndex >= 0 && service.manifest.Nodes[memberIndex].Role != RolePrimary
	stateChanged := digest != "" && service.manifest.StateDigest != digest
	if !identityChanged && !stateChanged && !roleChanged {
		return nil
	}
	if stateChanged {
		if err := writeStateSnapshot(service.directory, digest, contents); err != nil {
			return err
		}
	}
	candidate := cloneManifest(service.manifest)
	candidate.Generation++
	candidate.UpdatedAt = service.clock()
	if stateChanged {
		candidate.StateDigest = digest
	}
	if identityChanged {
		candidate.Nodes[memberIndex].Name = service.nodeName
		candidate.Nodes[memberIndex].AdvertiseURL = service.advertiseURL
		candidate.Nodes[memberIndex].TrustAnchor = string(service.localTrustAnchorPEM)
		candidate.Nodes[memberIndex].Version = service.version
		candidate.Nodes[memberIndex].Addresses = localAddresses
	}
	if roleChanged {
		candidate.Nodes[memberIndex].Role = RolePrimary
	}
	if err := writeManifest(service.directory, candidate); err != nil {
		return err
	}
	service.manifest = candidate
	return cleanupStateSnapshots(service.directory, candidate.StateDigest)
}

func (service *Service) captureState(ctx context.Context) ([]byte, string, error) {
	if service.replicator == nil {
		return nil, "", nil
	}
	contents, err := service.replicator.Capture(ctx)
	if err != nil {
		return nil, "", fmt.Errorf("capture cluster state: %w", err)
	}
	digest := stateDigest(contents)
	return contents, digest, nil
}

func (service *Service) applyState(ctx context.Context, digest string, contents []byte) error {
	if digest == "" {
		return nil
	}
	if !validStateDigest(digest) || stateDigest(contents) != digest {
		return errors.New("cluster state snapshot digest is invalid")
	}
	if service.replicator == nil {
		return errors.New("cluster state replication is not configured")
	}
	if err := writeStateSnapshot(service.directory, digest, contents); err != nil {
		return err
	}
	if err := service.replicator.Apply(ctx, contents); err != nil {
		return fmt.Errorf("apply cluster state: %w", err)
	}
	return nil
}

func stateDigest(contents []byte) string {
	digest := sha256.Sum256(contents)
	return hex.EncodeToString(digest[:])
}

func validStateDigest(value string) bool {
	if len(value) != sha256.Size*2 {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}

func stateSnapshotPath(directory, digest string) string {
	return filepath.Join(directory, stateSnapshotPrefix+digest+stateSnapshotSuffix)
}

func writeStateSnapshot(directory, digest string, contents []byte) error {
	if !validStateDigest(digest) || stateDigest(contents) != digest {
		return errors.New("refuse to persist cluster state with an invalid digest")
	}
	path := stateSnapshotPath(directory, digest)
	if existing, err := os.ReadFile(path); err == nil {
		if stateDigest(existing) != digest {
			return errors.New("stored cluster state snapshot is corrupt")
		}
		return nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("read cluster state snapshot: %w", err)
	}
	temporary, err := os.CreateTemp(directory, ".state-*.snapshot")
	if err != nil {
		return fmt.Errorf("create temporary cluster state snapshot: %w", err)
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if err := temporary.Chmod(0o600); err != nil {
		temporary.Close()
		return fmt.Errorf("secure temporary cluster state snapshot: %w", err)
	}
	if _, err := temporary.Write(contents); err != nil {
		temporary.Close()
		return fmt.Errorf("write temporary cluster state snapshot: %w", err)
	}
	if err := temporary.Sync(); err != nil {
		temporary.Close()
		return fmt.Errorf("sync temporary cluster state snapshot: %w", err)
	}
	if err := temporary.Close(); err != nil {
		return fmt.Errorf("close temporary cluster state snapshot: %w", err)
	}
	if err := os.Rename(temporaryPath, path); err != nil {
		return fmt.Errorf("commit cluster state snapshot: %w", err)
	}
	return syncDirectory(directory)
}

func readStateSnapshot(directory, digest string) ([]byte, error) {
	if digest == "" {
		return nil, nil
	}
	if !validStateDigest(digest) {
		return nil, errors.New("cluster manifest contains an invalid state digest")
	}
	contents, err := os.ReadFile(stateSnapshotPath(directory, digest))
	if err != nil {
		return nil, fmt.Errorf("read cluster state snapshot: %w", err)
	}
	if stateDigest(contents) != digest {
		return nil, errors.New("cluster state snapshot does not match its manifest digest")
	}
	return contents, nil
}

func cleanupStateSnapshots(directory, keepDigest string) error {
	entries, err := os.ReadDir(directory)
	if err != nil {
		return fmt.Errorf("list cluster state snapshots: %w", err)
	}
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasPrefix(name, stateSnapshotPrefix) || !strings.HasSuffix(name, stateSnapshotSuffix) {
			continue
		}
		if name == stateSnapshotPrefix+keepDigest+stateSnapshotSuffix {
			continue
		}
		if err := os.Remove(filepath.Join(directory, name)); err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("remove obsolete cluster state snapshot: %w", err)
		}
	}
	return syncDirectory(directory)
}
