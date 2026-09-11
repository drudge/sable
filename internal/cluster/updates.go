package cluster

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/drudge/sable/internal/update"
	"github.com/drudge/sable/internal/version"
	"golang.org/x/mod/semver"
)

const (
	rolloutFileName       = "update-rollout.json"
	nodeUpdateFileName    = "node-update.json"
	rolloutNodeTimeout    = 20 * time.Minute
	rolloutPrepareTimeout = time.Minute
	updateProtocolVersion = 1
)

// Persisted phases and wire actions are shared by both sides of a rollout.
const (
	rolloutPreparing = "preparing"
	rolloutUpdating  = "updating"
	rolloutVerifying = "verifying"
	updateRestarting = "restarting"
	updateComplete   = "complete"
	updateFailed     = "failed"
	rolloutStopped   = "stopped"
	updateQueued     = "queued"
	updatePrepared   = "prepared"
	updateInstalling = "installing"
	updateInstalled  = "installed"
	actionPrepare    = "prepare"
	actionInstall    = "install"
	actionRestart    = "restart"
	actionRelease    = "release"
)

type UpdateController interface {
	Status() update.Status
	Installable() error
	ServiceManaged() bool
	Reserve(string) error
	Release(string)
	InstallVersion(string, string) error
}

// UpdateCommand travels only over the existing authenticated primary sync connection.
type UpdateCommand struct {
	ID        string `json:"id"`
	ClusterID string `json:"cluster_id"`
	PrimaryID string `json:"primary_id"`
	Version   string `json:"version"`
	Action    string `json:"action"`
}

type NodeUpdateStatus struct {
	ClusterID     string    `json:"cluster_id,omitempty"`
	PrimaryID     string    `json:"primary_id,omitempty"`
	LastCommandAt time.Time `json:"last_command_at,omitzero"`
	Supported     bool      `json:"supported"`
	Blocked       string    `json:"blocked,omitempty"`
	ID            string    `json:"id,omitempty"`
	Version       string    `json:"version,omitempty"`
	Phase         string    `json:"phase,omitempty"`
	Error         string    `json:"error,omitempty"`
}

type RolloutNode struct {
	ID    string `json:"id"`
	Name  string `json:"name"`
	Phase string `json:"phase"`
}

type RolloutStatus struct {
	ID        string        `json:"id"`
	ClusterID string        `json:"cluster_id"`
	PrimaryID string        `json:"primary_id"`
	Version   string        `json:"version"`
	Phase     string        `json:"phase"`
	Error     string        `json:"error,omitempty"`
	Nodes     []RolloutNode `json:"nodes"`
	Index     int           `json:"index"`
	Deadline  time.Time     `json:"deadline"`
}

func (status RolloutStatus) Active() bool {
	return status.Phase == rolloutPreparing || status.Phase == rolloutUpdating || status.Phase == updateRestarting || status.Phase == rolloutVerifying
}

type clusterUpdates struct {
	mu         sync.Mutex
	controller UpdateController
	restart    func()
	local      NodeUpdateStatus
	rollout    RolloutStatus
}

// SetUpdateController restores progress before monitoring starts. Interrupted
// rollouts stop; only a primary that has reached its target may finish verification.
func (service *Service) SetUpdateController(controller UpdateController, restart func()) error {
	updates := &clusterUpdates{controller: controller, restart: restart, local: NodeUpdateStatus{Supported: true}}
	if err := controller.Installable(); err != nil {
		updates.local.Blocked = err.Error()
	}
	if !controller.ServiceManaged() || restart == nil {
		updates.local.Blocked = "Automatic restart requires an installed systemd service, SABLE_WEB_UPDATES=true for Docker, or updates.restart_managed=true with a working external supervisor."
	}
	configured := false
	defer func() {
		if !configured && updates.local.ID != "" {
			controller.Release(updates.local.ID)
		}
	}()
	capability := updates.local
	if err := readUpdateState(service.directory, nodeUpdateFileName, &updates.local); err != nil {
		return err
	}
	updates.local.Supported, updates.local.Blocked = capability.Supported, capability.Blocked
	if updates.local.ID != "" {
		if err := controller.Reserve(updates.local.ID); err != nil {
			updates.local.Blocked = err.Error()
		}
		if sameRelease(service.version, updates.local.Version) {
			updates.local.Phase, updates.local.Error = updateComplete, ""
		} else {
			updates.local.Phase, updates.local.Error = updateFailed, "Node restarted before its update completed. Review it before trying again."
		}
	}
	if err := readUpdateState(service.directory, rolloutFileName, &updates.rollout); err != nil {
		return err
	}
	if updates.rollout.Active() {
		if len(updates.rollout.Nodes) == 0 || updates.rollout.Index < 0 || updates.rollout.Index >= len(updates.rollout.Nodes) && updates.rollout.Phase != rolloutVerifying {
			return errors.New("saved rollout has invalid node progress")
		}
		if updates.rollout.Phase == updateRestarting && sameRelease(service.version, updates.rollout.Version) {
			updates.rollout.Phase = rolloutVerifying
			updates.rollout.Deadline = time.Now().Add(rolloutNodeTimeout)
		} else {
			updates.rollout.Phase, updates.rollout.Error = updateFailed, "The coordinator restarted. Review every node before starting another rollout."
		}
		if err := writeClusterJSON(service.directory, rolloutFileName, updates.rollout); err != nil {
			return err
		}
	}
	service.updates = updates
	configured = true
	return nil
}

func sameRelease(left, right string) bool {
	return strings.TrimPrefix(left, "v") == strings.TrimPrefix(right, "v")
}

func readUpdateState(directory, name string, destination any) error {
	contents, err := os.ReadFile(filepath.Join(directory, name))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if err := json.Unmarshal(contents, destination); err != nil {
		return fmt.Errorf("read %s: %w", name, err)
	}
	return nil
}

func (service *Service) RolloutStatus() RolloutStatus {
	if service.updates == nil {
		return RolloutStatus{}
	}
	service.updates.mu.Lock()
	defer service.updates.mu.Unlock()
	status := service.updates.rollout
	status.Nodes = slices.Clone(status.Nodes)
	return status
}

// RollingUpdatesSupported uses the last reported capability so a node's restart
// does not hide rollout progress. StartRollout separately requires fresh, healthy
// reports before any update can begin. Only the primary receives every report.
func (service *Service) RollingUpdatesSupported() bool {
	return service.RollingUpdatesUnavailableReason() == ""
}

// RollingUpdatesUnavailableReason explains the same capability gate used to start a rollout.
func (service *Service) RollingUpdatesUnavailableReason() string {
	if service.updates == nil {
		return "This installation does not support automatic updates and restarts."
	}
	service.updates.mu.Lock()
	defer service.updates.mu.Unlock()
	service.mu.RLock()
	defer service.mu.RUnlock()
	if service.manifest == nil {
		return "Initialize or join a cluster to use rolling updates."
	}
	if service.manifest.PrimaryID != service.nodeID {
		return "Start rolling updates from the cluster primary."
	}
	if len(service.manifest.Nodes) < 2 {
		return "Add a replica to use rolling updates."
	}
	for _, node := range service.manifest.Nodes {
		report := &service.updates.local
		if node.ID != service.nodeID {
			report = service.telemetry[node.ID].heartbeat.Update
		}
		if report == nil {
			return fmt.Sprintf("Waiting for update capability information from %s.", node.Name)
		}
		if report.Blocked != "" {
			return fmt.Sprintf("%s: %s", node.Name, report.Blocked)
		}
		if !report.Supported {
			return fmt.Sprintf("%s does not support automatic updates and restarts.", node.Name)
		}
	}
	return ""
}

func (service *Service) localUpdateStatus() *NodeUpdateStatus {
	if service.updates == nil {
		return nil
	}
	service.updates.mu.Lock()
	defer service.updates.mu.Unlock()
	status := service.updates.local
	if status.ID == "" && (service.updates.controller.Status().Busy() || service.updates.controller.Status().Installed) {
		status.Blocked = "A local update is already in progress."
	}
	return &status
}

func (service *Service) updateReports() map[string]NodeUpdateStatus {
	reports := map[string]NodeUpdateStatus{service.nodeID: service.updates.local}
	service.mu.RLock()
	defer service.mu.RUnlock()
	for id, observed := range service.telemetry {
		if observed.heartbeat.Update != nil && time.Since(observed.received) <= heartbeatFreshness {
			reports[id] = *observed.heartbeat.Update
		}
	}
	return reports
}

func (service *Service) StartRollout(_ context.Context, target string) error {
	if service.updates == nil {
		return errors.New("cluster updates are unavailable")
	}
	service.updates.mu.Lock()
	defer service.updates.mu.Unlock()
	if service.updates.rollout.Active() {
		return errors.New("a cluster update is already running")
	}
	state := service.Snapshot()
	if !state.Initialized || state.LocalRole != RolePrimary {
		return ErrNotPrimary
	}
	if len(state.Nodes) < 2 {
		return errors.New("rolling updates require at least two nodes")
	}
	target = "v" + strings.TrimPrefix(strings.TrimSpace(target), "v")
	if (version.Info{Release: target}).Development() {
		return errors.New("choose a published release version")
	}
	reports := service.updateReports()
	rollout := RolloutStatus{ClusterID: state.ClusterID, PrimaryID: state.PrimaryID, Version: target, Phase: rolloutPreparing, Deadline: time.Now().Add(rolloutPrepareTimeout)}
	needsUpdate := false
	for _, node := range state.Nodes {
		if !rolloutNodeHealthy(node) {
			return fmt.Errorf("%s must be online and fully synchronized", node.Name)
		}
		report := reports[node.ID]
		if !report.Supported {
			return fmt.Errorf("%s does not support rolling updates; update it manually first", node.Name)
		}
		if report.Blocked != "" {
			return fmt.Errorf("%s: %s", node.Name, report.Blocked)
		}
		if report.ID != "" {
			return fmt.Errorf("%s is still finishing a previous rollout; wait for it to release", node.Name)
		}
		current := "v" + strings.TrimPrefix(node.Version, "v")
		if (version.Info{Release: current}).Development() || semver.Compare(target, current) < 0 {
			return fmt.Errorf("%s cannot be rolled forward to %s", node.Name, target)
		}
		needsUpdate = needsUpdate || !sameRelease(current, target)
		if node.ID != state.PrimaryID {
			rollout.Nodes = append(rollout.Nodes, RolloutNode{ID: node.ID, Name: node.Name, Phase: updateQueued})
		}
	}
	if !needsUpdate {
		return errors.New("all nodes already run this release")
	}
	primary := state.Nodes[slices.IndexFunc(state.Nodes, func(node Node) bool { return node.ID == state.PrimaryID })]
	rollout.Nodes = append(rollout.Nodes, RolloutNode{ID: primary.ID, Name: primary.Name, Phase: updateQueued})
	id, err := newID()
	if err != nil {
		return err
	}
	rollout.ID = id
	if err := service.updates.controller.Reserve(id); err != nil {
		return err
	}
	if err := service.saveRollout(rollout); err != nil {
		service.updates.controller.Release(id)
		return err
	}
	return nil
}

func rolloutNodeHealthy(node Node) bool {
	return node.State == StateOnline && node.SyncState == SyncCurrent && node.AppliedGeneration == node.CurrentGeneration
}

func (service *Service) StopRollout() error {
	if service.updates == nil {
		return errors.New("cluster updates are unavailable")
	}
	service.updates.mu.Lock()
	defer service.updates.mu.Unlock()
	rollout := service.updates.rollout
	if !rollout.Active() {
		return nil
	}
	rollout.Phase, rollout.Error = rolloutStopped, "Stopped by an operator. An installation or restart already in progress may finish; no further nodes will restart."
	return service.saveRollout(rollout)
}

// saveRollout is called with updates.mu held, and persists before issuing commands.
func (service *Service) saveRollout(rollout RolloutStatus) error {
	if err := writeClusterJSON(service.directory, rolloutFileName, rollout); err != nil {
		service.updates.rollout.Phase, service.updates.rollout.Error = updateFailed, "Cannot persist rollout progress: "+err.Error()
		return err
	}
	service.updates.rollout = rollout
	return nil
}

func (service *Service) updateCommand(nodeID string) *UpdateCommand {
	if service.updates == nil {
		return nil
	}
	service.updates.mu.Lock()
	defer service.updates.mu.Unlock()
	return service.updateCommandLocked(nodeID)
}

func (service *Service) updateCommandLocked(nodeID string) *UpdateCommand {
	rollout := service.updates.rollout
	state := service.Snapshot()
	if rollout.ID == "" || state.ClusterID != rollout.ClusterID || state.PrimaryID != service.nodeID || !slices.ContainsFunc(rollout.Nodes, func(node RolloutNode) bool { return node.ID == nodeID }) {
		return nil
	}
	command := &UpdateCommand{ID: rollout.ID, ClusterID: rollout.ClusterID, PrimaryID: rollout.PrimaryID, Version: rollout.Version, Action: actionPrepare}
	if !rollout.Active() {
		command.Action = actionRelease
		return command
	}
	if rollout.Phase == rolloutUpdating && rollout.Index < len(rollout.Nodes) && rollout.Nodes[rollout.Index].ID == nodeID {
		command.Action = rollout.Nodes[rollout.Index].Phase
		if command.Action == updateQueued {
			command.Action = actionPrepare
		}
	}
	if command.Action == actionRestart {
		for _, peer := range state.Nodes {
			if peer.ID != nodeID && !rolloutNodeHealthy(peer) {
				return nil
			}
		}
	}
	return command
}

func (service *Service) advanceUpdates(ctx context.Context) {
	if service.updates == nil || ctx.Err() != nil {
		return
	}
	service.updates.mu.Lock()
	defer service.updates.mu.Unlock()
	state := service.Snapshot()
	if rollout := service.updates.rollout; rollout.Active() && (state.ClusterID != rollout.ClusterID || state.PrimaryID != rollout.PrimaryID) {
		rollout.Phase, rollout.Error = updateFailed, "Cluster membership or primary changed during the rollout."
		_ = service.saveRollout(rollout)
	}
	local := &service.updates.local
	if local.ID != "" && (local.ClusterID != state.ClusterID || local.PrimaryID != state.PrimaryID || time.Since(local.LastCommandAt) > rolloutNodeTimeout) {
		service.updates.controller.Release(local.ID)
		*local = NodeUpdateStatus{Supported: local.Supported, Blocked: local.Blocked}
		if err := os.Remove(filepath.Join(service.directory, nodeUpdateFileName)); err != nil && !errors.Is(err, os.ErrNotExist) {
			local.Blocked = err.Error()
		}
	}
	if state.LocalRole == RolePrimary {
		service.advanceRollout(state)
		service.applyUpdateCommand(service.updateCommandLocked(service.nodeID))
	} else {
		service.mu.RLock()
		command, fresh := service.pendingUpdate, time.Since(service.lastSuccessfulSync) <= heartbeatFreshness
		service.mu.RUnlock()
		if fresh {
			service.applyUpdateCommand(command)
		}
	}
}

func (service *Service) advanceRollout(state State) {
	rollout := service.updates.rollout
	if !rollout.Active() {
		return
	}
	fail := func(message string) {
		rollout.Phase, rollout.Error = updateFailed, message
		_ = service.saveRollout(rollout)
	}
	if rollout.ClusterID != state.ClusterID || rollout.PrimaryID != state.PrimaryID || len(rollout.Nodes) != len(state.Nodes) {
		fail("Cluster membership or primary changed during the rollout.")
		return
	}
	for _, planned := range rollout.Nodes {
		if !slices.ContainsFunc(state.Nodes, func(node Node) bool { return node.ID == planned.ID }) {
			fail("Cluster membership changed during the rollout.")
			return
		}
	}
	if time.Now().After(rollout.Deadline) {
		fail("Timed out waiting for a node. Review its version, health, and synchronization before retrying.")
		return
	}
	reports := service.updateReports()
	for _, node := range rollout.Nodes {
		report := reports[node.ID]
		if report.ID == rollout.ID && report.Error != "" {
			fail(node.Name + ": " + report.Error)
			return
		}
	}
	if rollout.Phase == rolloutPreparing {
		for _, node := range state.Nodes {
			report := reports[node.ID]
			if !rolloutNodeHealthy(node) {
				fail(node.Name + " lost health or synchronization during preparation.")
				return
			}
			if report.ID != rollout.ID || report.Phase != updatePrepared {
				return
			}
		}
		rollout.Phase, rollout.Deadline = rolloutUpdating, time.Now().Add(rolloutNodeTimeout)
		_ = service.saveRollout(rollout)
		return
	}
	if rollout.Phase == rolloutVerifying {
		for _, node := range state.Nodes {
			if !sameRelease(node.Version, rollout.Version) || !rolloutNodeHealthy(node) {
				return
			}
		}
		rollout.Phase = updateComplete
		for i := range rollout.Nodes {
			rollout.Nodes[i].Phase = updateComplete
		}
		_ = service.saveRollout(rollout)
		return
	}
	if rollout.Phase == updateRestarting {
		return
	}
	active := &rollout.Nodes[rollout.Index]
	node := state.Nodes[slices.IndexFunc(state.Nodes, func(node Node) bool { return node.ID == active.ID })]
	if sameRelease(node.Version, rollout.Version) && rolloutNodeHealthy(node) {
		active.Phase = updateComplete
		rollout.Index++
		rollout.Deadline = time.Now().Add(rolloutNodeTimeout)
		if rollout.Index == len(rollout.Nodes) {
			rollout.Phase = rolloutVerifying
		}
		_ = service.saveRollout(rollout)
		return
	}
	// Never authorize another restart while any other node is unavailable or behind.
	for _, peer := range state.Nodes {
		if peer.ID != active.ID && !rolloutNodeHealthy(peer) {
			return
		}
	}
	report := reports[active.ID]
	if report.ID != rollout.ID {
		return
	}
	if active.Phase == updateQueued && report.Phase == updatePrepared {
		active.Phase = actionInstall
		_ = service.saveRollout(rollout)
	} else if active.Phase == actionInstall && report.Phase == updateInstalled {
		active.Phase = actionRestart
		_ = service.saveRollout(rollout)
	}
}

func (service *Service) applyUpdateCommand(command *UpdateCommand) {
	if command == nil {
		return
	}
	state := service.Snapshot()
	if command.ClusterID != state.ClusterID || command.PrimaryID != state.PrimaryID {
		return
	}
	updates := service.updates
	local := &updates.local
	if command.Action == actionRelease {
		if local.ID == command.ID {
			updates.controller.Release(command.ID)
			*local = NodeUpdateStatus{Supported: local.Supported, Blocked: local.Blocked}
			if err := os.Remove(filepath.Join(service.directory, nodeUpdateFileName)); err != nil && !errors.Is(err, os.ErrNotExist) {
				local.Blocked = err.Error()
			}
		} else {
			updates.controller.Release(command.ID)
		}
		return
	}
	if local.ID != "" && local.ID != command.ID {
		return
	}
	if local.ID == "" {
		if command.Action != actionPrepare {
			return
		}
		local.ID, local.Version = command.ID, command.Version
		local.ClusterID, local.PrimaryID, local.LastCommandAt = command.ClusterID, command.PrimaryID, time.Now()
		if err := updates.controller.Reserve(command.ID); err != nil {
			local.Phase, local.Error = updateFailed, err.Error()
			return
		}
		local.Phase = updatePrepared
		if err := writeClusterJSON(service.directory, nodeUpdateFileName, local); err != nil {
			local.Phase, local.Error = updateFailed, err.Error()
		}
		return
	}
	if local.Version != command.Version || local.Error != "" {
		return
	}
	local.LastCommandAt = time.Now()
	switch command.Action {
	case actionInstall:
		if local.Phase == updatePrepared {
			local.Phase = updateInstalling
			if err := writeClusterJSON(service.directory, nodeUpdateFileName, local); err != nil {
				local.Phase, local.Error = updateFailed, err.Error()
				return
			}
			if err := updates.controller.InstallVersion(command.ID, command.Version); err != nil {
				local.Phase, local.Error = updateFailed, err.Error()
				return
			}
		}
		if local.Phase == updateInstalling {
			status := updates.controller.Status()
			if status.Error != "" {
				local.Phase, local.Error = updateFailed, status.Error
				return
			}
			if status.Installed && sameRelease(status.LatestVersion, command.Version) {
				local.Phase = updateInstalled
			}
		}
	case actionRestart:
		if local.Phase != updateInstalled {
			return
		}
		status := updates.controller.Status()
		if !status.Installed || !sameRelease(status.LatestVersion, command.Version) || !updates.controller.ServiceManaged() {
			local.Phase, local.Error = updateFailed, "The expected release is not installed or automatic restart is unavailable."
			return
		}
		local.Phase = updateRestarting
		if err := writeClusterJSON(service.directory, nodeUpdateFileName, local); err != nil {
			local.Phase, local.Error = updateFailed, err.Error()
			return
		}
		if state.LocalRole == RolePrimary {
			rollout := updates.rollout
			rollout.Phase = updateRestarting
			if err := service.saveRollout(rollout); err != nil {
				return
			}
		}
		updates.restart()
	}
}
