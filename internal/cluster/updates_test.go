package cluster

import (
	"context"
	"errors"
	"net/http"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/drudge/sable/internal/update"
	"github.com/drudge/sable/internal/version"
)

type rolloutTestUpdater struct {
	status      update.Status
	reserved    string
	installs    []string
	blocked     error
	failInstall bool
}

func (updater *rolloutTestUpdater) Status() update.Status { return updater.status }
func (updater *rolloutTestUpdater) Installable() error    { return updater.blocked }
func (updater *rolloutTestUpdater) ServiceManaged() bool  { return true }
func (updater *rolloutTestUpdater) Reserve(id string) error {
	if updater.blocked != nil {
		return updater.blocked
	}
	if updater.reserved != "" && updater.reserved != id {
		return update.ErrUpdateInProgress
	}
	updater.reserved = id
	return nil
}
func (updater *rolloutTestUpdater) Release(id string) {
	if updater.reserved == id {
		updater.reserved = ""
	}
}
func (updater *rolloutTestUpdater) InstallVersion(id, target string) error {
	if updater.reserved != id {
		return errors.New("not reserved")
	}
	updater.installs = append(updater.installs, target)
	if updater.failInstall {
		updater.status = update.Status{Phase: update.PhaseFailed, Error: "checksum mismatch"}
		return nil
	}
	updater.status = update.Status{Phase: update.PhaseInstalled, Installed: true, LatestVersion: strings.TrimPrefix(target, "v")}
	return nil
}

type rolloutFixture struct {
	nodes    []*Service
	updaters []*rolloutTestUpdater
	restarts []string
	pending  map[int]bool
}

func newRolloutFixture(t *testing.T, replicas int) *rolloutFixture {
	t.Helper()
	primary, replica := joinedClusterServices(t)
	fixture := &rolloutFixture{nodes: []*Service{primary, replica}, pending: make(map[int]bool)}
	for i := 1; i < replicas; i++ {
		token, err := primary.CreateEnrollmentToken(context.Background(), time.Minute)
		if err != nil {
			t.Fatal(err)
		}
		node, err := Open(Options{DataDirectory: t.TempDir(), NodeName: "dns-3", AdvertiseURL: "https://dns-3.example:5380", HTTPClient: &http.Client{Transport: serviceRoundTripper{primary: primary}}})
		if err != nil {
			t.Fatal(err)
		}
		if err := node.Join(context.Background(), JoinOptions{PrimaryURL: primary.advertiseURL, Token: token.Token, Addresses: []string{"192.0.2.3"}}); err != nil {
			t.Fatal(err)
		}
		fixture.nodes = append(fixture.nodes, node)
	}
	for i, node := range fixture.nodes {
		node.version = "1.0.0"
		fixture.updaters = append(fixture.updaters, &rolloutTestUpdater{})
		fixture.configure(t, i)
	}
	for range 4 {
		fixture.tick(t)
	}
	return fixture
}

func (fixture *rolloutFixture) configure(t *testing.T, index int) {
	t.Helper()
	node := fixture.nodes[index]
	if err := node.SetUpdateController(fixture.updaters[index], func() {
		fixture.restarts = append(fixture.restarts, node.nodeID)
		fixture.pending[index] = true
	}); err != nil {
		t.Fatal(err)
	}
}

func (fixture *rolloutFixture) tick(t *testing.T) {
	t.Helper()
	ctx := context.Background()
	for i, node := range fixture.nodes {
		if fixture.pending[i] {
			continue
		}
		if err := node.syncFromPrimary(ctx); err != nil {
			t.Fatal(err)
		}
		node.advanceUpdates(ctx)
	}
}

func (fixture *rolloutFixture) restart(t *testing.T, index int, release string) {
	t.Helper()
	node := fixture.nodes[index]
	node.version, node.startedAt = release, time.Now()
	fixture.updaters[index] = &rolloutTestUpdater{}
	fixture.configure(t, index)
	delete(fixture.pending, index)
}

func TestRollingUpdateRestartsReplicasOneAtATimeAndPrimaryLast(t *testing.T) {
	fixture := newRolloutFixture(t, 2)
	primary := fixture.nodes[0]
	if err := primary.StartRollout(context.Background(), "1.1.0"); err != nil {
		t.Fatal(err)
	}
	if err := primary.StartRollout(context.Background(), "1.2.0"); err == nil {
		t.Fatal("concurrent rollout accepted")
	}
	for range 15 {
		fixture.tick(t)
	}
	if !slices.Equal(fixture.restarts, []string{fixture.nodes[1].nodeID}) {
		t.Fatalf("restarts before first recovery = %v, rollout = %+v", fixture.restarts, primary.RolloutStatus())
	}
	if len(fixture.updaters[2].installs) != 0 || len(fixture.updaters[0].installs) != 0 {
		t.Fatal("another node installed before the first recovered")
	}
	fixture.restart(t, 1, "1.1.0")
	for range 15 {
		fixture.tick(t)
	}
	if !slices.Equal(fixture.restarts, []string{fixture.nodes[1].nodeID, fixture.nodes[2].nodeID}) {
		t.Fatalf("restarts = %v, rollout = %+v", fixture.restarts, primary.RolloutStatus())
	}
	fixture.restart(t, 2, "1.1.0")
	for range 15 {
		fixture.tick(t)
	}
	if !slices.Equal(fixture.restarts, []string{fixture.nodes[1].nodeID, fixture.nodes[2].nodeID, primary.nodeID}) {
		t.Fatalf("restarts = %v, rollout = %+v", fixture.restarts, primary.RolloutStatus())
	}
	if primary.RolloutStatus().Phase != "restarting" {
		t.Fatal("primary restart not persisted")
	}
	fixture.restart(t, 0, "1.1.0")
	for range 10 {
		fixture.tick(t)
	}
	if primary.RolloutStatus().Phase != "complete" {
		t.Fatalf("rollout = %+v", primary.RolloutStatus())
	}
	for _, updater := range fixture.updaters {
		if updater.reserved != "" {
			t.Fatal("reservation was not released")
		}
	}
}

func TestRollingUpdateStopsOnInstallationFailure(t *testing.T) {
	fixture := newRolloutFixture(t, 2)
	fixture.updaters[1].failInstall = true
	primary := fixture.nodes[0]
	if err := primary.StartRollout(context.Background(), "1.1.0"); err != nil {
		t.Fatal(err)
	}
	for range 15 {
		fixture.tick(t)
	}
	if status := primary.RolloutStatus(); status.Phase != "failed" || !strings.Contains(status.Error, "checksum mismatch") {
		t.Fatalf("status = %+v", status)
	}
	if len(fixture.restarts) != 0 || len(fixture.updaters[2].installs) != 0 || len(fixture.updaters[0].installs) != 0 {
		t.Fatal("failure did not stop the rollout")
	}
}

func TestRollingUpdateRejectsUnsupportedBlockedUnhealthyAndNewerNodes(t *testing.T) {
	for _, scenario := range []string{"unsupported", "blocked", "offline", "behind", "newer", "replica", "single"} {
		t.Run(scenario, func(t *testing.T) {
			fixture := newRolloutFixture(t, 1)
			primary, replica := fixture.nodes[0], fixture.nodes[1]
			observed := primary.telemetry[replica.nodeID]
			switch scenario {
			case "unsupported":
				observed.heartbeat.Update = nil
			case "blocked":
				observed.heartbeat.Update.Blocked = "read-only binary"
			case "offline":
				observed.received = time.Now().Add(-time.Minute)
			case "behind":
				observed.heartbeat.AppliedGeneration = 0
			case "newer":
				observed.heartbeat.Version = "2.0.0"
				primary.manifest.Nodes[slices.IndexFunc(primary.manifest.Nodes, func(node member) bool { return node.ID == replica.nodeID })].Version = "2.0.0"
			case "replica":
				primary = replica
			case "single":
				primary.manifest.Nodes = slices.DeleteFunc(primary.manifest.Nodes, func(node member) bool { return node.ID != primary.nodeID })
			}
			if scenario != "replica" {
				primary.telemetry[replica.nodeID] = observed
			}
			if err := primary.StartRollout(context.Background(), "1.1.0"); err == nil {
				t.Fatal("unsafe rollout accepted")
			}
			if len(fixture.restarts) > 0 {
				t.Fatal("preflight restarted a node")
			}
		})
	}
}

func TestRollingUpdatesSupportedRequiresEveryMemberCapability(t *testing.T) {
	for _, scenario := range []string{"supported", "restart", "unknown", "legacy", "unsupported", "blocked", "local blocked", "local unsupported", "unconfigured", "single", "replica"} {
		t.Run(scenario, func(t *testing.T) {
			fixture := newRolloutFixture(t, 2)
			primary, replica := fixture.nodes[0], fixture.nodes[2]
			observed := primary.telemetry[replica.nodeID]
			switch scenario {
			case "restart":
				observed.received = time.Now().Add(-time.Minute)
			case "unknown":
				observed = nodeTelemetry{}
			case "legacy":
				observed.heartbeat.Update = nil
			case "unsupported":
				observed.heartbeat.Update.Supported = false
			case "blocked":
				observed.heartbeat.Update.Blocked = "automatic restart unavailable"
			case "local blocked":
				primary.updates.local.Blocked = "read-only binary"
			case "local unsupported":
				primary.updates = nil
			case "unconfigured":
				primary.manifest = nil
			case "single":
				primary.manifest.Nodes = slices.DeleteFunc(primary.manifest.Nodes, func(node member) bool { return node.ID != primary.nodeID })
			case "replica":
				primary = replica
			}
			primary.telemetry[replica.nodeID] = observed
			want := scenario == "supported" || scenario == "restart"
			if reason := primary.RollingUpdatesUnavailableReason(); (reason == "") != want {
				t.Fatalf("support and reason disagree: %q", reason)
			}
			if scenario == "blocked" && !strings.Contains(primary.RollingUpdatesUnavailableReason(), "automatic restart unavailable") {
				t.Fatal("node restriction was lost")
			}
			if got := primary.RollingUpdatesSupported(); got != want {
				t.Fatalf("RollingUpdatesSupported() = %t, want %t", got, want)
			}
		})
	}
}

func TestRollingUpdatesHonorContainerWebUpdateOptIn(t *testing.T) {
	// Model a Docker replica without systemd or an extra TOML restart setting.
	t.Setenv("PATH", t.TempDir())
	originalRelease := version.Release
	t.Cleanup(func() { version.Release = originalRelease })
	for _, test := range []struct {
		name           string
		enabled        string
		release        string
		restartManaged bool
		unwritable     bool
		want           bool
	}{
		{name: "unset", release: "1.1.0"},
		{name: "enabled", enabled: "true", release: "1.1.0", want: true},
		{name: "disabled", enabled: "false", release: "1.1.0"},
		{name: "invalid", enabled: "sometimes", release: "1.1.0"},
		{name: "external supervisor", release: "1.1.0", restartManaged: true, want: true},
		{name: "development build", enabled: "true", release: "dev"},
		{name: "unwritable binary", enabled: "true", release: "1.1.0", unwritable: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Setenv(update.ContainerWebUpdatesEnvironment, test.enabled)
			version.Release = test.release
			primary, replica := joinedClusterServices(t)
			if err := primary.SetUpdateController(&rolloutTestUpdater{}, func() {}); err != nil {
				t.Fatal(err)
			}
			binaryPath := filepath.Join(t.TempDir(), "sable")
			if test.unwritable {
				binaryPath = filepath.Join(binaryPath, "missing", "sable")
			}
			manager := update.NewManager(update.Options{BinaryPath: binaryPath, RestartManaged: test.restartManaged})
			if err := replica.SetUpdateController(manager, func() { t.Fatal("capability negotiation requested a restart") }); err != nil {
				t.Fatal(err)
			}
			for range 2 {
				if err := replica.syncFromPrimary(context.Background()); err != nil {
					t.Fatal(err)
				}
			}
			if got := primary.RollingUpdatesSupported(); got != test.want {
				t.Fatalf("rolling updates supported = %t, want %t; replica report: %+v", got, test.want, primary.telemetry[replica.nodeID].heartbeat.Update)
			}
		})
	}
}

func TestRollingUpdateStopAndTimeoutPreventFurtherRestarts(t *testing.T) {
	for _, scenario := range []string{"stop", "timeout", "coordinator restart"} {
		t.Run(scenario, func(t *testing.T) {
			fixture := newRolloutFixture(t, 1)
			primary := fixture.nodes[0]
			if err := primary.StartRollout(context.Background(), "1.1.0"); err != nil {
				t.Fatal(err)
			}
			fixture.tick(t)
			switch scenario {
			case "stop":
				if err := primary.StopRollout(); err != nil {
					t.Fatal(err)
				}
			case "timeout":
				primary.updates.rollout.Deadline = time.Now().Add(-time.Second)
			case "coordinator restart":
				fixture.restart(t, 0, "1.0.0")
			}
			for range 10 {
				fixture.tick(t)
			}
			if primary.RolloutStatus().Active() || len(fixture.restarts) != 0 {
				t.Fatalf("rollout continued: %+v", primary.RolloutStatus())
			}
		})
	}
}

func TestNewReplicaNegotiatesUpdateProtocolBeforeChangingSignedHeartbeat(t *testing.T) {
	primary, replica := joinedClusterServices(t)
	updater := &rolloutTestUpdater{}
	if err := replica.SetUpdateController(updater, func() {}); err != nil {
		t.Fatal(err)
	}
	for range 3 {
		if err := replica.syncFromPrimary(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	if primary.telemetry[replica.nodeID].heartbeat.Update != nil {
		t.Fatal("new fields sent before the primary advertises support")
	}
	if err := primary.SetUpdateController(&rolloutTestUpdater{}, func() {}); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if err := replica.syncFromPrimary(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	if primary.telemetry[replica.nodeID].heartbeat.Update == nil {
		t.Fatal("update protocol was not negotiated")
	}
}

func TestRolloutWaitsForExactVersionAndFreshSynchronization(t *testing.T) {
	fixture := newRolloutFixture(t, 2)
	primary := fixture.nodes[0]
	if err := primary.StartRollout(context.Background(), "1.1.0"); err != nil {
		t.Fatal(err)
	}
	for range 15 {
		fixture.tick(t)
	}
	// A restarted node on the old version is an explicit failure, not success.
	fixture.restart(t, 1, "1.0.0")
	for range 10 {
		fixture.tick(t)
	}
	if primary.RolloutStatus().Phase != "failed" || len(fixture.restarts) != 1 {
		t.Fatalf("wrong running version was accepted: %+v", primary.RolloutStatus())
	}
}

func TestRestartCommandIsWithheldWhenAnotherNodeLosesHealth(t *testing.T) {
	fixture := newRolloutFixture(t, 2)
	primary := fixture.nodes[0]
	if err := primary.StartRollout(context.Background(), "1.1.0"); err != nil {
		t.Fatal(err)
	}
	for range 12 {
		fixture.tick(t)
		if primary.RolloutStatus().Nodes[0].Phase == "restart" {
			break
		}
	}
	if primary.RolloutStatus().Nodes[0].Phase != "restart" {
		t.Fatal("fixture did not reach restart authorization")
	}
	other := fixture.nodes[2]
	observed := primary.telemetry[other.nodeID]
	observed.received = time.Now().Add(-time.Minute)
	primary.telemetry[other.nodeID] = observed
	if command := primary.updateCommand(fixture.nodes[1].nodeID); command != nil {
		t.Fatalf("restart authorized without another healthy node: %+v", command)
	}
}

func TestReplicaDiscardsRestartCommandAfterFailedSyncAndExpiresReservation(t *testing.T) {
	fixture := newRolloutFixture(t, 1)
	primary, replica := fixture.nodes[0], fixture.nodes[1]
	if err := primary.StartRollout(context.Background(), "1.1.0"); err != nil {
		t.Fatal(err)
	}
	for range 4 {
		fixture.tick(t)
	}
	replica.pendingUpdate = &UpdateCommand{ID: replica.updates.local.ID, ClusterID: replica.manifest.ClusterID, PrimaryID: primary.nodeID, Version: "v1.1.0", Action: "restart"}
	primary.manifest.StatusKey = "invalid-key"
	if err := replica.syncFromPrimary(context.Background()); err == nil {
		t.Fatal("invalid primary signature unexpectedly succeeded")
	}
	if replica.pendingUpdate != nil || replica.updatePrimaryID != "" {
		t.Fatal("failed sync retained an old command or protocol negotiation")
	}
	replica.updates.local.LastCommandAt = time.Now().Add(-rolloutNodeTimeout - time.Second)
	replica.advanceUpdates(context.Background())
	if replica.updates.local.ID != "" || fixture.updaters[1].reserved != "" || len(fixture.restarts) != 0 {
		t.Fatal("abandoned reservation was not released safely")
	}
}

func TestPrimaryReopensPersistedFinalRestartForVerification(t *testing.T) {
	fixture := newRolloutFixture(t, 1)
	primary := fixture.nodes[0]
	if err := primary.StartRollout(context.Background(), "1.1.0"); err != nil {
		t.Fatal(err)
	}
	for range 15 {
		fixture.tick(t)
	}
	fixture.restart(t, 1, "1.1.0")
	for range 15 {
		fixture.tick(t)
	}
	reopened, err := Open(Options{DataDirectory: primary.directory, NodeName: primary.nodeName, AdvertiseURL: primary.advertiseURL, Version: "1.1.0"})
	if err != nil {
		t.Fatal(err)
	}
	if err := reopened.SetUpdateController(&rolloutTestUpdater{}, func() { t.Fatal("reopened coordinator restarted before verification") }); err != nil {
		t.Fatal(err)
	}
	if status := reopened.RolloutStatus(); status.Phase != "verifying" || status.Version != "v1.1.0" {
		t.Fatalf("persisted rollout = %+v", status)
	}
	reopened.advanceUpdates(context.Background())
	if reopened.RolloutStatus().Phase != "verifying" {
		t.Fatal("completed before receiving fresh replica telemetry")
	}
}

func TestPrimaryHandoffMarksTheOldRolloutFailed(t *testing.T) {
	fixture := newRolloutFixture(t, 1)
	primary, replica := fixture.nodes[0], fixture.nodes[1]
	if err := primary.StartRollout(context.Background(), "1.1.0"); err != nil {
		t.Fatal(err)
	}
	for range 3 {
		fixture.tick(t)
	}
	if err := primary.Promote(context.Background(), replica.nodeID); err != nil {
		t.Fatal(err)
	}
	primary.advanceUpdates(context.Background())
	if status := primary.RolloutStatus(); status.Phase != "failed" {
		t.Fatalf("handoff left a live rollout: %+v", status)
	}
	if fixture.updaters[0].reserved != "" || len(fixture.restarts) != 0 {
		t.Fatal("handoff did not release the old primary safely")
	}
}
