//go:build integration

package clusterfault

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/drudge/sable/internal/cluster"
	"github.com/drudge/sable/internal/clustertest"
	"github.com/drudge/sable/internal/config"
	"github.com/drudge/sable/internal/updatefeed"
)

// The rolling update runs each member from updateFrom to updateTo: two
// faultinject builds of this source that differ only in the release they
// report. The updatedemo tag points their update checks at a local feed.
const (
	updateFrom = "1.0.1"
	updateTo   = "1.0.2"
	// rolloutTimeout bounds one rolling update of the whole cluster.
	rolloutTimeout = 3 * time.Minute
)

var updateBuilds struct {
	once     sync.Once
	from, to string
	err      error
}

// TestRollingUpdateRestartsEachMemberOncePrimaryLast runs a real rolling
// update with no writes in flight: replicas one at a time, the primary last.
// Some member must answer for the ledger zone throughout, no SOA serial may
// go backward, and every member must restart once into the new release.
func TestRollingUpdateRestartsEachMemberOncePrimaryLast(t *testing.T) {
	faults, checks, records := rollingUpdate(t, 0)
	writeAndObserve(t, faults, checks, records, 2)
	checks.converged(t, faults, records)
}

// TestRollingUpdateUnderWritesLosesNothing runs the same rolling update
// while the primary takes a write a second, a steady load for an API- or
// DHCP-driven cluster. The rollout must finish and no acknowledged write may
// be lost.
func TestRollingUpdateUnderWritesLosesNothing(t *testing.T) {
	faults, checks, records := rollingUpdate(t, time.Second)
	checks.converged(t, faults, records)
}

// rollingUpdate starts an updatable cluster, writes to it, rolls it to
// updateTo while writing every writeEvery (never, when zero), and checks
// that each member restarted once, the primary last, into updateTo.
func rollingUpdate(t *testing.T, writeEvery time.Duration) (*faultCluster, *invariants, *ledger) {
	t.Helper()
	faults, restarts := startUpdatableCluster(t)
	checks, records := newInvariants(), &ledger{}
	writeAndObserve(t, faults, checks, records, 2)
	checks.converged(t, faults, records)
	primary := faults.members[0]
	startRollout(t, primary)
	watchRollout(t, faults, primary, checks, records, writeEvery)
	checks.converged(t, faults, records)
	order := restarts()
	if len(order) != len(faults.members) || order[len(order)-1] != primary.name {
		t.Fatalf("restart order = %v, want each member once and %s last", order, primary.name)
	}
	for _, node := range primary.state(t).Nodes {
		if strings.TrimPrefix(node.Version, "v") != updateTo {
			t.Errorf("%s runs %q after the rollout, want %s", node.Name, node.Version, updateTo)
		}
	}
	return faults, checks, records
}

// startUpdatableCluster starts three members on their own copy of the
// updateFrom build, offers updateTo from a local feed, and supervises each
// member like Sable's installed service. restarts reports the members in
// the order they restarted into an update.
func startUpdatableCluster(t *testing.T) (faults *faultCluster, restarts func() []string) {
	t.Helper()
	from, to := updateBinaries(t)
	feed, err := updatefeed.Start(updatefeed.Release{
		Version: updateTo, Binary: to, Directory: t.TempDir(), Notes: "Cluster fault harness build.",
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(feed.Close)
	var mu sync.Mutex
	var order []string
	faults = startClusterWith(t, 3, func(node *member, configuration *config.Config) {
		node.binary = installBinary(t, from, node.directory)
		node.environment = []string{
			"SABLE_DEMO_RELEASE_API=" + feed.URL, "SABLE_UPDATE_BINARY_PATH=" + node.binary,
			"SABLE_GITHUB_TOKEN=", "GITHUB_TOKEN=",
		}
		node.restarted = func() {
			mu.Lock()
			defer mu.Unlock()
			order = append(order, node.name)
		}
		configuration.Updates.RestartManaged = true
	})
	return faults, func() []string {
		mu.Lock()
		defer mu.Unlock()
		return slices.Clone(order)
	}
}

// updateBinaries builds the updateFrom and updateTo binaries once per run.
func updateBinaries(t *testing.T) (from, to string) {
	t.Helper()
	updateBuilds.once.Do(func() {
		directory := filepath.Dir(faultBinary)
		updateBuilds.from = filepath.Join(directory, updateFrom, "sable")
		updateBuilds.to = filepath.Join(directory, updateTo, "sable")
		if updateBuilds.err = buildRelease(updateFrom, updateBuilds.from); updateBuilds.err == nil {
			updateBuilds.err = buildRelease(updateTo, updateBuilds.to)
		}
	})
	if updateBuilds.err != nil {
		t.Fatal(updateBuilds.err)
	}
	return updateBuilds.from, updateBuilds.to
}

func buildRelease(release, output string) error {
	var log bytes.Buffer
	err := updatefeed.Build(context.Background(), updatefeed.BuildOptions{
		Output: output, Release: release, Commit: "clusterfault", Tags: "faultinject,updatedemo", Log: &log,
	})
	if err != nil {
		return fmt.Errorf("%w\n%s", err, log.String())
	}
	return nil
}

// installBinary copies binary into the member's directory, since an update
// replaces the file its member runs.
func installBinary(t *testing.T, binary, directory string) string {
	t.Helper()
	contents, err := os.ReadFile(binary)
	if err != nil {
		t.Fatal(err)
	}
	installed := filepath.Join(directory, "bin", "sable")
	if err := os.MkdirAll(filepath.Dir(installed), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(installed, contents, 0o755); err != nil {
		t.Fatal(err)
	}
	return installed
}

// startRollout checks for updates on the primary and starts a rolling
// update to updateTo, retrying while the check is still settling.
func startRollout(t *testing.T, primary *member) {
	t.Helper()
	if status, err := primary.postForm("/ui/updates/check", nil); err != nil || status != http.StatusOK {
		t.Fatalf("check for updates = %d: %v", status, err)
	}
	clustertest.WaitForCondition(t, primary.node, func() bool {
		status, err := primary.postForm("/ui/updates/cluster", url.Values{"version": {updateTo}})
		return err == nil && status == http.StatusOK
	})
}

// watchRollout follows the rollout until it completes, writing through the
// primary every writeEvery (never, when zero) and checking every member's
// SOA serial each round. A write the restarting primary refuses isn't
// acknowledged, so it's allowed; a round in which no member answers for the
// ledger zone is an outage and fails.
func watchRollout(t *testing.T, faults *faultCluster, primary *member, checks *invariants, records *ledger, writeEvery time.Duration) {
	t.Helper()
	path := filepath.Join(primary.directory, "data", "cluster", "update-rollout.json")
	deadline := time.Now().Add(rolloutTimeout)
	var lastWrite time.Time
	for time.Now().Before(deadline) {
		status := readRollout(t, path)
		switch status.Phase {
		case cluster.RolloutComplete:
			return
		case cluster.RolloutFailed, cluster.RolloutStopped:
			t.Fatalf("rollout %s: %s", status.Phase, status.Error)
		}
		if writeEvery > 0 && time.Since(lastWrite) >= writeEvery {
			records.write(primary)
			lastWrite = time.Now()
		}
		served := 0
		for _, node := range faults.members {
			if checks.observeSerial(t, node) {
				served++
			}
		}
		if served == 0 {
			t.Errorf("no member answered for %s during the rollout (%s)", ledgerZone, status.Phase)
		}
		time.Sleep(clustertest.PollingInterval)
	}
	t.Fatalf("rollout did not complete within %s: %+v", rolloutTimeout, readRollout(t, path))
}

func readRollout(t *testing.T, path string) cluster.RolloutStatus {
	t.Helper()
	var status cluster.RolloutStatus
	contents, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return status
	}
	if err == nil {
		err = json.Unmarshal(contents, &status)
	}
	if err != nil {
		t.Fatalf("read rollout status: %v", err)
	}
	return status
}
