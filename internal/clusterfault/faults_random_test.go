//go:build integration

package clusterfault

import (
	"math/rand/v2"
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/drudge/sable/internal/cluster"
	"github.com/drudge/sable/internal/faultinject"
)

const (
	// seedEnv replays a randomized run: the seed picks the cluster size and
	// every step, so a failing seed reproduces the same schedule.
	seedEnv = "SABLE_CLUSTERFAULT_SEED"
	// stepsEnv sets how many faults a randomized run injects.
	stepsEnv     = "SABLE_CLUSTERFAULT_STEPS"
	defaultSteps = 6
)

// randomRun is one seeded randomized run against a real cluster.
type randomRun struct {
	t       *testing.T
	random  *rand.Rand
	faults  *faultCluster
	checks  *invariants
	records *ledger
}

// randomStep is one fault a randomized run can inject. A step that trips an
// open bug names its issue and only runs with knownBugsEnv set.
type randomStep struct {
	name  string
	issue string
	run   func(*randomRun)
}

var randomSteps = []randomStep{
	{name: "writes", run: (*randomRun).writes},
	{name: "replica kill and restart", run: (*randomRun).killReplica},
	{name: "replica clock skew", run: (*randomRun).skewReplica},
	{name: "replica disk full", run: (*randomRun).fillReplicaDisk},
	{name: "primary disk full", run: (*randomRun).fillPrimaryDisk},
	{name: "replica partition", run: (*randomRun).partitionReplica},
	{name: "primary failover", run: (*randomRun).failOver},
}

// TestRandomizedFaults starts a 3 to 5 node cluster and injects a seeded run
// of faults, holding every invariant after each step. It logs the seed, and
// seedEnv replays it.
func TestRandomizedFaults(t *testing.T) {
	seed := randomSeed(t)
	steps := stepCount(t)
	random := rand.New(rand.NewPCG(seed, seed))
	size := 3 + random.IntN(3)
	t.Logf("seed %d: %d nodes, %d steps", seed, size, steps)
	t.Cleanup(func() {
		if t.Failed() {
			t.Logf("replay with %s=%d %s=%d", seedEnv, seed, stepsEnv, steps)
		}
	})
	run := &randomRun{t: t, random: random, faults: startCluster(t, size), checks: newInvariants(), records: &ledger{}}
	run.writes()
	run.checks.converged(t, run.faults, run.records)
	choices := enabledSteps()
	for index := range steps {
		step := choices[random.IntN(len(choices))]
		t.Logf("step %d: %s", index+1, step.name)
		step.run(run)
		run.checks.converged(t, run.faults, run.records)
		if t.Failed() {
			t.Fatalf("invariants broke after step %d (%s)", index+1, step.name)
		}
	}
}

func randomSeed(t *testing.T) uint64 {
	t.Helper()
	text := os.Getenv(seedEnv)
	if text == "" {
		return uint64(time.Now().UnixNano())
	}
	seed, err := strconv.ParseUint(text, 10, 64)
	if err != nil {
		t.Fatalf("%s=%q is not a seed: %v", seedEnv, text, err)
	}
	return seed
}

func stepCount(t *testing.T) int {
	t.Helper()
	text := os.Getenv(stepsEnv)
	if text == "" {
		return defaultSteps
	}
	steps, err := strconv.Atoi(text)
	if err != nil || steps < 1 {
		t.Fatalf("%s=%q is not a positive step count", stepsEnv, text)
	}
	return steps
}

// enabledSteps leaves out steps that trip open bugs unless knownBugsEnv is
// set. A seed replays the same schedule only with the same setting.
func enabledSteps() []randomStep {
	if os.Getenv(knownBugsEnv) == "1" {
		return randomSteps
	}
	var enabled []randomStep
	for _, step := range randomSteps {
		if step.issue == "" {
			enabled = append(enabled, step)
		}
	}
	return enabled
}

// writes makes one to three acknowledged writes through the primary.
func (run *randomRun) writes() {
	writeAndObserve(run.t, run.faults, run.checks, run.records, 1+run.random.IntN(3))
}

// replica picks one running replica.
func (run *randomRun) replica() *member {
	var replicas []*member
	for _, node := range run.faults.running() {
		if node.state(run.t).LocalRole == cluster.RoleReplica {
			replicas = append(replicas, node)
		}
	}
	if len(replicas) == 0 {
		run.t.Fatal("no running replica")
	}
	return replicas[run.random.IntN(len(replicas))]
}

// during sets faults on node, writes, and clears them.
func (run *randomRun) during(node *member, faults faultinject.Faults) {
	node.setFaults(run.t, faults)
	run.writes()
	node.setFaults(run.t, faultinject.Faults{})
}

func (run *randomRun) killReplica() {
	node := run.replica()
	node.kill(run.t)
	run.writes()
	node.start(run.t)
}

func (run *randomRun) skewReplica() {
	offset := skew
	if run.random.IntN(2) == 0 {
		offset = -skew
	}
	run.during(run.replica(), faultinject.Faults{ClockOffset: offset})
}

func (run *randomRun) fillReplicaDisk() {
	run.during(run.replica(), faultinject.Faults{DiskFull: true})
}

// fillPrimaryDisk fills the primary's disk during writes. It may refuse them
// but must not acknowledge any it can't store.
func (run *randomRun) fillPrimaryDisk() {
	primary := run.faults.primary()
	primary.setFaults(run.t, faultinject.Faults{DiskFull: true})
	for range 1 + run.random.IntN(3) {
		if run.records.write(primary) {
			run.t.Errorf("primary acknowledged ledger write %d with a full disk", run.records.attempted)
		}
		run.checks.observe(run.t, run.faults)
	}
	primary.setFaults(run.t, faultinject.Faults{})
}

func (run *randomRun) partitionReplica() {
	heal := partition(run.t, run.faults, run.replica())
	run.writes()
	heal()
}

// failOver kills the converged primary, promotes a replica for recovery,
// writes, and restarts the old primary, which must step down. The run has
// converged before each step, so the replication window (#582) holds nothing.
func (run *randomRun) failOver() {
	old := run.faults.primary()
	term := old.state(run.t).Term
	successor := run.replica()
	old.kill(run.t)
	successor.promote(run.t)
	waitRole(run.t, successor, cluster.RolePrimary, term)
	run.writes()
	old.start(run.t)
	waitRole(run.t, old, cluster.RoleReplica, term)
}
