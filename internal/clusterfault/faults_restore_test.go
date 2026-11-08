//go:build integration

package clusterfault

import (
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"testing"

	"github.com/drudge/sable/internal/clustertest"
)

// backupPassphrase seals every backup the harness takes.
const backupPassphrase = "cluster-fault-harness"

// TestPrimaryRestoreFromBackupBringsTheClusterBack backs up the primary,
// takes more writes, and restores the backup onto the primary, as
// docs/backup.md says to: every node must come back into line with the
// restored state and lose the later writes, and the cluster must take new
// writes afterwards. Serials across the restore are #590's test, so the
// recovered cluster is checked on its own.
func TestPrimaryRestoreFromBackupBringsTheClusterBack(t *testing.T) {
	faults, _, records, undone := restorePrimaryFromBackup(t)
	requireConvergedWithin(t, faults, records, clustertest.Timeout)
	checks := newInvariants()
	writeAndObserve(t, faults, checks, records, 2)
	checks.converged(t, faults, records)
	for _, entry := range undone {
		requireAbsent(t, faults, entry.name)
	}
}

// TestPrimaryRestoreKeepsSOASerialsMonotonic restores an older backup onto
// the primary. The zone's content goes back, but its SOA serial must not:
// a secondary only transfers a zone whose serial is greater than the one it
// holds (RFC 1034 §4.3.5, RFC 1982 §3.2), so a serial that goes back strands
// every secondary, and the next write reuses a serial already served for
// other content.
func TestPrimaryRestoreKeepsSOASerialsMonotonic(t *testing.T) {
	knownBug(t, "drudge/sable#590")
	faults, checks, records, _ := restorePrimaryFromBackup(t)
	writeAndObserve(t, faults, checks, records, 2)
	checks.converged(t, faults, records)
}

// restorePrimaryFromBackup backs up the primary after three writes, makes
// three more, then stops the primary, restores the backup onto it, and
// starts it again. The ledger is put back to the backup; the later writes
// come back as undone.
func restorePrimaryFromBackup(t *testing.T) (*faultCluster, *invariants, *ledger, []write) {
	t.Helper()
	faults := startCluster(t, 3)
	checks, records := newInvariants(), &ledger{}
	writeAndObserve(t, faults, checks, records, 3)
	checks.converged(t, faults, records)
	primary := faults.members[0]
	archive := primary.backup(t)
	restored := slices.Clone(records.acknowledged)
	writeAndObserve(t, faults, checks, records, 3)
	checks.converged(t, faults, records)
	undone := slices.Clone(records.acknowledged[len(restored):])
	primary.stop(t)
	primary.restore(t, archive)
	primary.start(t)
	records.acknowledged = restored
	return faults, checks, records, undone
}

// backup writes a backup of the member with the sable CLI and returns its
// path. The node keeps running, as it would under a scheduled backup.
func (node *member) backup(t *testing.T) string {
	t.Helper()
	archive := filepath.Join(t.TempDir(), node.name+".sablebackup")
	node.runCLI(t, "backup", "create", "--config", node.configuration, "--out", archive)
	return archive
}

// restore restores archive onto the stopped member with the sable CLI,
// keeping its configuration.
func (node *member) restore(t *testing.T, archive string) {
	t.Helper()
	node.runCLI(t, "backup", "restore", "--config", node.configuration, "--keep-config", archive)
}

func (node *member) runCLI(t *testing.T, arguments ...string) {
	t.Helper()
	command := exec.Command(faultBinary, arguments...)
	command.Env = append(os.Environ(), "SABLE_BACKUP_PASSPHRASE="+backupPassphrase)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("sable %v: %v\n%s", arguments[:2], err, output)
	}
}
