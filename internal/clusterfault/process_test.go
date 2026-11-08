//go:build integration

package clusterfault

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/drudge/sable/internal/clustertest"
)

// faultBinary is the Sable binary every member runs: built once per test run
// with the faultinject tag, so each node reads its own fault control file.
// Faults are process-wide state in Sable, so in-process nodes can't hold
// different ones.
var faultBinary string

// faultRefresh is how long a node may take to see a new control file. Sable
// re-reads it at most every 250ms (faultinject.RefreshInterval).
const faultRefresh = 500 * time.Millisecond

func TestMain(m *testing.M) {
	os.Exit(runWithFaultBinary(m))
}

func runWithFaultBinary(m *testing.M) int {
	directory, err := os.MkdirTemp("", "sable-clusterfault-")
	if err != nil {
		fmt.Fprintln(os.Stderr, "create build directory:", err)
		return 1
	}
	defer os.RemoveAll(directory)
	faultBinary = filepath.Join(directory, "sable")
	build := exec.Command("go", "build", "-tags=faultinject", "-o", faultBinary, "github.com/drudge/sable/cmd/sable")
	build.Env = append(os.Environ(), "GOEXPERIMENT=jsonv2", "CGO_ENABLED=0")
	build.Stdout, build.Stderr = os.Stderr, os.Stderr
	if err := build.Run(); err != nil {
		fmt.Fprintln(os.Stderr, "build faultinject Sable:", err)
		return 1
	}
	return m.Run()
}

// faults is what a member's control file asks for, in the JSON shape the
// faultinject package documents.
type faults struct {
	ClockOffset time.Duration
	DiskFull    bool
}

func (node *member) controlFile() string { return filepath.Join(node.directory, "faults.json") }

// setFaults replaces the member's faults and waits until the node has had
// time to read them.
func (node *member) setFaults(t *testing.T, wanted faults) {
	t.Helper()
	contents, err := json.Marshal(map[string]any{
		"clock_offset": wanted.ClockOffset.String(), "disk_full": wanted.DiskFull,
	})
	if err != nil {
		t.Fatal(err)
	}
	temporary := node.controlFile() + ".tmp"
	if err := os.WriteFile(temporary, contents, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(temporary, node.controlFile()); err != nil {
		t.Fatal(err)
	}
	time.Sleep(faultRefresh)
}

// kill ends the member with SIGKILL: no shutdown, no final writes.
func (node *member) kill(t *testing.T) {
	t.Helper()
	node.client.CloseIdleConnections()
	clustertest.KillNode(t, node.node)
	node.node = nil
}
