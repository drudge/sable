//go:build faultinject

package faultinject

import (
	"os"
	"path/filepath"
	"testing"
)

// UseFaults points the hooks at a fresh control file holding faults, makes
// every read see the file at once, and puts both back when the test ends.
// It returns a function that rewrites the file. Tests that call it change
// process-wide state, so they must not run in parallel.
func UseFaults(t testing.TB, faults Faults) func(Faults) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "faults.json")
	write := func(faults Faults) {
		t.Helper()
		if err := WriteControlFile(path, faults); err != nil {
			t.Fatal(err)
		}
	}
	write(faults)
	interval := RefreshInterval
	RefreshInterval = 0
	SetControlFile(path)
	t.Cleanup(func() {
		RefreshInterval = interval
		SetControlFile(os.Getenv(ControlEnv))
	})
	return write
}
