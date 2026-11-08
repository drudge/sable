//go:build integration

package clusterfault

import (
	"os"
	"testing"
)

// knownBugsEnv runs the tests for open bugs instead of skipping them, so a
// fix can be checked against its failing test.
const knownBugsEnv = "SABLE_CLUSTERFAULT_KNOWN_BUGS"

// knownBug skips a test that fails because of an open issue, unless
// knownBugsEnv is set to 1.
func knownBug(t *testing.T, issue string) {
	t.Helper()
	if os.Getenv(knownBugsEnv) != "1" {
		t.Skipf("fails until %s is fixed; set %s=1 to run it", issue, knownBugsEnv)
	}
}
