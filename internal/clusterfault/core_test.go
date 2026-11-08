//go:build integration

package clusterfault

import (
	"fmt"
	"testing"
)

// TestHarnessKeepsInvariantsWithoutFaults is the harness's own baseline: a
// healthy cluster takes writes, converges, and passes every invariant.
func TestHarnessKeepsInvariantsWithoutFaults(t *testing.T) {
	for _, size := range []int{3, 5} {
		t.Run(fmt.Sprintf("%d_nodes", size), func(t *testing.T) {
			faults := startCluster(t, size)
			checks, records := newInvariants(), &ledger{}
			for range 5 {
				records.mustWrite(t, faults)
				checks.observe(t, faults)
			}
			checks.converged(t, faults, records)
		})
	}
}

func TestSerialLessFollowsRFC1982(t *testing.T) {
	for _, test := range []struct {
		a, b uint32
		want bool
	}{
		{1, 2, true}, {2, 1, false}, {5, 5, false},
		{0xFFFFFFFF, 0, true}, {0, 0xFFFFFFFF, false},
		{2026110801, 2026110802, true},
	} {
		if got := serialLess(test.a, test.b); got != test.want {
			t.Errorf("serialLess(%d, %d) = %v, want %v", test.a, test.b, got, test.want)
		}
	}
}
