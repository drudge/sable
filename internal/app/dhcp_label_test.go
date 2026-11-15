package app

import (
	"testing"

	"github.com/drudge/sable/internal/dhcp"
)

// TestReview628LeaseRowCarriesTheNameItRegisters: the stored lease keeps the
// label its name publishes under, so the API, MCP and console show it and
// reserving the lease names the reservation (F38).
func TestReview628LeaseRowCarriesTheNameItRegisters(t *testing.T) {
	t.Parallel()
	for hostname, want := range map[string]string{"Phone": "phone", "Bob's iPad": "bobs-ipad", "wpad": "", "": ""} {
		row := dhcpLeaseToStore(dhcp.Lease{Hostname: hostname})
		if row.Label != want {
			t.Errorf("Label for %q = %q; want %q, the name this lease registers", hostname, row.Label, want)
		}
		if row.Hostname != hostname {
			t.Errorf("Hostname = %q; want %q as the client sent it", row.Hostname, hostname)
		}
	}
}
