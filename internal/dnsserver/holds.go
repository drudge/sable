package dnsserver

import (
	"fmt"
	"time"
)

// HoldPolicy blocks everything for a client, except the domains it is
// allowed, until Until, or for as long as the hold is configured when Until
// is zero.
type HoldPolicy struct {
	// Client is an IP address, CIDR network or hardware address.
	Client string
	Until  time.Time
}

func (runtime *Runtime) compileHolds(holds []HoldPolicy) error {
	var table clientTable[int64]
	for _, hold := range holds {
		var until int64
		if !hold.Until.IsZero() {
			until = hold.Until.UnixNano()
		}
		if err := table.add(hold.Client, until); err != nil {
			return fmt.Errorf("invalid blocking hold client %q", hold.Client)
		}
	}
	table.sort()
	runtime.holds = table
	return nil
}

// held reports whether a hold blocks everything for client at now. A hold
// that has ended no longer applies, so nothing needs to remove it on time.
func (runtime *Runtime) held(client policyClient, now func() time.Time) bool {
	until, found := runtime.holds.lookup(client)
	return found && (until == 0 || now().UnixNano() < until)
}
