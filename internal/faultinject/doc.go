// Package faultinject lets the cluster fault harness skew a node's clock and
// fill its disk while the node runs. The hooks exist only in binaries built
// with the faultinject build tag. Without it, Now is time.Now, CheckWrite
// returns nil, SQLDriver returns its argument, and Enabled is false, so a
// release build carries none of this.
//
// A faultinject build reads its faults from the JSON file named by the
// SABLE_FAULTINJECT_CONTROL environment variable, re-reading it at most every
// RefreshInterval:
//
//	{"clock_offset": "-45s", "disk_full": true}
//
// clock_offset is a Go duration added to every Now. disk_full makes
// CheckWrite, and every write through a driver from SQLDriver, fail with an
// error that wraps syscall.ENOSPC. A missing file means no faults.
package faultinject

// ControlEnv names the environment variable that holds the control file's
// path in a faultinject build.
const ControlEnv = "SABLE_FAULTINJECT_CONTROL"
