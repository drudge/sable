// Package faultinject lets the cluster fault harness skew a node's clock,
// fill its disk, and cut it off from its peers while the node runs. The hooks
// exist only in binaries built with the faultinject build tag. Without it,
// Now is time.Now, CheckWrite returns nil, SQLDriver and HTTPClient return
// their argument, and Enabled is false, so a release build carries none of
// this.
//
// A faultinject build reads its faults from the JSON file named by the
// SABLE_FAULTINJECT_CONTROL environment variable, re-reading it at most every
// RefreshInterval:
//
//	{"clock_offset": "-45s", "disk_full": true, "unreachable": ["127.0.0.1:8443"]}
//
// clock_offset is a Go duration added to every Now. disk_full makes
// CheckWrite, and every write through a driver from SQLDriver, fail with an
// error that wraps syscall.ENOSPC. unreachable lists host:port addresses the
// cluster's HTTP client can't reach: dials to them are refused and open
// connections to them reset, so listing each side's address on the other
// partitions two nodes, and listing it on one side only cuts one direction.
// WriteControlFile writes the file from any build. A missing file means no
// faults.
package faultinject

// ControlEnv names the environment variable that holds the control file's
// path in a faultinject build.
const ControlEnv = "SABLE_FAULTINJECT_CONTROL"
