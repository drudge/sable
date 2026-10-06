//go:build linux

package procstats

import (
	"bytes"
	"os"
	"strconv"
)

// residentBytes reads the second field of /proc/self/statm, resident pages.
func residentBytes() (uint64, bool) {
	statm, err := os.ReadFile("/proc/self/statm")
	if err != nil {
		return 0, false
	}
	fields := bytes.Fields(statm)
	if len(fields) < 2 {
		return 0, false
	}
	pages, err := strconv.ParseUint(string(fields[1]), 10, 64)
	if err != nil {
		return 0, false
	}
	return pages * uint64(os.Getpagesize()), true
}
