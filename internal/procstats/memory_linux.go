//go:build linux

package procstats

import (
	"bytes"
	"os"
	"strconv"
)

// memoryBytes reads the first two fields of /proc/self/statm: total and
// resident pages.
func memoryBytes() (resident, virtual uint64, ok bool) {
	statm, err := os.ReadFile("/proc/self/statm")
	if err != nil {
		return 0, 0, false
	}
	fields := bytes.Fields(statm)
	if len(fields) < 2 {
		return 0, 0, false
	}
	size, sizeErr := strconv.ParseUint(string(fields[0]), 10, 64)
	pages, pagesErr := strconv.ParseUint(string(fields[1]), 10, 64)
	if sizeErr != nil || pagesErr != nil {
		return 0, 0, false
	}
	pageSize := uint64(os.Getpagesize())
	return pages * pageSize, size * pageSize, true
}

func openFDs() (uint64, bool) {
	directory, err := os.Open("/proc/self/fd")
	if err != nil {
		return 0, false
	}
	defer directory.Close()
	names, err := directory.Readdirnames(-1)
	if err != nil {
		return 0, false
	}
	// Reading the directory holds one descriptor of its own.
	return uint64(max(len(names)-1, 0)), true
}
