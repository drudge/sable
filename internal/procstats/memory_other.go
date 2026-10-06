//go:build !linux

package procstats

// memoryBytes and openFDs have no portable source outside Linux: getrusage
// reports only the peak resident size, not the current one.
func memoryBytes() (resident, virtual uint64, ok bool) { return 0, 0, false }

func openFDs() (uint64, bool) { return 0, false }
