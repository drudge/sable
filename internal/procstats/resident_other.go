//go:build !linux

package procstats

// residentBytes has no portable source outside Linux: getrusage reports only
// the peak, not the current size.
func residentBytes() (uint64, bool) { return 0, false }
