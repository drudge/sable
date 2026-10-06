// Package procstats reads the Sable process's own memory and CPU use, for
// /metrics and the MCP get_stats tool.
package procstats

import (
	"runtime"
	"time"
)

// Stats is one reading of the process. ResidentBytes is zero where the
// platform cannot report it (see HasResident), and CPUSeconds likewise (see
// HasCPU).
type Stats struct {
	// CPUSeconds is the user plus system CPU time the process has used.
	CPUSeconds float64
	HasCPU     bool
	// ResidentBytes is the memory the operating system has resident for
	// the process, Go heap and everything else (Linux only).
	ResidentBytes uint64
	HasResident   bool

	Goroutines int
	NumCPU     int
	GOMAXPROCS int

	// HeapAllocBytes is memory held by live and not yet collected objects.
	HeapAllocBytes uint64
	// HeapInuseBytes is heap spans with at least one object in them.
	HeapInuseBytes uint64
	// HeapIdleBytes is heap spans with no objects, released or not.
	HeapIdleBytes uint64
	// HeapReleasedBytes is idle heap returned to the operating system.
	HeapReleasedBytes uint64
	// HeapSysBytes is heap memory obtained from the operating system.
	HeapSysBytes uint64
	HeapObjects  uint64
	// SysBytes is all memory the Go runtime obtained from the operating
	// system: heap, stacks, and runtime structures.
	SysBytes uint64
	// NextGCBytes is the heap size that triggers the next collection.
	NextGCBytes uint64

	GCCycles       uint32
	GCPauseSeconds float64
	// LastGC is when the last collection finished, zero before the first.
	LastGC time.Time
}

// Read takes a reading. runtime.ReadMemStats stops the world for a few
// microseconds, so call it per scrape or tool call, never per query.
func Read() Stats {
	var memory runtime.MemStats
	runtime.ReadMemStats(&memory)
	stats := Stats{
		Goroutines:        runtime.NumGoroutine(),
		NumCPU:            runtime.NumCPU(),
		GOMAXPROCS:        runtime.GOMAXPROCS(0),
		HeapAllocBytes:    memory.HeapAlloc,
		HeapInuseBytes:    memory.HeapInuse,
		HeapIdleBytes:     memory.HeapIdle,
		HeapReleasedBytes: memory.HeapReleased,
		HeapSysBytes:      memory.HeapSys,
		HeapObjects:       memory.HeapObjects,
		SysBytes:          memory.Sys,
		NextGCBytes:       memory.NextGC,
		GCCycles:          memory.NumGC,
		GCPauseSeconds:    time.Duration(memory.PauseTotalNs).Seconds(),
	}
	if memory.LastGC != 0 {
		stats.LastGC = time.Unix(0, int64(memory.LastGC))
	}
	stats.CPUSeconds, stats.HasCPU = cpuSeconds()
	stats.ResidentBytes, stats.HasResident = residentBytes()
	return stats
}
