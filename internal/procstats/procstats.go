// Package procstats reads the Sable process's own memory and CPU use, for
// /metrics and the MCP get_stats tool.
package procstats

import (
	"math"
	"runtime"
	"runtime/debug"
	"runtime/metrics"
	"time"
)

// startTime stands in for the process start: package variables are set
// before main runs, so it is earlier than anything Sable does at startup.
var startTime = time.Now()

// Stats is one reading of the process. A field with a Has flag is zero where
// the platform cannot report it.
type Stats struct {
	StartTime time.Time
	// CPUSeconds is the user plus system CPU time the process has used.
	CPUSeconds float64
	HasCPU     bool
	// ResidentBytes is the memory the operating system has resident for
	// the process, Go heap and everything else; VirtualBytes is its
	// address space. Linux only.
	ResidentBytes uint64
	VirtualBytes  uint64
	HasMemory     bool
	// OpenFDs is the file descriptors open now (Linux only); MaxFDs is the
	// soft limit on them (Unix only).
	OpenFDs    uint64
	HasOpenFDs bool
	MaxFDs     uint64
	HasMaxFDs  bool

	Goroutines int
	Threads    int
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
	// NextGCBytes is the heap size the runtime aims to collect at.
	NextGCBytes uint64
	// MemoryLimitBytes is GOMEMLIMIT, or 0 when there is none.
	MemoryLimitBytes uint64

	GCCycles       int64
	GCPauseSeconds float64
	// GCPauseQuantiles are the minimum, 25th, 50th, 75th percentile, and
	// maximum of the recent stop-the-world pauses, in seconds.
	GCPauseQuantiles [5]float64
	// LastGC is when the last collection finished, zero before the first.
	LastGC time.Time
}

// GCPauseQuantileRanks are the ranks GCPauseQuantiles holds, in order.
var GCPauseQuantileRanks = [5]float64{0, 0.25, 0.5, 0.75, 1}

var runtimeSamples = []string{
	"/memory/classes/heap/objects:bytes",
	"/memory/classes/heap/unused:bytes",
	"/memory/classes/heap/free:bytes",
	"/memory/classes/heap/released:bytes",
	"/memory/classes/total:bytes",
	"/gc/heap/objects:objects",
	"/gc/heap/goal:bytes",
	"/gc/gomemlimit:bytes",
	"/sched/goroutines:goroutines",
	"/sched/threads/total:threads",
	"/sched/gomaxprocs:threads",
}

// Read takes a reading. Unlike runtime.ReadMemStats, neither runtime/metrics
// nor debug.ReadGCStats stops the world, so a scrape never stalls queries.
func Read() Stats {
	samples := make([]metrics.Sample, len(runtimeSamples))
	for index, name := range runtimeSamples {
		samples[index].Name = name
	}
	metrics.Read(samples)
	value := func(index int) uint64 {
		if samples[index].Value.Kind() != metrics.KindUint64 {
			return 0
		}
		return samples[index].Value.Uint64()
	}
	objects, unused, free, released := value(0), value(1), value(2), value(3)
	stats := Stats{
		StartTime:         startTime,
		NumCPU:            runtime.NumCPU(),
		HeapAllocBytes:    objects,
		HeapInuseBytes:    objects + unused,
		HeapIdleBytes:     free + released,
		HeapReleasedBytes: released,
		HeapSysBytes:      objects + unused + free + released,
		SysBytes:          value(4),
		HeapObjects:       value(5),
		NextGCBytes:       value(6),
		Goroutines:        int(value(8)),
		Threads:           int(value(9)),
		GOMAXPROCS:        int(value(10)),
	}
	// math.MaxInt64 means no limit was set.
	if limit := value(7); limit != math.MaxInt64 {
		stats.MemoryLimitBytes = limit
	}
	readGC(&stats)
	stats.CPUSeconds, stats.HasCPU = cpuSeconds()
	stats.ResidentBytes, stats.VirtualBytes, stats.HasMemory = memoryBytes()
	stats.OpenFDs, stats.HasOpenFDs = openFDs()
	stats.MaxFDs, stats.HasMaxFDs = maxFDs()
	return stats
}

func readGC(stats *Stats) {
	gc := debug.GCStats{PauseQuantiles: make([]time.Duration, len(GCPauseQuantileRanks))}
	debug.ReadGCStats(&gc)
	stats.GCCycles = gc.NumGC
	stats.GCPauseSeconds = gc.PauseTotal.Seconds()
	stats.LastGC = gc.LastGC
	if gc.NumGC == 0 {
		return
	}
	for index, pause := range gc.PauseQuantiles {
		stats.GCPauseQuantiles[index] = pause.Seconds()
	}
}
