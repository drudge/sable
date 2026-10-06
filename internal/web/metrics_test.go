package web

import (
	"strings"
	"testing"
	"time"

	"github.com/drudge/sable/internal/procstats"
)

func TestWriteProcessMetrics(t *testing.T) {
	t.Parallel()
	stats := procstats.Stats{
		CPUSeconds: 12.5, HasCPU: true, ResidentBytes: 48 << 20, HasResident: true,
		Goroutines: 42, GOMAXPROCS: 4, HeapAllocBytes: 10 << 20, HeapInuseBytes: 12 << 20,
		HeapIdleBytes: 3 << 20, HeapReleasedBytes: 1 << 20, HeapSysBytes: 15 << 20, HeapObjects: 9000,
		SysBytes: 24 << 20, NextGCBytes: 20 << 20, GCCycles: 7, GCPauseSeconds: 0.0015,
		LastGC: time.Unix(1_790_000_000, 500_000_000),
	}
	var output strings.Builder
	writeProcessMetrics(&output, stats)
	for _, expected := range []string{
		"# TYPE process_cpu_seconds_total counter\nprocess_cpu_seconds_total 12.5\n",
		"# TYPE process_resident_memory_bytes gauge\nprocess_resident_memory_bytes 50331648\n",
		"go_goroutines 42\n",
		"go_sched_gomaxprocs_threads 4\n",
		"go_memstats_heap_alloc_bytes 10485760\n",
		"go_memstats_heap_inuse_bytes 12582912\n",
		"go_memstats_heap_objects 9000\n",
		"go_memstats_last_gc_time_seconds 1790000000.5\n",
		"# TYPE go_gc_duration_seconds summary\ngo_gc_duration_seconds_sum 0.0015\ngo_gc_duration_seconds_count 7\n",
	} {
		if !strings.Contains(output.String(), expected) {
			t.Errorf("process metrics do not contain %q:\n%s", expected, output.String())
		}
	}

	output.Reset()
	writeProcessMetrics(&output, procstats.Stats{Goroutines: 1})
	for _, absent := range []string{"process_cpu_seconds_total", "process_resident_memory_bytes"} {
		if strings.Contains(output.String(), absent) {
			t.Errorf("process metrics report %s the platform could not read:\n%s", absent, output.String())
		}
	}
	if !strings.Contains(output.String(), "go_memstats_last_gc_time_seconds 0\n") {
		t.Errorf("last GC before the first collection is not 0:\n%s", output.String())
	}
}
