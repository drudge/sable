//go:build faultinject

package cluster

import (
	"errors"
	"syscall"
	"testing"
	"time"

	"github.com/drudge/sable/internal/faultinject"
)

func TestClusterClockFollowsInjectedSkew(t *testing.T) {
	faultinject.UseFaults(t, faultinject.Faults{ClockOffset: -2 * time.Minute})
	service, err := Open(Options{DataDirectory: t.TempDir(), NodeName: "dns-1"})
	if err != nil {
		t.Fatal(err)
	}
	if skew := time.Until(service.clock()); skew > -119*time.Second || skew < -121*time.Second {
		t.Fatalf("clock skew = %v, want about -2m", skew)
	}
	if skew := time.Until(service.Snapshot().ObservedAt); skew > -119*time.Second || skew < -121*time.Second {
		t.Fatalf("snapshot skew = %v, want about -2m", skew)
	}
}

func TestClusterStateWritesFailWhileTheDiskIsFull(t *testing.T) {
	write := faultinject.UseFaults(t, faultinject.Faults{DiskFull: true})
	directory := t.TempDir()
	if err := writeManifest(directory, &manifest{ClusterID: "cluster"}); !errors.Is(err, syscall.ENOSPC) {
		t.Fatalf("writeManifest() = %v, want ENOSPC", err)
	}
	contents := []byte("{}")
	if err := writeStateSnapshot(directory, stateDigest(contents), contents); !errors.Is(err, syscall.ENOSPC) {
		t.Fatalf("writeStateSnapshot() = %v, want ENOSPC", err)
	}
	write(faultinject.Faults{})
	if err := writeManifest(directory, &manifest{ClusterID: "cluster"}); err != nil {
		t.Fatalf("writeManifest() after the disk cleared = %v", err)
	}
	if err := writeStateSnapshot(directory, stateDigest(contents), contents); err != nil {
		t.Fatalf("writeStateSnapshot() after the disk cleared = %v", err)
	}
}
