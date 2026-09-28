package app

import (
	"context"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/drudge/sable/internal/config"
	"github.com/drudge/sable/internal/neighbors"
	"github.com/drudge/sable/internal/querylog"
	"github.com/pelletier/go-toml/v2"
)

type fakeClientTracker struct {
	stopped int
	resumed []time.Time
}

func (tracker *fakeClientTracker) StopClientTracking(context.Context) error {
	tracker.stopped++
	return nil
}

func (tracker *fakeClientTracker) ResumeClientTracking(_ context.Context, now time.Time) error {
	tracker.resumed = append(tracker.resumed, now)
	return nil
}

func TestSwitchInsightsStopsAndStartsFresh(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 9, 28, 12, 0, 0, 0, time.UTC)
	for _, test := range []struct {
		name         string
		was, enabled bool
		stopped      int
		resumed      int
	}{
		{name: "stays on", was: true, enabled: true},
		{name: "turned off", was: true, enabled: false, stopped: 1},
		{name: "stays off", was: false, enabled: false, stopped: 1},
		{name: "turned back on", was: false, enabled: true, resumed: 1},
	} {
		t.Run(test.name, func(t *testing.T) {
			tracker := &fakeClientTracker{}
			if err := switchInsights(context.Background(), tracker, test.was, test.enabled, now); err != nil {
				t.Fatal(err)
			}
			if tracker.stopped != test.stopped || len(tracker.resumed) != test.resumed {
				t.Fatalf("stopped %d and resumed %d times, want %d and %d", tracker.stopped, len(tracker.resumed), test.stopped, test.resumed)
			}
		})
	}
}

func TestNeighborSamplerLeavesTheTableUnreadWhileInsightsIsOff(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithCancel(context.Background())
	var reads atomic.Int32
	done := make(chan struct{})
	go func() {
		defer close(done)
		runNeighborSampler(ctx, func() bool { return false },
			func() ([]neighbors.Entry, error) { reads.Add(1); return nil, nil },
			func(context.Context, []querylog.ClientIdentity) error { return nil },
			slog.New(slog.NewTextHandler(io.Discard, nil)))
	}()
	time.Sleep(20 * time.Millisecond)
	cancel()
	<-done
	if got := reads.Load(); got != 0 {
		t.Fatalf("neighbor table read %d times with Insights off", got)
	}
}

type fakeInsightData struct {
	deletedAt time.Time
	deletes   []time.Time
}

func (data *fakeInsightData) InsightDataDeletedAt(context.Context) (time.Time, bool, error) {
	return data.deletedAt, !data.deletedAt.IsZero(), nil
}

func (data *fakeInsightData) DeleteInsightData(_ context.Context, at time.Time) error {
	data.deletes = append(data.deletes, at)
	data.deletedAt = at
	return nil
}

func TestClusterStateCarriesTheInsightsSwitchAndDeletion(t *testing.T) {
	ctx := context.Background()
	deletedAt := time.Date(2026, 9, 28, 12, 0, 0, 0, time.UTC)
	sourceConfiguration := config.Defaults()
	sourceConfiguration.Insights.Enabled = false
	sourceManager := newTestConfigurationManager(t, sourceConfiguration)
	// The primary normalizes on load in production.
	if err := sourceManager.Update(ctx, func(*config.Config) error { return nil }); err != nil {
		t.Fatal(err)
	}
	source := newClusterStateReplicator(sourceManager, newTestZoneManager(t, nil), nil, newTestTSIGStore(), newTestUniFiCredentials(), newTestOIDCSecrets())
	source.setInsightData(&fakeInsightData{deletedAt: deletedAt})
	contents, err := source.Capture(ctx)
	if err != nil {
		t.Fatal(err)
	}

	applies := 0
	path := filepath.Join(t.TempDir(), "sable.toml")
	encoded, err := toml.Marshal(config.Defaults())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, encoded, 0o600); err != nil {
		t.Fatal(err)
	}
	targetManager := config.NewManager(path, config.Defaults(), func(context.Context, config.Config, config.Config) error {
		applies++
		return nil
	})
	targetData := &fakeInsightData{}
	replica := newClusterStateReplicator(targetManager, newTestZoneManager(t, nil), nil, newTestTSIGStore(), newTestUniFiCredentials(), newTestOIDCSecrets())
	replica.setInsightData(targetData)
	for range 3 {
		if err := replica.Apply(ctx, contents); err != nil {
			t.Fatal(err)
		}
	}
	if targetManager.Current().Config.Insights.Enabled {
		t.Fatal("replica kept Insights on after the primary turned it off")
	}
	if len(targetData.deletes) != 1 || !targetData.deletes[0].Equal(deletedAt) {
		t.Fatalf("replica deleted its Insights data at %v, want once at %s", targetData.deletes, deletedAt)
	}
	if applies != 1 {
		t.Fatalf("snapshot wrote configuration %d times, want 1", applies)
	}

	// A replica that deleted its own data since keeps what it has collected.
	targetData.deletedAt, targetData.deletes = deletedAt.Add(time.Hour), nil
	if err := replica.Apply(ctx, contents); err != nil {
		t.Fatal(err)
	}
	if len(targetData.deletes) != 0 {
		t.Fatalf("replica deleted again for an older deletion: %v", targetData.deletes)
	}
}

func TestReplicatedRuntimeConfigurationKeepsLocalInsightsWhenPrimaryOmitsIt(t *testing.T) {
	candidate := config.Defaults()
	source := replicatedRuntimeConfiguration(config.Defaults())
	source.InsightsEnabled = nil
	candidate.Insights.Enabled = false
	applyReplicatedRuntimeConfiguration(&candidate, source)
	if candidate.Insights.Enabled {
		t.Fatal("a primary that predates the switch turned Insights on")
	}
	off := false
	source.InsightsEnabled = &off
	candidate.Insights.Enabled = true
	applyReplicatedRuntimeConfiguration(&candidate, source)
	if candidate.Insights.Enabled {
		t.Fatal("primary's Insights switch was ignored")
	}
}
