package app

import (
	"context"
	"maps"
	"net/netip"
	"slices"
	"sync"
	"testing"

	"github.com/drudge/sable/internal/zone"
)

// recordingNotifier remembers each NOTIFY round it is asked for.
type recordingNotifier struct {
	mu    sync.Mutex
	calls map[string][]string
}

func (notifier *recordingNotifier) NotifyZone(_ context.Context, name string, targets []string) []error {
	notifier.mu.Lock()
	defer notifier.mu.Unlock()
	if notifier.calls == nil {
		notifier.calls = make(map[string][]string)
	}
	notifier.calls[name] = append([]string(nil), targets...)
	return nil
}

func (notifier *recordingNotifier) reset() map[string][]string {
	notifier.mu.Lock()
	defer notifier.mu.Unlock()
	calls := notifier.calls
	notifier.calls = nil
	return calls
}

func (stub *stubZoneEditor) setNotify(t *testing.T, name string, disabled bool, targets ...string) {
	t.Helper()
	stub.mu.Lock()
	defer stub.mu.Unlock()
	index := slices.IndexFunc(stub.zones, func(candidate zone.Zone) bool { return candidate.Name == name })
	if index < 0 {
		t.Fatalf("zone %q not found", name)
	}
	stub.zones[index].Notify = targets
	stub.zones[index].Disabled = disabled
}

// A sync that advances a zone's serial must tell that zone's secondaries
// (RFC 1996 §4.7), once per changed zone, and an idempotent sync must not.
func TestUniFiSyncNotifiesSecondariesOfChangedZones(t *testing.T) {
	other, err := zone.NewPrimary("other.example.net", 300, "", "", syncTestTime)
	if err != nil {
		t.Fatal(err)
	}
	editor := &stubZoneEditor{zones: []zone.Zone{other}}
	reader := &stubReader{inventory: testInventory()}
	syncer := newTestSyncer(t, testSettings(mapping("net-lan", "Default", "clients.example.net")), editor, reader)
	notifier := &recordingNotifier{}
	syncer.notifier = notifier

	syncer.runOnce(t.Context())
	syncer.notifying.Wait()
	if calls := notifier.reset(); len(calls) != 0 {
		t.Fatalf("zones created without notify targets were notified: %v", calls)
	}

	editor.setNotify(t, "clients.example.net", false, "192.0.2.53:53")
	editor.setNotify(t, "1.168.192.in-addr.arpa", true, "192.0.2.54:53")
	editor.setNotify(t, "other.example.net", false, "192.0.2.55:53")
	reader.inventory.Hosts[0].Address = netip.MustParseAddr("192.168.1.11")

	syncer.runOnce(t.Context())
	syncer.notifying.Wait()
	calls := notifier.reset()
	want := map[string][]string{"clients.example.net": {"192.0.2.53:53"}}
	if !maps.EqualFunc(calls, want, slices.Equal) {
		t.Fatalf("NOTIFY rounds = %v, want %v (the disabled reverse zone and the untouched zone stay quiet)", calls, want)
	}

	syncer.runOnce(t.Context())
	syncer.notifying.Wait()
	if calls := notifier.reset(); len(calls) != 0 {
		t.Fatalf("an idempotent sync sent NOTIFY: %v", calls)
	}
}

func TestAdvancedZonesCountsNewAndChangedSerials(t *testing.T) {
	first, _ := zone.NewPrimary("a.test", 300, "", "", syncTestTime)
	second, _ := zone.NewPrimary("b.test", 300, "", "", syncTestTime)
	zones := []zone.Zone{first, second}
	before := zoneSerials(zones)
	if got := advancedZones(before, zones); len(got) != 0 {
		t.Fatalf("unchanged zones reported as advanced: %v", got)
	}
	zone.AdvanceSerial(&zones[1], syncTestTime)
	third, _ := zone.NewPrimary("c.test", 300, "", "", syncTestTime)
	zones = append(zones, third)
	if got := advancedZones(before, zones); !slices.Equal(got, []string{"b.test", "c.test"}) {
		t.Fatalf("advanced = %v, want b.test and c.test", got)
	}
}
