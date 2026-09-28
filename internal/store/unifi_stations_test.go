package store

import (
	"context"
	"net/netip"
	"slices"
	"testing"
	"time"

	"github.com/drudge/sable/internal/unifi"
)

// Each read replaces the last one's networks and stations, and adds to each
// station's hourly traffic history, which keeps the last reading of every hour
// and forgets hours older than a week and a day.
func TestUniFiReadingKeepsLatestReadAndHourlyTraffic(t *testing.T) {
	store := openIdentityStore(t)
	ctx := context.Background()
	start := time.Date(2026, 9, 20, 10, 5, 0, 0, time.UTC)
	network := unifi.Network{
		ID: "net-guest", Name: "Guest", Gateway: netip.MustParseAddr("10.0.50.1"), DHCP: true,
		DHCPDNS: []netip.Addr{netip.MustParseAddr("1.1.1.1"), netip.MustParseAddr("1.0.0.1")},
	}
	station := func(bytes uint64, uptime time.Duration) unifi.Station {
		return unifi.Station{
			MAC: "aa:bb:cc:00:00:01", Address: netip.MustParseAddr("10.0.50.20"),
			IPv6: []netip.Addr{netip.MustParseAddr("2001:db8::20")}, NetworkID: "net-guest",
			Uptime: uptime, Bytes: bytes, LastSeen: start,
		}
	}
	old := unifi.Inventory{Stations: []unifi.Station{{MAC: "aa:bb:cc:00:00:09", Address: netip.MustParseAddr("10.0.50.99")}}}
	if err := store.RecordUniFiReading(ctx, old, start.Add(-9*24*time.Hour)); err != nil {
		t.Fatalf("record old reading: %v", err)
	}
	for index, moment := range []time.Time{start, start.Add(20 * time.Minute), start.Add(time.Hour)} {
		inventory := unifi.Inventory{Networks: []unifi.Network{network}, Stations: []unifi.Station{station(uint64(index+1)*1000, 48*time.Hour+moment.Sub(start))}}
		if err := store.RecordUniFiReading(ctx, inventory, moment); err != nil {
			t.Fatalf("record reading %d: %v", index, err)
		}
	}
	reading, err := store.UniFiReading(ctx, start.Add(-24*time.Hour))
	if err != nil {
		t.Fatalf("UniFiReading: %v", err)
	}
	if !reading.ReadAt.Equal(start.Add(time.Hour)) {
		t.Fatalf("read at %s, want the latest read", reading.ReadAt)
	}
	if len(reading.Networks) != 1 || !slices.Equal(reading.Networks[0].DHCPDNS, network.DHCPDNS) ||
		reading.Networks[0].Gateway != network.Gateway || !reading.Networks[0].DHCP {
		t.Fatalf("networks = %+v, want the guest network as read", reading.Networks)
	}
	if len(reading.Stations) != 1 {
		t.Fatalf("stations = %+v, want only the latest read's station", reading.Stations)
	}
	got := reading.Stations[0]
	if got.Address != netip.MustParseAddr("10.0.50.20") || len(got.IPv6) != 1 || got.Bytes != 3000 ||
		got.Uptime != 49*time.Hour || !got.LastSeen.Equal(start) {
		t.Fatalf("station = %+v, want its addresses, counter, and a 49 hour connection", got)
	}
	samples := reading.Traffic["aa:bb:cc:00:00:01"]
	if len(samples) != 2 || samples[0].Bytes != 2000 || samples[1].Bytes != 3000 {
		t.Fatalf("traffic = %+v, want the last reading of each of two hours", samples)
	}
	if !samples[0].ConnectedAt.Equal(start.Add(-48 * time.Hour)) {
		t.Fatalf("connected at %s, want 48 hours before the first read", samples[0].ConnectedAt)
	}
	if everything, err := store.UniFiReading(ctx, time.Time{}); err != nil || len(everything.Traffic["aa:bb:cc:00:00:09"]) != 0 {
		t.Fatalf("history older than a week and a day survived: %+v, %v", everything.Traffic, err)
	}
}

func TestUniFiReadingIsEmptyBeforeAnyRead(t *testing.T) {
	reading, err := openIdentityStore(t).UniFiReading(context.Background(), time.Time{})
	if err != nil || !reading.ReadAt.IsZero() || len(reading.Stations) != 0 {
		t.Fatalf("reading = %+v, %v, want nothing", reading, err)
	}
}

// With Insights off nothing about devices is kept, and deleting Insights data
// takes the UniFi readings with it.
func TestUniFiReadingFollowsTheInsightsSwitch(t *testing.T) {
	store := openIdentityStore(t)
	ctx := context.Background()
	now := time.Date(2026, 9, 20, 10, 0, 0, 0, time.UTC)
	inventory := unifi.Inventory{Stations: []unifi.Station{{MAC: "aa:bb:cc:00:00:01", Address: netip.MustParseAddr("10.0.50.20"), Bytes: 5}}}
	store.SetClientTracking(false)
	if err := store.RecordUniFiReading(ctx, inventory, now); err != nil {
		t.Fatal(err)
	}
	if reading, _ := store.UniFiReading(ctx, time.Time{}); !reading.ReadAt.IsZero() {
		t.Fatalf("a reading was kept with tracking off: %+v", reading)
	}
	store.SetClientTracking(true)
	if err := store.RecordUniFiReading(ctx, inventory, now); err != nil {
		t.Fatal(err)
	}
	if err := store.DeleteInsightData(ctx, now); err != nil {
		t.Fatal(err)
	}
	if reading, _ := store.UniFiReading(ctx, time.Time{}); !reading.ReadAt.IsZero() || len(reading.Traffic) != 0 {
		t.Fatalf("deleting Insights data left the UniFi reading: %+v", reading)
	}
}
