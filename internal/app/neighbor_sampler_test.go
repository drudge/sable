package app

import (
	"context"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/drudge/sable/internal/neighbors"
	"github.com/drudge/sable/internal/querylog"
	"github.com/drudge/sable/internal/unifi"
)

func TestSampleNeighborsRecordsEveryEntry(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 9, 22, 12, 0, 0, 0, time.UTC)
	var recorded []querylog.ClientIdentity
	err := sampleNeighbors(context.Background(),
		func() ([]neighbors.Entry, error) {
			return []neighbors.Entry{{Address: netip.MustParseAddr("10.0.0.5"), MAC: net.HardwareAddr{0x3c, 0x22, 0xfb, 1, 2, 3}}}, nil
		},
		func(_ context.Context, identities []querylog.ClientIdentity) error { recorded = identities; return nil },
		now)
	if err != nil {
		t.Fatal(err)
	}
	if len(recorded) != 1 || recorded[0] != (querylog.ClientIdentity{Address: "10.0.0.5", MAC: "3c:22:fb:01:02:03", Source: neighborIdentitySource, SeenAt: now}) {
		t.Fatalf("recorded = %+v", recorded)
	}
}

func TestUniFiIdentitiesCoverEveryAddressOfAHost(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 9, 22, 12, 0, 0, 0, time.UTC)
	identities := unifiIdentities(unifi.Inventory{Hosts: []unifi.Host{
		{MAC: "3c:22:fb:01:02:03", Hostname: "george-laptop", Address: netip.MustParseAddr("10.0.0.5"), IPv6: []netip.Addr{netip.MustParseAddr("fd00::5")}},
		{MAC: "", Hostname: "no-mac", Address: netip.MustParseAddr("10.0.0.6")},
	}}, now)
	if len(identities) != 2 || identities[1].Address != "fd00::5" || identities[0].Hostname != "george-laptop" || identities[0].Source != unifiIdentitySource {
		t.Fatalf("identities = %+v", identities)
	}
}

func TestUniFiIdentitiesNameTheControllersGear(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 9, 27, 12, 0, 0, 0, time.UTC)
	identities := unifiIdentities(unifi.Inventory{Gear: []unifi.Host{
		{MAC: "0c:ea:14:f3:42:fc", Hostname: "Office U7 Pro", Address: netip.MustParseAddr("10.0.7.79"), Kind: "access point"},
		{MAC: "90:41:b2:9c:f8:a4", Hostname: "UPS Tower", Address: netip.MustParseAddr("10.0.7.40"), Kind: "ups"},
	}}, now)
	want := querylog.ClientIdentity{Address: "10.0.7.79", MAC: "0c:ea:14:f3:42:fc", Source: "unifi-network", Hostname: "Office U7 Pro", SeenAt: now}
	if len(identities) != 2 || identities[0] != want {
		t.Fatalf("identities = %+v, want %+v first", identities, want)
	}
	// A UPS is vouched for as a UPS, not network equipment.
	if identities[1].Source != "unifi-ups" || identities[1].Hostname != "UPS Tower" {
		t.Fatalf("UPS identity = %+v", identities[1])
	}
}
