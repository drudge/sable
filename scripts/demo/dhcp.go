package main

import (
	"context"
	"fmt"
	"net/netip"
	"time"

	"github.com/drudge/sable/internal/config"
	"github.com/drudge/sable/internal/store"
)

// dhcpFixture is the lab network Vandelay hands addresses out on with Sable
// instead of UniFi: a few reserved instruments and the rest from the pool.
// It stays off, so the demo never answers on a real network, with the leases
// it handed out before.
func dhcpFixture() config.DHCP {
	return config.DHCP{Scopes: []config.DHCPScope{{
		ID: "lab", Name: "Lab", Subnet: "10.20.50.0/24", Router: "10.20.50.1", Domain: "corp.vandelay.com",
		DNS:    []string{"10.20.10.53", "10.20.10.54"},
		Ranges: []config.DHCPRange{{Start: "10.20.50.100", End: "10.20.50.199"}},
		Reservations: []config.DHCPReservation{
			{MAC: "00:1b:a9:50:10:01", Address: "10.20.50.10", Name: "lab-printer", Comment: "Brother, by the bench"},
			{MAC: "00:0d:56:50:10:02", Address: "10.20.50.11", Name: "spectrometer", Comment: "Calibration rig"},
			{MAC: "b8:27:eb:50:10:03", Address: "10.20.50.12", Name: "latex-sensor-hub"},
		},
	}}}
}

// dhcpLeases are the lab's current leases: two reserved instruments online
// and a handful of laptops and phones from the pool.
func dhcpLeases(now time.Time) []store.DHCPLease {
	type demoLease struct {
		address, mac, name string
		bound              time.Duration
	}
	leases := []demoLease{
		{"10.20.50.10", "00:1b:a9:50:10:01", "lab-printer", 3 * time.Hour},
		{"10.20.50.11", "00:0d:56:50:10:02", "spectrometer", 20 * time.Minute},
		{"10.20.50.104", "3c:22:fb:11:04:a3", "elaine-macbook", 2 * time.Hour}, // roams in from Corporate, so its Insights drawer has a lease
		{"10.20.50.117", "a4:83:e7:50:20:17", "kramer-iphone", 5 * time.Hour},
		{"10.20.50.121", "f0:18:98:50:20:21", "george-thinkpad", 40 * time.Minute},
		{"10.20.50.133", "dc:a6:32:50:20:33", "", 7 * time.Hour},
	}
	rows := make([]store.DHCPLease, 0, len(leases))
	for _, lease := range leases {
		bound := now.Add(-lease.bound)
		rows = append(rows, store.DHCPLease{
			NodeID: "dns-1", Address: netip.MustParseAddr(lease.address), ScopeID: "lab", ClientKey: "01" + lease.mac,
			MAC: lease.mac, Hostname: lease.name, Label: lease.name, State: store.DHCPLeaseActive,
			BoundAt: bound, ExpiresAt: bound.Add(12 * time.Hour),
		})
	}
	return rows
}

func seedDHCPLeases(ctx context.Context, backing *store.Store, now time.Time) error {
	if _, err := backing.SaveDHCPLeases(ctx, dhcpLeases(now)); err != nil {
		return fmt.Errorf("write demo DHCP leases: %w", err)
	}
	return nil
}
