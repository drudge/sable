package store

import (
	"context"
	"database/sql"
	"fmt"
	"net/netip"
	"strings"
	"time"

	"github.com/drudge/sable/internal/unifi"
)

// unifiTrafficHistory is how long each station's hourly traffic counters are
// kept: a week, the longest a device may be watched for, and a day to spare.
const unifiTrafficHistory = 8 * 24 * time.Hour

func unifiStationTables() []string {
	return []string{`
CREATE TABLE IF NOT EXISTS sable_unifi_network (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    gateway TEXT NOT NULL DEFAULT '',
    dhcp BOOLEAN NOT NULL DEFAULT FALSE,
    dhcp_dns TEXT NOT NULL DEFAULT '',
    read_at TIMESTAMP NOT NULL
)`, `
CREATE TABLE IF NOT EXISTS sable_unifi_station (
    mac TEXT PRIMARY KEY,
    name TEXT NOT NULL DEFAULT '',
    network_id TEXT NOT NULL DEFAULT '',
    addresses TEXT NOT NULL DEFAULT '',
    wired BOOLEAN NOT NULL DEFAULT FALSE,
    connected_at TIMESTAMP NOT NULL,
    last_seen TIMESTAMP,
    bytes BIGINT NOT NULL DEFAULT 0,
    read_at TIMESTAMP NOT NULL
)`, `
CREATE TABLE IF NOT EXISTS sable_unifi_station_traffic (
    mac TEXT NOT NULL,
    hour TIMESTAMP NOT NULL,
    connected_at TIMESTAMP NOT NULL,
    bytes BIGINT NOT NULL,
    read_at TIMESTAMP NOT NULL,
    PRIMARY KEY (mac, hour)
)`}
}

// RecordUniFiReading keeps the controller's latest networks and connected
// stations in place of the last read's, and adds each station's traffic
// counter to its hourly history. The UniFi sync calls it after each read, off
// the DNS request path. Nothing is kept while client tracking is off.
func (store *Store) RecordUniFiReading(ctx context.Context, inventory unifi.Inventory, readAt time.Time) error {
	// With Insights off nothing about a device is kept.
	if !store.ClientTracking() {
		return nil
	}
	readAt = readAt.UTC().Truncate(time.Second)
	return store.withTx(ctx, "UniFi reading", func(transaction *sql.Tx) error {
		return store.recordUniFiReading(ctx, transaction, inventory, readAt)
	})
}

func (store *Store) recordUniFiReading(ctx context.Context, transaction *sql.Tx, inventory unifi.Inventory, readAt time.Time) error {
	for _, table := range []string{"sable_unifi_network", "sable_unifi_station"} {
		if _, err := transaction.ExecContext(ctx, "DELETE FROM "+table); err != nil {
			return fmt.Errorf("clear %s: %w", table, err)
		}
	}
	for _, network := range inventory.Networks {
		gateway := ""
		if network.Gateway.IsValid() {
			gateway = network.Gateway.String()
		}
		if _, err := transaction.ExecContext(ctx, `
INSERT INTO sable_unifi_network (id, name, gateway, dhcp, dhcp_dns, read_at)
VALUES (`+store.placeholders(6)+`)`, network.ID, network.Name, gateway, network.DHCP, joinAddresses(network.DHCPDNS), readAt); err != nil {
			return fmt.Errorf("record UniFi network: %w", err)
		}
	}
	for _, station := range inventory.Stations {
		var lastSeen any
		if !station.LastSeen.IsZero() {
			lastSeen = station.LastSeen.UTC()
		}
		connectedAt := station.ConnectedAt(readAt)
		bytes := int64(min(station.Bytes, 1<<62))
		if _, err := transaction.ExecContext(ctx, `
INSERT INTO sable_unifi_station (mac, name, network_id, addresses, wired, connected_at, last_seen, bytes, read_at)
VALUES (`+store.placeholders(9)+`)`, station.MAC, station.Name, station.NetworkID, joinAddresses(station.Addresses()),
			station.Wired, connectedAt, lastSeen, bytes, readAt); err != nil {
			return fmt.Errorf("record UniFi station: %w", err)
		}
		// Each hour keeps its last reading, so the history shows how far the
		// counter had climbed by the end of every hour.
		if _, err := transaction.ExecContext(ctx, `
INSERT INTO sable_unifi_station_traffic (mac, hour, connected_at, bytes, read_at)
VALUES (`+store.placeholders(5)+`)
ON CONFLICT (mac, hour) DO UPDATE SET connected_at = excluded.connected_at, bytes = excluded.bytes, read_at = excluded.read_at`,
			station.MAC, readAt.Truncate(time.Hour), connectedAt, bytes, readAt); err != nil {
			return fmt.Errorf("record UniFi station traffic: %w", err)
		}
	}
	if _, err := transaction.ExecContext(ctx, "DELETE FROM sable_unifi_station_traffic WHERE hour < "+store.placeholder(1), readAt.Add(-unifiTrafficHistory)); err != nil {
		return fmt.Errorf("prune UniFi station traffic: %w", err)
	}
	return nil
}

// UniFiReading returns the controller's latest networks and stations, with
// each station's hourly traffic counters since a moment. A database that has
// never read a controller returns a reading with no ReadAt.
func (store *Store) UniFiReading(ctx context.Context, since time.Time) (unifi.Reading, error) {
	reading := unifi.Reading{Traffic: make(map[string][]unifi.TrafficSample)}
	networks, err := store.database.QueryContext(ctx, "SELECT id, name, gateway, dhcp, dhcp_dns, read_at FROM sable_unifi_network ORDER BY name, id")
	if err != nil {
		return reading, fmt.Errorf("read UniFi networks: %w", err)
	}
	for networks.Next() {
		var network unifi.Network
		var gateway, servers string
		var readAt any
		if err := networks.Scan(&network.ID, &network.Name, &gateway, &network.DHCP, &servers, &readAt); err != nil {
			networks.Close()
			return reading, fmt.Errorf("scan UniFi network: %w", err)
		}
		network.Gateway, _ = netip.ParseAddr(gateway)
		network.DHCPDNS = splitAddresses(servers)
		if err := laterReading(&reading, readAt); err != nil {
			networks.Close()
			return reading, err
		}
		reading.Networks = append(reading.Networks, network)
	}
	networks.Close()
	if err := networks.Err(); err != nil {
		return reading, fmt.Errorf("read UniFi networks: %w", err)
	}

	stations, err := store.database.QueryContext(ctx, `
SELECT mac, name, network_id, addresses, wired, connected_at, last_seen, bytes, read_at
FROM sable_unifi_station ORDER BY mac`)
	if err != nil {
		return reading, fmt.Errorf("read UniFi stations: %w", err)
	}
	for stations.Next() {
		var station unifi.Station
		var addresses string
		var connected, lastSeen, readAt any
		var bytes int64
		if err := stations.Scan(&station.MAC, &station.Name, &station.NetworkID, &addresses, &station.Wired,
			&connected, &lastSeen, &bytes, &readAt); err != nil {
			stations.Close()
			return reading, fmt.Errorf("scan UniFi station: %w", err)
		}
		read, err := databaseTime(readAt)
		if err != nil {
			stations.Close()
			return reading, fmt.Errorf("read UniFi station time: %w", err)
		}
		connectedAt, err := databaseTime(connected)
		if err != nil {
			stations.Close()
			return reading, fmt.Errorf("read UniFi station connection: %w", err)
		}
		if lastSeen != nil {
			if station.LastSeen, err = databaseTime(lastSeen); err != nil {
				stations.Close()
				return reading, fmt.Errorf("read UniFi station last seen: %w", err)
			}
		}
		parsed := splitAddresses(addresses)
		if len(parsed) > 0 {
			station.Address, station.IPv6 = parsed[0], parsed[1:]
		}
		station.Uptime, station.Bytes = max(read.Sub(connectedAt), 0), uint64(max(bytes, 0))
		if read.After(reading.ReadAt) {
			reading.ReadAt = read
		}
		reading.Stations = append(reading.Stations, station)
	}
	stations.Close()
	if err := stations.Err(); err != nil {
		return reading, fmt.Errorf("read UniFi stations: %w", err)
	}

	traffic, err := store.database.QueryContext(ctx, `
SELECT mac, connected_at, bytes, read_at FROM sable_unifi_station_traffic
WHERE hour >= `+store.placeholder(1)+` ORDER BY mac, hour`, since.UTC().Truncate(time.Hour))
	if err != nil {
		return reading, fmt.Errorf("read UniFi station traffic: %w", err)
	}
	defer traffic.Close()
	for traffic.Next() {
		var mac string
		var connected, readAt any
		var bytes int64
		if err := traffic.Scan(&mac, &connected, &bytes, &readAt); err != nil {
			return reading, fmt.Errorf("scan UniFi station traffic: %w", err)
		}
		sample := unifi.TrafficSample{Bytes: uint64(max(bytes, 0))}
		if sample.ConnectedAt, err = databaseTime(connected); err != nil {
			return reading, fmt.Errorf("read UniFi station traffic connection: %w", err)
		}
		if sample.ReadAt, err = databaseTime(readAt); err != nil {
			return reading, fmt.Errorf("read UniFi station traffic time: %w", err)
		}
		reading.Traffic[mac] = append(reading.Traffic[mac], sample)
	}
	return reading, traffic.Err()
}

// laterReading moves a reading's time up to a row's, when the row is newer.
func laterReading(reading *unifi.Reading, value any) error {
	read, err := databaseTime(value)
	if err != nil {
		return fmt.Errorf("read UniFi reading time: %w", err)
	}
	if read.After(reading.ReadAt) {
		reading.ReadAt = read
	}
	return nil
}

func joinAddresses(addresses []netip.Addr) string {
	values := make([]string, 0, len(addresses))
	for _, address := range addresses {
		values = append(values, address.String())
	}
	return strings.Join(values, " ")
}

func splitAddresses(value string) []netip.Addr {
	var addresses []netip.Addr
	for _, field := range strings.Fields(value) {
		if address, err := netip.ParseAddr(field); err == nil {
			addresses = append(addresses, address)
		}
	}
	return addresses
}
