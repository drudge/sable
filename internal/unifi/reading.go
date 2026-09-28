package unifi

import "time"

// Reading is what Sable keeps from its latest read of the controller for
// Insights: the networks with the DNS servers their DHCP hands out, the
// clients connected at that moment, and how each client's traffic counter
// grew over the days before.
type Reading struct {
	ReadAt   time.Time
	Networks []Network
	Stations []Station
	// Traffic holds each station's traffic counter as last read in each hour,
	// oldest first, keyed by its hardware address.
	Traffic map[string][]TrafficSample
}

// TrafficSample is one reading of a station's traffic counter. The counter
// starts over when the station reconnects, so ConnectedAt says which
// connection it counts.
type TrafficSample struct {
	ReadAt      time.Time
	ConnectedAt time.Time
	Bytes       uint64
}

// ConnectedAt is when a station connected, as of the read that reported it.
// It is rounded to the minute so the same connection reads the same from one
// sync to the next.
func (station Station) ConnectedAt(readAt time.Time) time.Time {
	return readAt.Add(-station.Uptime).UTC().Round(time.Minute)
}
