package app

import (
	"sync"
	"time"

	"github.com/drudge/sable/internal/dhcp"
)

// dhcpMaxDelayedOffers bounds the OFFERs held back by offer_delay. A
// client's newer DISCOVER replaces its waiting OFFER, so this caps distinct
// clients, not repeats; past it the OFFER is dropped and counted.
const dhcpMaxDelayedOffers = dhcpQueueSize

// dhcpDelayedOffers holds each client's OFFER until its offer_delay is up.
// Waiting OFFERs are runtime timers, not goroutines, and there is at most
// one per client: a client takes only the reply carrying the xid of its
// latest DISCOVER (RFC 2131 §4.4.1), so a newer one replaces the older.
type dhcpDelayedOffers struct {
	mutex   sync.Mutex
	pending map[string]*time.Timer
	stopped bool
}

// schedule runs write after delay in place of the client's waiting OFFER,
// and reports false when too many other clients are already waiting.
func (delayed *dhcpDelayedOffers) schedule(client string, delay time.Duration, write func()) bool {
	delayed.mutex.Lock()
	defer delayed.mutex.Unlock()
	if delayed.stopped {
		return true
	}
	if old, found := delayed.pending[client]; found {
		old.Stop()
	} else if len(delayed.pending) >= dhcpMaxDelayedOffers {
		return false
	}
	if delayed.pending == nil {
		delayed.pending = make(map[string]*time.Timer)
	}
	var timer *time.Timer
	timer = time.AfterFunc(delay, func() {
		delayed.mutex.Lock()
		current := delayed.pending[client] == timer && !delayed.stopped
		if current {
			delete(delayed.pending, client)
		}
		delayed.mutex.Unlock()
		if current {
			write()
		}
	})
	delayed.pending[client] = timer
	return true
}

// waiting reports how many OFFERs are held back.
func (delayed *dhcpDelayedOffers) waiting() int {
	delayed.mutex.Lock()
	defer delayed.mutex.Unlock()
	return len(delayed.pending)
}

// stop drops every waiting OFFER, so none goes out after the server stops.
func (delayed *dhcpDelayedOffers) stop() {
	delayed.mutex.Lock()
	defer delayed.mutex.Unlock()
	delayed.stopped = true
	for client, timer := range delayed.pending {
		timer.Stop()
		delete(delayed.pending, client)
	}
}

// dhcpOfferKey names the client an OFFER is for: the hardware type and
// address the reply is addressed to (RFC 2131 §4.1, chaddr).
func dhcpOfferKey(request dhcp.Packet) string {
	return string(append([]byte{request.HType}, request.CHAddr...))
}
