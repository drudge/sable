package app

import (
	"sync"
	"time"

	"github.com/drudge/sable/internal/dhcp"
)

// dhcpMaxDelayedOffers bounds the OFFERs held back by offer_delay (D28). A
// client's newer DISCOVER replaces its waiting OFFER, so this caps distinct
// clients, not repeats; past it the OFFER is dropped and counted.
const dhcpMaxDelayedOffers = 1024

// dhcpDelayedOffers holds each client's OFFER until its offer_delay is up.
// Waiting OFFERs are runtime timers, not goroutines, and there is at most
// one per client: a client takes only the reply carrying the xid of its
// latest DISCOVER (RFC 2131 §4.4.1), so a newer one replaces the older.
type dhcpDelayedOffers struct {
	mutex   sync.Mutex
	pending map[string]*dhcpDelayedOffer
	stopped bool
}

// dhcpDelayedOffer is one client's waiting OFFER: the reply to its latest
// DISCOVER, sent when the first DISCOVER's delay is up.
type dhcpDelayedOffer struct {
	timer *time.Timer
	write func()
}

// schedule sends write after delay, and reports false when too many other
// clients are already waiting. A client that retransmits before its OFFER
// goes out keeps its first deadline and gets the reply to its newest
// DISCOVER: restarting the clock would starve a client retrying faster than
// offer_delay (RFC 2131 §4.1 lets it retry from about 1 s).
func (delayed *dhcpDelayedOffers) schedule(client string, delay time.Duration, write func()) bool {
	delayed.mutex.Lock()
	defer delayed.mutex.Unlock()
	if delayed.stopped {
		return true
	}
	if waiting, found := delayed.pending[client]; found {
		waiting.write = write
		return true
	}
	if len(delayed.pending) >= dhcpMaxDelayedOffers {
		return false
	}
	if delayed.pending == nil {
		delayed.pending = make(map[string]*dhcpDelayedOffer)
	}
	offer := &dhcpDelayedOffer{write: write}
	offer.timer = time.AfterFunc(delay, func() { delayed.fire(client, offer) })
	delayed.pending[client] = offer
	return true
}

// fire sends a client's waiting OFFER unless the server stopped first.
func (delayed *dhcpDelayedOffers) fire(client string, offer *dhcpDelayedOffer) {
	delayed.mutex.Lock()
	current := delayed.pending[client] == offer && !delayed.stopped
	write := offer.write
	if current {
		delete(delayed.pending, client)
	}
	delayed.mutex.Unlock()
	if current {
		write()
	}
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
	for client, offer := range delayed.pending {
		offer.timer.Stop()
		delete(delayed.pending, client)
	}
}

// dhcpOfferKey names the client an OFFER is for: the hardware type and
// address the reply is addressed to (RFC 2131 §4.1, chaddr).
func dhcpOfferKey(request dhcp.Packet) string {
	return string(append([]byte{request.HType}, request.CHAddr...))
}
