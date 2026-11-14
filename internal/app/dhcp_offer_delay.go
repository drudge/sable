package app

import (
	"sync"
	"time"

	"github.com/drudge/sable/internal/dhcp"
)

// dhcpMaxDelayedOffers bounds the OFFERs held back by offer_delay or a
// conflict probe (D29). A client's newer DISCOVER replaces its waiting OFFER,
// so this caps distinct clients, not repeats; past it the OFFER is dropped
// and counted.
const dhcpMaxDelayedOffers = 512

// dhcpDelayedOffers holds each client's OFFER until its offer_delay is up and
// its address has been probed. Waiting OFFERs are runtime timers, and a probe
// runs on its timer's goroutine, so there is at most one goroutine per
// client: a client takes only the reply carrying the xid of its latest
// DISCOVER (RFC 2131 §4.4.1), so a newer one replaces the older.
type dhcpDelayedOffers struct {
	mutex   sync.Mutex
	pending map[string]*dhcpDelayedOffer
	stopped bool
	// running counts timers that may still fire, so stop can wait them out.
	running sync.WaitGroup
}

// dhcpDelayedOffer is one client's waiting OFFER: the reply to its latest
// DISCOVER, sent when the first DISCOVER's delay is up and probe allows it.
type dhcpDelayedOffer struct {
	timer *time.Timer
	write func()
	// probe reports whether the offered address is still free; nil skips it.
	probe func() bool
}

// schedule sends write after delay once probe allows it, and reports false
// when too many other clients are already waiting. A client that retransmits
// before its OFFER goes out keeps its first deadline and probe, and gets the
// reply to its newest DISCOVER: restarting the clock would starve a client
// retrying faster than offer_delay (RFC 2131 §4.1 lets it retry from 1 s).
func (delayed *dhcpDelayedOffers) schedule(client string, delay time.Duration, write func(), probe func() bool) bool {
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
	offer := &dhcpDelayedOffer{write: write, probe: probe}
	delayed.running.Add(1)
	offer.timer = time.AfterFunc(delay, func() {
		defer delayed.running.Done()
		delayed.fire(client, offer)
	})
	delayed.pending[client] = offer
	return true
}

// fire probes the client's address, holding its slot meanwhile, then sends
// its newest OFFER unless the probe found the address taken or the server
// stopped.
func (delayed *dhcpDelayedOffers) fire(client string, offer *dhcpDelayedOffer) {
	if !delayed.current(client, offer) {
		return
	}
	free := offer.probe == nil || offer.probe()
	delayed.mutex.Lock()
	current := delayed.pending[client] == offer && !delayed.stopped
	write := offer.write
	if current {
		delete(delayed.pending, client)
	}
	delayed.mutex.Unlock()
	if current && free {
		write()
	}
}

// current reports whether offer is still the client's waiting one.
func (delayed *dhcpDelayedOffers) current(client string, offer *dhcpDelayedOffer) bool {
	delayed.mutex.Lock()
	defer delayed.mutex.Unlock()
	return delayed.pending[client] == offer && !delayed.stopped
}

// waiting reports how many OFFERs are held back.
func (delayed *dhcpDelayedOffers) waiting() int {
	delayed.mutex.Lock()
	defer delayed.mutex.Unlock()
	return len(delayed.pending)
}

// stop drops every waiting OFFER and waits for probes already running, so
// nothing is sent or queued after the server stops.
func (delayed *dhcpDelayedOffers) stop() {
	delayed.mutex.Lock()
	delayed.stopped = true
	for client, offer := range delayed.pending {
		if offer.timer.Stop() {
			delayed.running.Done()
		}
		delete(delayed.pending, client)
	}
	delayed.mutex.Unlock()
	delayed.running.Wait()
}

// dhcpOfferKey names the client an OFFER is for: the hardware type and
// address the reply is addressed to (RFC 2131 §4.1, chaddr).
func dhcpOfferKey(request dhcp.Packet) string {
	return string(append([]byte{request.HType}, request.CHAddr...))
}
