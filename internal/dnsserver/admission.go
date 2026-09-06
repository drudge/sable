package dnsserver

import (
	"net/netip"
	"sync"
)

const (
	defaultMaxConcurrent          = 1024
	defaultMaxConcurrentPerClient = 64
	maximumConcurrentResolutions  = 65536
)

// Counts unresolved requests, including coalesced waiters and background work.
// Client entries exist only while work is active, so random source addresses
// cannot grow a permanent tracking table. Limits come from the active runtime;
// activation never resets work already in progress.
type resolutionAdmission struct {
	mu                             sync.Mutex
	active                         int
	clients                        map[string]int
	rejectedGlobal, rejectedClient uint64
}

func (admission *resolutionAdmission) acquire(client string, totalLimit, clientLimit int) (func(), bool) {
	if address, err := netip.ParseAddr(client); err == nil {
		client = address.Unmap().WithZone("").String()
	}
	admission.mu.Lock()
	defer admission.mu.Unlock()
	if admission.active >= totalLimit {
		admission.rejectedGlobal++
		return nil, false
	}
	if admission.clients[client] >= clientLimit {
		admission.rejectedClient++
		return nil, false
	}
	if admission.clients == nil {
		admission.clients = make(map[string]int)
	}
	admission.active++
	admission.clients[client]++
	return func() {
		admission.mu.Lock()
		defer admission.mu.Unlock()
		admission.active--
		admission.clients[client]--
		if admission.clients[client] == 0 {
			delete(admission.clients, client)
		}
	}, true
}

func (admission *resolutionAdmission) snapshot() (active, clients int, rejectedGlobal, rejectedClient uint64) {
	admission.mu.Lock()
	defer admission.mu.Unlock()
	return admission.active, len(admission.clients), admission.rejectedGlobal, admission.rejectedClient
}
