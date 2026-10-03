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
	client = canonicalClient(client)
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

// canonicalClient writes an address client in one form, so the IPv4 and
// IPv4-mapped forms of one address share a limit. Clients usually arrive in
// that form already, and then it's returned without allocating.
func canonicalClient(client string) string {
	address, err := netip.ParseAddr(client)
	if err != nil {
		return client
	}
	var buffer [64]byte
	canonical := address.Unmap().WithZone("").AppendTo(buffer[:0])
	if string(canonical) == client {
		return client
	}
	return string(canonical)
}
