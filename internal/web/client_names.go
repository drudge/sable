package web

import (
	"context"
	"log/slog"
	"net/netip"
	"sync"
	"time"

	"github.com/drudge/sable/internal/web/pages"
)

// The console names the clients in its rankings by asking the resolver for a
// PTR, which is the only way to catch a name that lives outside the zones this
// server is authoritative for: a conditional forwarder pointed at a router, or
// a reverse zone answered upstream. Because that reaches the network, the
// lookups are capped, run in parallel, share a deadline, and are remembered, so
// a dashboard with hundreds of clients never becomes hundreds of DNS queries
// per render.
const (
	// reverseNameLimit is how many unnamed clients one render will look up. The
	// rankings are sorted by traffic, so the cap always spends itself on the
	// clients an operator is most likely to be looking at.
	reverseNameLimit = 50
	// reverseNameWorkers bounds how many of those run at once.
	reverseNameWorkers = 8
	// reverseNameBudget is how long a render waits. Lookups that miss it keep
	// running on their own deadline, so their answers are already cached by the
	// time the page is next drawn.
	reverseNameBudget   = 900 * time.Millisecond
	reverseNameDeadline = 3 * time.Second
	// A name is remembered far longer than a miss: hostnames on a home network
	// rarely move, while an address that has no PTR today may get one when the
	// next DHCP sync runs.
	reverseNameLifetime     = 30 * time.Minute
	reverseNameMissLifetime = 5 * time.Minute
)

type reverseResolver interface {
	ReverseLookup(context.Context, netip.Addr) (string, error)
}

type reverseNameEntry struct {
	name      string
	expiresAt time.Time
}

type reverseNameCache struct {
	mutex    sync.Mutex
	entries  map[string]reverseNameEntry
	inflight map[string]struct{}
	resolver reverseResolver
	logger   *slog.Logger
	now      func() time.Time
}

func newReverseNameCache(resolver reverseResolver, logger *slog.Logger) *reverseNameCache {
	return &reverseNameCache{
		entries:  make(map[string]reverseNameEntry),
		inflight: make(map[string]struct{}),
		resolver: resolver,
		logger:   logger,
		now:      time.Now,
	}
}

// names returns what is known for the given addresses, looking up the ones it
// has no unexpired answer for.
func (cache *reverseNameCache) names(addresses []string) map[string]string {
	if cache == nil || cache.resolver == nil {
		return nil
	}
	known, pending := cache.partition(addresses)
	if len(pending) > 0 {
		cache.resolve(pending)
		for _, address := range pending {
			if name, found := cache.cached(address); found && name != "" {
				known[address] = name
			}
		}
	}
	return known
}

// partition splits addresses into the ones already answered and the ones that
// need a lookup, claiming the latter so two renders at once ask only once.
func (cache *reverseNameCache) partition(addresses []string) (map[string]string, []string) {
	known := make(map[string]string, len(addresses))
	pending := make([]string, 0, len(addresses))
	moment := cache.now()

	cache.mutex.Lock()
	defer cache.mutex.Unlock()
	for _, address := range addresses {
		entry, cached := cache.entries[address]
		if cached && moment.Before(entry.expiresAt) {
			if entry.name != "" {
				known[address] = entry.name
			}
			continue
		}
		if _, claimed := cache.inflight[address]; claimed {
			continue
		}
		if len(pending) >= reverseNameLimit {
			continue
		}
		cache.inflight[address] = struct{}{}
		pending = append(pending, address)
	}
	return known, pending
}

func (cache *reverseNameCache) cached(address string) (string, bool) {
	cache.mutex.Lock()
	defer cache.mutex.Unlock()
	entry, found := cache.entries[address]
	if !found || !cache.now().Before(entry.expiresAt) {
		return "", false
	}
	return entry.name, true
}

func (cache *reverseNameCache) store(address, name string) {
	lifetime := reverseNameMissLifetime
	if name != "" {
		lifetime = reverseNameLifetime
	}
	cache.mutex.Lock()
	defer cache.mutex.Unlock()
	cache.entries[address] = reverseNameEntry{name: name, expiresAt: cache.now().Add(lifetime)}
	delete(cache.inflight, address)
}

// resolve looks the addresses up and waits out the render's budget. The lookups
// carry their own context so the ones that outlast the budget still finish and
// leave their answer behind for the next render.
func (cache *reverseNameCache) resolve(addresses []string) {
	ctx, cancel := context.WithTimeout(context.Background(), reverseNameDeadline)
	workers := make(chan struct{}, reverseNameWorkers)
	finished := make(chan struct{})
	var group sync.WaitGroup
	for _, address := range addresses {
		parsed, err := netip.ParseAddr(address)
		if err != nil {
			cache.store(address, "")
			continue
		}
		group.Add(1)
		go func(address string, parsed netip.Addr) {
			defer group.Done()
			workers <- struct{}{}
			defer func() { <-workers }()
			name, err := cache.resolver.ReverseLookup(ctx, parsed)
			if err != nil {
				// A client with no PTR is the ordinary case, not a fault, so
				// the miss is remembered at debug level and nothing else.
				cache.logger.Debug("reverse lookup for dashboard client", "address", address, "error", err)
				name = ""
			}
			cache.store(address, name)
		}(address, parsed)
	}
	go func() {
		group.Wait()
		cancel()
		close(finished)
	}()

	timer := time.NewTimer(reverseNameBudget)
	defer timer.Stop()
	select {
	case <-finished:
	case <-timer.C:
	}
}

// nameRankedClients fills in the hostname beside every client the local zones
// and host overrides could not already account for.
func (server *Server) nameRankedClients(clients []pages.RankedStatView) {
	if server.reverseNames == nil {
		return
	}
	unnamed := make([]string, 0, min(len(clients), reverseNameLimit))
	for _, client := range clients {
		if client.Secondary == "" {
			unnamed = append(unnamed, client.Name)
		}
	}
	if len(unnamed) == 0 {
		return
	}
	names := server.reverseNames.names(unnamed)
	for index := range clients {
		if clients[index].Secondary == "" {
			clients[index].Secondary = names[clients[index].Name]
		}
	}
}
