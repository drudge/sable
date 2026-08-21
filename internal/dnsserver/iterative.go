package dnsserver

import (
	"container/list"
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
)

const (
	maximumIterativeDepth   = 24
	maximumIterativeQueries = 96
	// Delegations and name-server addresses are held no longer than a day even
	// when the zone claims more, so a stale nameset cannot outlive a renumbering.
	maximumDelegationTTL = uint32(24 * 60 * 60)
)

// The IPv4 addresses in the IANA root hints change very rarely. Operators can
// override this seed list with resolver.root_hints without rebuilding Sable.
var defaultRootHints = []string{
	"198.41.0.4:53", "170.247.170.2:53", "192.33.4.12:53", "199.7.91.13:53",
	"192.203.230.10:53", "192.5.5.241:53", "192.112.36.4:53", "198.97.190.53:53",
	"192.36.148.17:53", "192.58.128.30:53", "193.0.14.129:53", "199.7.83.42:53",
	"202.12.27.33:53",
}

type iterativeBudget struct {
	remaining int
}

// addressCache is a small map of name to server addresses with per-entry expiry
// and least-recently-used eviction. It backs both the delegation cache and the
// name-server address cache. Eviction order matters: picking an arbitrary map
// entry, as this used to, could throw away the delegation the resolver was about
// to reuse while keeping one it had not touched in an hour.
type addressCache struct {
	mu       sync.Mutex
	entries  map[string]*list.Element
	recency  list.List
	capacity int
}

type addressEntry struct {
	key       string
	addresses []string
	expiresAt time.Time
}

func newAddressCache(capacity int) *addressCache {
	return &addressCache{entries: make(map[string]*list.Element), capacity: max(capacity, 1)}
}

func (cache *addressCache) get(name string, now time.Time) ([]string, bool) {
	cache.mu.Lock()
	defer cache.mu.Unlock()
	return cache.lookupLocked(normalizeName(name), now)
}

func (cache *addressCache) lookupLocked(name string, now time.Time) ([]string, bool) {
	element, found := cache.entries[name]
	if !found {
		return nil, false
	}
	entry := element.Value.(*addressEntry)
	if !now.Before(entry.expiresAt) {
		cache.removeLocked(element)
		return nil, false
	}
	cache.recency.MoveToFront(element)
	return slices.Clone(entry.addresses), true
}

func (cache *addressCache) set(name string, addresses []string, ttl uint32, now time.Time) {
	if ttl == 0 || len(addresses) == 0 {
		return
	}
	name = normalizeName(name)
	cache.mu.Lock()
	defer cache.mu.Unlock()
	entry := &addressEntry{key: name, addresses: slices.Clone(addresses), expiresAt: now.Add(time.Duration(ttl) * time.Second)}
	if element, found := cache.entries[name]; found {
		element.Value = entry
		cache.recency.MoveToFront(element)
		return
	}
	cache.entries[name] = cache.recency.PushFront(entry)
	for cache.recency.Len() > cache.capacity {
		cache.removeLocked(cache.recency.Back())
	}
}

func (cache *addressCache) removeLocked(element *list.Element) {
	if element == nil {
		return
	}
	delete(cache.entries, element.Value.(*addressEntry).key)
	cache.recency.Remove(element)
}

// delegationCache maps a zone to the addresses that serve it, and answers for the
// closest enclosing zone it knows so resolution can start below the root.
type delegationCache struct{ *addressCache }

func newDelegationCache(capacity int) *delegationCache {
	return &delegationCache{addressCache: newAddressCache(capacity)}
}

func (cache *delegationCache) get(name string, now time.Time) (string, []string, bool) {
	name = normalizeName(name)
	cache.mu.Lock()
	defer cache.mu.Unlock()
	for current := name; current != ""; {
		if servers, found := cache.lookupLocked(current, now); found {
			return current, servers, true
		}
		separator := strings.IndexByte(current, '.')
		if separator < 0 {
			break
		}
		current = current[separator+1:]
	}
	return "", nil, false
}

func (cache *delegationCache) set(zone string, servers []string, ttl uint32, now time.Time) {
	cache.addressCache.set(zone, servers, ttl, now)
}

func normalizeRootHints(configured []string) ([]string, error) {
	if len(configured) == 0 {
		return append([]string(nil), defaultRootHints...), nil
	}
	result := make([]string, 0, len(configured))
	for _, raw := range configured {
		host, port, err := net.SplitHostPort(strings.TrimSpace(raw))
		if err != nil || port == "" {
			return nil, fmt.Errorf("root hint %q must be an IP address with a port", raw)
		}
		address, err := netip.ParseAddr(strings.Trim(host, "[]"))
		if err != nil || address.Zone() != "" {
			return nil, fmt.Errorf("root hint %q must use an IPv4 or IPv6 address", raw)
		}
		result = append(result, net.JoinHostPort(address.String(), port))
	}
	return slices.Compact(result), nil
}

func (handler *Handler) resolveNetwork(request *dns.Msg, runtime *Runtime, forwarders []string) (*dns.Msg, error) {
	ctx, cancel := context.WithTimeout(context.Background(), runtime.timeout)
	defer cancel()
	return handler.resolveNetworkContext(ctx, request, runtime, forwarders)
}

func (handler *Handler) resolveNetworkContext(
	ctx context.Context,
	request *dns.Msg,
	runtime *Runtime,
	forwarders []string,
) (*dns.Msg, error) {
	if len(forwarders) > 0 {
		return handler.exchangeContext(ctx, request, runtime, forwarders)
	}
	if runtime.mode != "recursive" {
		return nil, errors.New("no default forwarders are configured")
	}
	if len(request.Question) != 1 || request.Opcode != dns.OpcodeQuery {
		return nil, errors.New("iterative resolution requires one standard DNS question")
	}
	budget := &iterativeBudget{remaining: maximumIterativeQueries}
	response, err := handler.resolveIterativeQuestion(ctx, request.Question[0], runtime, budget, 0)
	if response == nil {
		return nil, err
	}
	response.Id = request.Id
	response.Question = append(response.Question[:0], request.Question...)
	response.RecursionDesired = request.RecursionDesired
	response.RecursionAvailable = true
	response.Authoritative = false
	return response, err
}

func (handler *Handler) resolveIterativeQuestion(
	ctx context.Context,
	question dns.Question,
	runtime *Runtime,
	budget *iterativeBudget,
	depth int,
) (*dns.Msg, error) {
	if depth > maximumIterativeDepth {
		return nil, errors.New("iterative resolution exceeded the maximum delegation depth")
	}
	servers := append([]string(nil), runtime.rootHints...)
	closestZone := ""
	if zone, cachedServers, found := runtime.delegations.get(question.Name, time.Now()); found {
		closestZone, servers = zone, cachedServers
	}
	visited := make(map[string]struct{})

	// Query only successive delegation names until the closest authority is
	// reached. The final owner and record type are withheld from parent zones.
	for _, candidate := range minimizedDelegationNames(question.Name) {
		if closestZone != "" && (candidate == dns.Fqdn(closestZone) || strings.HasSuffix(dns.Fqdn(closestZone), candidate)) {
			continue
		}
		response, err := handler.exchangeIterative(ctx, iterativeQuery(candidate, dns.TypeNS), servers, runtime, budget)
		if err != nil {
			return nil, err
		}
		zone, names, referral := referralFrom(response, question.Name)
		if !referral {
			continue
		}
		if _, duplicate := visited[zone]; duplicate {
			return nil, fmt.Errorf("iterative resolution encountered a referral loop at %s", dns.Fqdn(zone))
		}
		visited[zone] = struct{}{}
		servers, err = handler.referralServers(ctx, zone, names, response.Extra, runtime, budget, depth+1)
		if err != nil {
			return nil, err
		}
		runtime.delegations.set(zone, servers, referralTTL(response), time.Now())
	}

	var cnameChain []dns.RR
	current := question
	for hops := 0; hops <= maximumIterativeDepth; hops++ {
		response, err := handler.exchangeIterative(ctx, iterativeQuery(current.Name, current.Qtype), servers, runtime, budget)
		if err != nil {
			return nil, err
		}
		if target, cname := cnameTarget(response, current); cname != nil && current.Qtype != dns.TypeCNAME && !answerContainsType(response, current.Qtype) {
			cnameChain = append(cnameChain, response.Answer...)
			targetResponse, resolveErr := handler.resolveIterativeQuestion(ctx, dns.Question{Name: target, Qtype: current.Qtype, Qclass: current.Qclass}, runtime, budget, depth+1)
			if resolveErr != nil {
				return nil, resolveErr
			}
			targetResponse.Answer = append(cnameChain, targetResponse.Answer...)
			return targetResponse, nil
		}
		if iterativeTerminal(response) {
			if len(cnameChain) > 0 {
				response.Answer = append(cnameChain, response.Answer...)
			}
			return response, nil
		}
		zone, names, referral := referralFrom(response, current.Name)
		if !referral {
			return nil, fmt.Errorf("authority returned neither an answer nor a referral for %s", dns.Fqdn(current.Name))
		}
		if _, duplicate := visited[zone]; duplicate {
			return nil, fmt.Errorf("iterative resolution encountered a referral loop at %s", dns.Fqdn(zone))
		}
		visited[zone] = struct{}{}
		servers, err = handler.referralServers(ctx, zone, names, response.Extra, runtime, budget, depth+1)
		if err != nil {
			return nil, err
		}
		runtime.delegations.set(zone, servers, referralTTL(response), time.Now())
	}
	return nil, errors.New("iterative resolution exceeded the maximum alias depth")
}

func iterativeQuery(name string, recordType uint16) *dns.Msg {
	message := new(dns.Msg)
	message.SetQuestion(dns.Fqdn(name), recordType)
	message.RecursionDesired = false
	message.CheckingDisabled = true
	message.SetEdns0(1232, true)
	return message
}

func minimizedDelegationNames(name string) []string {
	labels := dns.SplitDomainName(dns.Fqdn(name))
	if len(labels) < 2 {
		return nil
	}
	result := make([]string, 0, len(labels)-1)
	for start := len(labels) - 1; start > 0; start-- {
		result = append(result, strings.Join(labels[start:], ".")+".")
	}
	return result
}

func (handler *Handler) exchangeIterative(
	ctx context.Context,
	request *dns.Msg,
	servers []string,
	runtime *Runtime,
	budget *iterativeBudget,
) (*dns.Msg, error) {
	if len(servers) == 0 {
		return nil, errors.New("delegation contains no reachable name-server addresses")
	}
	start := handler.upstreamIndex.Add(1) - 1
	var failures []error
	for offset := range len(servers) {
		if budget.remaining <= 0 {
			return nil, errors.New("iterative resolution exceeded its query budget")
		}
		budget.remaining--
		server := servers[(start+uint64(offset))%uint64(len(servers))]
		response, err := handler.exchangeWithRetries(ctx, request, "udp://"+server, runtime.retryTimeout, runtime.retries)
		if err != nil {
			failures = append(failures, fmt.Errorf("%s: %w", server, err))
			continue
		}
		if response.Rcode == dns.RcodeServerFailure || response.Rcode == dns.RcodeRefused {
			failures = append(failures, fmt.Errorf("%s returned %s", server, dns.RcodeToString[response.Rcode]))
			continue
		}
		return response, nil
	}
	return nil, fmt.Errorf("all authoritative servers failed: %w", errors.Join(failures...))
}

func referralFrom(response *dns.Msg, queryName string) (string, []string, bool) {
	queryName = normalizeName(queryName)
	byZone := make(map[string][]string)
	for _, record := range response.Ns {
		nameServer, ok := record.(*dns.NS)
		if !ok {
			continue
		}
		zone := normalizeName(nameServer.Hdr.Name)
		if queryName != zone && !strings.HasSuffix(queryName, "."+zone) {
			continue
		}
		byZone[zone] = append(byZone[zone], normalizeName(nameServer.Ns))
	}
	zone := ""
	for candidate := range byZone {
		if len(candidate) > len(zone) {
			zone = candidate
		}
	}
	if zone == "" {
		return "", nil, false
	}
	return zone, slices.Compact(byZone[zone]), true
}

func referralTTL(response *dns.Msg) uint32 {
	ttl := maximumDelegationTTL
	found := false
	for _, record := range response.Ns {
		if record.Header().Rrtype != dns.TypeNS {
			continue
		}
		found = true
		ttl = min(ttl, record.Header().Ttl)
	}
	if !found {
		return 0
	}
	return ttl
}

func (handler *Handler) referralServers(
	ctx context.Context,
	zone string,
	nameServers []string,
	additional []dns.RR,
	runtime *Runtime,
	budget *iterativeBudget,
	depth int,
) ([]string, error) {
	wanted := make(map[string]struct{}, len(nameServers))
	for _, name := range nameServers {
		wanted[name] = struct{}{}
	}
	addresses := make([]string, 0, len(nameServers)*2)
	resolved := make(map[string]bool, len(nameServers))
	for _, record := range additional {
		owner := normalizeName(record.Header().Name)
		if _, matches := wanted[owner]; !matches || (owner != zone && !strings.HasSuffix(owner, "."+zone)) {
			continue
		}
		if address, ok := addressFromRecord(record); ok {
			addresses = append(addresses, net.JoinHostPort(address.String(), "53"))
			resolved[owner] = true
		}
	}
	if len(addresses) >= 2 {
		return slices.Compact(addresses), nil
	}
	for _, name := range nameServers {
		if resolved[name] {
			continue
		}
		// A name server's own addresses are worth remembering beyond the zone that
		// sent us here: one host commonly serves many delegations, and without this
		// every cold delegation resolves the same host again from the root. Only
		// fully resolved answers are stored. Glue stays confined to the delegation
		// that carried it, because it is unverified data from the parent zone.
		if cached, found := runtime.nameServers.get(name, time.Now()); found {
			addresses = append(addresses, cached...)
			if len(addresses) >= 4 {
				break
			}
			continue
		}
		discovered := make([]string, 0, 2)
		ttl := maximumDelegationTTL
		for _, recordType := range []uint16{dns.TypeA, dns.TypeAAAA} {
			response, err := handler.resolveIterativeQuestion(ctx, dns.Question{Name: dns.Fqdn(name), Qtype: recordType, Qclass: dns.ClassINET}, runtime, budget, depth)
			if err != nil {
				continue
			}
			for _, record := range response.Answer {
				if address, ok := addressFromRecord(record); ok {
					discovered = append(discovered, net.JoinHostPort(address.String(), "53"))
					ttl = min(ttl, record.Header().Ttl)
				}
			}
		}
		runtime.nameServers.set(name, discovered, ttl, time.Now())
		addresses = append(addresses, discovered...)
		if len(addresses) >= 4 {
			break
		}
	}
	addresses = slices.Compact(addresses)
	if len(addresses) == 0 {
		return nil, fmt.Errorf("delegation for %s has no resolvable name servers", dns.Fqdn(zone))
	}
	return addresses, nil
}

func addressFromRecord(record dns.RR) (netip.Addr, bool) {
	switch current := record.(type) {
	case *dns.A:
		address, ok := netip.AddrFromSlice(current.A)
		return address.Unmap(), ok
	case *dns.AAAA:
		address, ok := netip.AddrFromSlice(current.AAAA)
		return address.Unmap(), ok
	default:
		return netip.Addr{}, false
	}
}

func cnameTarget(response *dns.Msg, question dns.Question) (string, dns.RR) {
	owner := normalizeName(question.Name)
	for _, record := range response.Answer {
		alias, ok := record.(*dns.CNAME)
		if ok && normalizeName(alias.Hdr.Name) == owner {
			return dns.Fqdn(alias.Target), record
		}
	}
	return "", nil
}

func answerContainsType(response *dns.Msg, recordType uint16) bool {
	for _, record := range response.Answer {
		if record.Header().Rrtype == recordType {
			return true
		}
	}
	return false
}

func iterativeTerminal(response *dns.Msg) bool {
	if response.Rcode != dns.RcodeSuccess || len(response.Answer) > 0 || response.Authoritative {
		return true
	}
	for _, record := range response.Ns {
		if record.Header().Rrtype == dns.TypeSOA {
			return true
		}
	}
	return false
}
