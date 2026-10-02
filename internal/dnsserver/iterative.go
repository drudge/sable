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
	// The bounds on how long a name found inside a zone is remembered.
	defaultNoCutTTL = 300
	minimumNoCutTTL = 30
	maximumNoCutTTL = 3600
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

// iterativeBudget caps the queries one lookup may send. Name-server addresses
// are found in parallel, so it is shared between goroutines.
type iterativeBudget struct {
	mu        sync.Mutex
	remaining int
	// shared holds the questions in flight once the lookup has gone
	// parallel. The A and AAAA lookups of one name server walk the same
	// zones, and each question they share is asked once.
	shared map[sharedExchangeKey]*sharedExchange
}

type sharedExchangeKey struct {
	name       string
	recordType uint16
	server     string
}

// sharedExchange is one question to a zone's servers that several parts of a
// lookup are waiting on.
type sharedExchange struct {
	key      sharedExchangeKey
	done     chan struct{}
	waiters  int
	response *dns.Msg
	err      error
}

// goParallel makes the lookup's questions shared from here on.
func (budget *iterativeBudget) goParallel() {
	budget.mu.Lock()
	defer budget.mu.Unlock()
	if budget.shared == nil {
		budget.shared = make(map[sharedExchangeKey]*sharedExchange)
	}
}

// join returns the exchange in flight for a question to servers, and whether
// the caller is the one to send it. It returns nothing until the lookup goes
// parallel.
func (budget *iterativeBudget) join(request *dns.Msg, servers []string) (*sharedExchange, bool) {
	budget.mu.Lock()
	defer budget.mu.Unlock()
	if budget.shared == nil {
		return nil, false
	}
	key := sharedExchangeKey{name: normalizeName(request.Question[0].Name), recordType: request.Question[0].Qtype, server: servers[0]}
	if call, found := budget.shared[key]; found {
		call.waiters++
		return call, false
	}
	call := &sharedExchange{key: key, done: make(chan struct{})}
	budget.shared[key] = call
	return call, true
}

// settle hands the sender's result to the others waiting on the question.
func (budget *iterativeBudget) settle(call *sharedExchange, response *dns.Msg, err error) {
	budget.mu.Lock()
	delete(budget.shared, call.key)
	if call.waiters > 0 && response != nil {
		// The sender goes on to change its response.
		call.response = response.Copy()
	}
	call.err = err
	budget.mu.Unlock()
	close(call.done)
}

func (call *sharedExchange) wait(ctx context.Context) (*dns.Msg, error) {
	select {
	case <-call.done:
		if call.response == nil {
			return nil, call.err
		}
		return call.response.Copy(), call.err
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// take spends one query, reporting false when none are left.
func (budget *iterativeBudget) take() bool {
	budget.mu.Lock()
	defer budget.mu.Unlock()
	if budget.remaining <= 0 {
		return false
	}
	budget.remaining--
	return true
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

// zoneCutCache remembers names QNAME minimization found inside a zone rather
// than delegated from it, keyed by the name and holding the zone. A later
// lookup below such a name starts its minimization past it instead of asking
// the zone's servers the same question again, which matters most for long
// alias chains and for DNSSEC validation, which walks the same names again.
type zoneCutCache struct{ *addressCache }

func newZoneCutCache(capacity int) *zoneCutCache {
	return &zoneCutCache{addressCache: newAddressCache(capacity)}
}

// record notes that name sits inside zone, with no delegation of its own.
func (cache *zoneCutCache) record(name, zone string, ttl uint32, now time.Time) {
	cache.set(name, []string{dns.Fqdn(zone)}, ttl, now)
}

// walked returns the deepest name at or above name known to sit inside zone,
// or nothing when no such name is known.
func (cache *zoneCutCache) walked(name, zone string, now time.Time) string {
	zone = dns.Fqdn(zone)
	name = normalizeName(name)
	cache.mu.Lock()
	defer cache.mu.Unlock()
	for current := name; current != ""; {
		if dns.Fqdn(current) == zone {
			break
		}
		if recorded, found := cache.lookupLocked(current, now); found && len(recorded) == 1 && recorded[0] == zone {
			return dns.Fqdn(current)
		}
		separator := strings.IndexByte(current, '.')
		if separator < 0 {
			break
		}
		current = current[separator+1:]
	}
	return ""
}

// noCutTTL is how long a name found inside a zone is remembered: the zone's
// negative-answer TTL when the response carries its SOA, within bounds.
func noCutTTL(response *dns.Msg) uint32 {
	ttl := uint32(defaultNoCutTTL)
	for _, record := range response.Ns {
		if soa, ok := record.(*dns.SOA); ok {
			ttl = min(soa.Hdr.Ttl, soa.Minttl)
		}
	}
	return min(max(ttl, minimumNoCutTTL), maximumNoCutTTL)
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
	// DS records belong to the parent side of a delegation, even when the
	// child authority was cached by an earlier lookup.
	cacheName := question.Name
	if question.Qtype == dns.TypeDS {
		cacheName = parentFQDN(question.Name)
	}
	if zone, cachedServers, found := runtime.delegations.get(cacheName, time.Now()); found {
		closestZone, servers = zone, cachedServers
	}
	visited := make(map[string]struct{})
	walked := runtime.walkedNames(cacheName, closestZone)

	// Query only successive delegation names until the closest authority is
	// reached. The final owner and record type are withheld from parent zones.
	candidates := minimizedDelegationNames(question.Name)
	if !runtime.qnameMinimization {
		// Every server is asked for the full name, and referrals are followed
		// as they come.
		candidates = nil
	}
minimizing:
	for _, candidate := range candidates {
		if closestZone != "" && (candidate == dns.Fqdn(closestZone) || strings.HasSuffix(dns.Fqdn(closestZone), candidate)) {
			continue
		}
		// A name already found inside the closest zone, and every name above
		// it, needs no second look.
		if walked != "" && dns.IsSubDomain(candidate, walked) {
			continue
		}
		response, err := handler.exchangeIterative(ctx, iterativeQuery(candidate, dns.TypeNS), servers, runtime, budget)
		if err != nil {
			return nil, err
		}
		zone, names, referral := referralFrom(response, question.Name)
		// Only a delegation below the servers already reached moves the search
		// on. Some servers, such as Amazon Route 53, list their own zone's name
		// servers beside every answer, including a wildcard CNAME they give for
		// an intermediate name, and that is an answer about this zone, not a
		// referral away from it.
		if !referral || len(response.Answer) > 0 || !belowZone(zone, closestZone) {
			switch {
			case aliasedAt(response, candidate):
				// The zone answers for this name itself, so it answers for
				// the full name too: ask it that now instead of label by label.
				break minimizing
			case response.Rcode == dns.RcodeSuccess && len(response.Answer) == 0:
				// No delegation here, only more of the same zone.
				runtime.recordWalked(candidate, closestZone, noCutTTL(response))
			case response.Authoritative && apexAt(response, candidate):
				// The servers answer for the zone below themselves, as the
				// uk servers do for co.uk. Remembering that saves asking
				// again for every name under it.
				closestZone = candidate
				runtime.delegations.set(candidate, servers, apexTTL(response, candidate), time.Now())
				walked = runtime.walkedNames(cacheName, closestZone)
			}
			continue
		}
		if _, duplicate := visited[zone]; duplicate {
			return nil, fmt.Errorf("iterative resolution encountered a referral loop at %s", dns.Fqdn(zone))
		}
		visited[zone] = struct{}{}
		servers, err = handler.referralServers(ctx, closestZone, zone, names, response.Extra, runtime, budget, depth+1)
		if err != nil {
			return nil, err
		}
		closestZone = zone
		runtime.delegations.set(zone, servers, referralTTL(response), time.Now())
		walked = runtime.walkedNames(cacheName, closestZone)
	}

	var cnameChain []dns.RR
	current := question
	for hops := 0; hops <= maximumIterativeDepth; hops++ {
		response, err := handler.exchangeIterative(ctx, iterativeQuery(current.Name, current.Qtype), servers, runtime, budget)
		if err != nil {
			return nil, err
		}
		if target, cname := cnameTarget(response, current); cname != nil && current.Qtype != dns.TypeCNAME && !answerContainsType(response, current.Qtype) {
			// Keep only this alias and its signatures. A server may add the
			// next links of the chain, as Amazon Route 53 does within its own
			// zone, but the target is looked up next and brings them itself,
			// so keeping them here would list them twice.
			cnameChain = append(cnameChain, aliasRecords(response, current.Name)...)
			targetResponse, resolveErr := handler.resolveIterativeQuestion(ctx, dns.Question{Name: target, Qtype: current.Qtype, Qclass: current.Qclass}, runtime, budget, depth+1)
			if resolveErr != nil {
				return nil, resolveErr
			}
			targetResponse.Answer = append(cnameChain, targetResponse.Answer...)
			return targetResponse, nil
		}
		if iterativeTerminal(response) {
			scrubOutOfBailiwick(response, closestZone)
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
		servers, err = handler.referralServers(ctx, closestZone, zone, names, response.Extra, runtime, budget, depth+1)
		if err != nil {
			return nil, err
		}
		closestZone = zone
		runtime.delegations.set(zone, servers, referralTTL(response), time.Now())
	}
	return nil, errors.New("iterative resolution exceeded the maximum alias depth")
}

// authorityAttemptTimeout is how long an authoritative server is waited on
// before the next server for the zone is asked. Authorities answer in tens of
// milliseconds from almost anywhere, so this is several round trips even on a
// slow path.
const authorityAttemptTimeout = 800 * time.Millisecond

// minimumFairTurn is the least time an authoritative server must have had
// before a failure counts against it.
const minimumFairTurn = 500 * time.Millisecond

func attemptGotFairTurn(ctx context.Context) bool {
	deadline, bounded := ctx.Deadline()
	return !bounded || time.Until(deadline) >= minimumFairTurn
}

// scrubOutOfBailiwick drops the authority and additional records a zone's
// servers have no say over, as BIND and Unbound do before trusting or
// validating anything. Some servers add them anyway: Comcast's for
// 94.19.96.in-addr.arpa list name servers for 19.96.in-addr.arpa above it,
// and Vultr's for a single address's reverse zone give an SOA for all of
// in-addr.arpa. Neither is signed, while the zones they name are, so the
// answer failed DNSSEC validation over records that weren't part of it.
func scrubOutOfBailiwick(response *dns.Msg, zone string) {
	zone = dns.Fqdn(zone)
	outside := func(record dns.RR) bool {
		return record.Header().Rrtype != dns.TypeOPT && !dns.IsSubDomain(zone, dns.Fqdn(record.Header().Name))
	}
	response.Ns = slices.DeleteFunc(response.Ns, outside)
	response.Extra = slices.DeleteFunc(response.Extra, outside)
}

// aliasRecords returns the CNAME an answer gives name, with the RRSIGs that
// sign it.
func aliasRecords(response *dns.Msg, name string) []dns.RR {
	owner := normalizeName(name)
	records := make([]dns.RR, 0, 2)
	for _, record := range response.Answer {
		if normalizeName(record.Header().Name) != owner {
			continue
		}
		switch current := record.(type) {
		case *dns.CNAME:
			records = append(records, record)
		case *dns.RRSIG:
			if current.TypeCovered == dns.TypeCNAME {
				records = append(records, record)
			}
		}
	}
	return records
}

// apexAt reports an answer that gives name's own NS records, making it a
// zone's apex.
func apexAt(response *dns.Msg, name string) bool {
	for _, record := range response.Answer {
		if nameServer, ok := record.(*dns.NS); ok && normalizeName(nameServer.Hdr.Name) == normalizeName(name) {
			return true
		}
	}
	return false
}

// apexTTL is how long the zone at name may be remembered: its NS records'
// TTL, no longer than a day.
func apexTTL(response *dns.Msg, name string) uint32 {
	ttl := maximumDelegationTTL
	for _, record := range response.Answer {
		if nameServer, ok := record.(*dns.NS); ok && normalizeName(nameServer.Hdr.Name) == normalizeName(name) {
			ttl = min(ttl, nameServer.Hdr.Ttl)
		}
	}
	return ttl
}

// aliasedAt reports an answer that makes name an alias, whether a CNAME the
// zone holds or one a wildcard gave it.
func aliasedAt(response *dns.Msg, name string) bool {
	for _, record := range response.Answer {
		if alias, ok := record.(*dns.CNAME); ok && normalizeName(alias.Hdr.Name) == normalizeName(name) {
			return true
		}
	}
	return false
}

// walkedNames and recordWalked use the zone cut cache when this runtime has
// one.
func (runtime *Runtime) walkedNames(name, zone string) string {
	if runtime.zoneCuts == nil {
		return ""
	}
	return runtime.zoneCuts.walked(name, zone, time.Now())
}

func (runtime *Runtime) recordWalked(name, zone string, ttl uint32) {
	if runtime.zoneCuts != nil {
		runtime.zoneCuts.record(name, zone, ttl, time.Now())
	}
}

// belowZone reports whether zone is strictly inside parent. An empty parent is
// the root.
func belowZone(zone, parent string) bool {
	zone, parent = dns.Fqdn(zone), dns.Fqdn(parent)
	return zone != parent && dns.IsSubDomain(parent, zone)
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
	call, sender := budget.join(request, servers)
	if call == nil {
		return handler.exchangeAuthorities(ctx, request, servers, runtime, budget)
	}
	if !sender {
		return call.wait(ctx)
	}
	response, err := handler.exchangeAuthorities(ctx, request, servers, runtime, budget)
	budget.settle(call, response, err)
	return response, err
}

// exchangeAuthorities asks a zone's servers a question, one after another
// until one answers.
func (handler *Handler) exchangeAuthorities(
	ctx context.Context,
	request *dns.Msg,
	servers []string,
	runtime *Runtime,
	budget *iterativeBudget,
) (*dns.Msg, error) {
	start := handler.upstreamIndex.Add(1) - 1
	// A server that just timed out is asked last for a while, so one that is
	// unreachable from here does not cost every lookup its share of the time.
	ordered := handler.authorityHealth.order(servers, start)
	var failures []error
	for offset, server := range ordered {
		// Out of time, no server gets a real turn, so none is tried or counted.
		if err := ctx.Err(); err != nil {
			failures = append(failures, fmt.Errorf("ran out of time before asking %s: %w", server, err))
			break
		}
		if !budget.take() {
			return nil, errors.New("iterative resolution exceeded its query budget")
		}
		attemptContext, release := forwarderBudget(ctx, len(servers)-offset)
		fair := attemptGotFairTurn(attemptContext)
		// The zone's other servers are its retries: one that is silent for
		// authorityAttemptTimeout is passed over for the next, rather than
		// asked again at the full retry timeout. Only the last server left
		// gets the configured retries.
		retryTimeout, retries := min(runtime.retryTimeout, authorityAttemptTimeout), 1
		if offset == len(ordered)-1 {
			retryTimeout, retries = runtime.retryTimeout, runtime.retries
		}
		response, err := handler.exchangeWithRetries(attemptContext, request, "udp://"+server, retryTimeout, retries)
		release()
		if err != nil {
			// A server is only held against when it had a fair turn: the
			// lookup's last moments, split many ways, prove nothing about it.
			if ctx.Err() == nil && fair {
				handler.authorityHealth.markUnhealthy(server)
			}
			failures = append(failures, fmt.Errorf("%s: %w", server, err))
			continue
		}
		handler.authorityHealth.markHealthy(server)
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
	parentZone string,
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
		// Glue is scoped to the referring parent, which may supply sibling
		// addresses (for example, the root supplies .com servers under .net).
		if _, matches := wanted[owner]; !matches || !dns.IsSubDomain(dns.Fqdn(parentZone), dns.Fqdn(owner)) {
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
	// A name server's own addresses are worth remembering beyond the zone that
	// sent us here: one host commonly serves many delegations, and without this
	// every cold delegation resolves the same host again from the root. Only
	// fully resolved answers are stored. Glue stays confined to the delegation
	// that carried it, because it is unverified data from the parent zone.
	var unresolved []string
	for _, name := range nameServers {
		if resolved[name] {
			continue
		}
		if cached, found := runtime.nameServers.get(name, time.Now()); found {
			addresses = append(addresses, cached...)
			continue
		}
		unresolved = append(unresolved, name)
	}
	// Names outside the parent's zone, as Route 53 and Akamai use, each need
	// a lookup of their own. A few are looked up at once, A and AAAA side by
	// side, so a cold chain waits for the slowest of them rather than for
	// all of them in turn.
	for len(addresses) < 4 && len(unresolved) > 0 {
		batch := unresolved[:min(len(unresolved), parallelNameServerLookups)]
		unresolved = unresolved[len(batch):]
		addresses = append(addresses, handler.resolveNameServerAddresses(ctx, batch, runtime, budget, depth)...)
	}
	addresses = slices.Compact(addresses)
	if len(addresses) == 0 {
		return nil, fmt.Errorf("delegation for %s has no resolvable name servers", dns.Fqdn(zone))
	}
	return addresses, nil
}

// parallelNameServerLookups is how many name servers' addresses are looked
// up at once when a referral carries no usable glue.
const parallelNameServerLookups = 2

// resolveNameServerAddresses looks up the A and AAAA records of names all at
// once, remembers each name's addresses, and returns them in the order of
// names, IPv4 first.
func (handler *Handler) resolveNameServerAddresses(ctx context.Context, names []string, runtime *Runtime, budget *iterativeBudget, depth int) []string {
	budget.goParallel()
	recordTypes := []uint16{dns.TypeA, dns.TypeAAAA}
	found := make([][]dns.RR, len(names)*len(recordTypes))
	var wait sync.WaitGroup
	for index := range found {
		name, recordType := names[index/len(recordTypes)], recordTypes[index%len(recordTypes)]
		wait.Go(func() {
			response, err := handler.resolveIterativeQuestion(ctx, dns.Question{Name: dns.Fqdn(name), Qtype: recordType, Qclass: dns.ClassINET}, runtime, budget, depth)
			if err == nil {
				found[index] = response.Answer
			}
		})
	}
	wait.Wait()
	var addresses []string
	for nameIndex, name := range names {
		discovered := make([]string, 0, 2)
		ttl := maximumDelegationTTL
		for _, records := range found[nameIndex*len(recordTypes) : (nameIndex+1)*len(recordTypes)] {
			for _, record := range records {
				if address, ok := addressFromRecord(record); ok {
					discovered = append(discovered, net.JoinHostPort(address.String(), "53"))
					ttl = min(ttl, record.Header().Ttl)
				}
			}
		}
		runtime.nameServers.set(name, discovered, ttl, time.Now())
		addresses = append(addresses, discovered...)
	}
	return addresses
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

// detachedLookup is a recursive lookup, with its DNSSEC validation, that runs
// to its own deadline apart from the clients waiting on it.
type detachedLookup struct {
	// fetched closes when the network part is done and validation starts;
	// done closes when the result is ready.
	fetched    chan struct{}
	done       chan struct{}
	response   *dns.Msg
	validation validationState
	err        error
	finishedAt time.Time
	// The fields below are guarded by Handler.detachedMu. waiting counts the
	// clients still waiting, so the lookup knows when it must cache its own
	// answer.
	hasFetched bool
	finished   bool
	waiting    int
}

// detachedAnswerGrace is how long a finished recursive lookup keeps its
// answer for a client that asks again. A device whose first question timed
// out retries within a few seconds, and the lookup it started is often what
// it is waiting for.
const detachedAnswerGrace = 5 * time.Second

// errStillRunning reports that a client stopped waiting while its recursive
// lookup kept going. The lookup caches its answer when it finishes, so the
// failure says nothing about the name and must not be cached as one.
var errStillRunning = errors.New("recursive resolution is still running and will finish for a retry")

// recursiveFinishBudget is how long a recursive lookup may keep working after
// its client stopped waiting. A cold chain through several providers can take
// several seconds, more than a client waits, and finishing it means the
// client's retry is answered from the cache.
func recursiveFinishBudget(runtime *Runtime) time.Duration {
	return max(4*runtime.timeout, 8*time.Second)
}

// resolveRecursiveWaiting resolves and validates a recursive request, waiting
// no longer than wait. The lookup itself runs on apart from the wait, up to
// recursiveFinishBudget, and a second client asking the same question
// meanwhile waits on the same lookup. A lookup that every client stopped
// waiting for caches its own answer when it finishes.
func (handler *Handler) resolveRecursiveWaiting(ctx context.Context, request *dns.Msg, runtime *Runtime, wait time.Duration) (*dns.Msg, validationState, error) {
	// Clients share a lookup whenever they would send the same question
	// upstream, which with validation on ignores their DO and CD bits.
	upstreamRequest := request
	if runtime.dnssec != nil {
		upstreamRequest = dnssecUpstreamRequest(request)
	}
	key := coalesceKey(upstreamRequest)
	key.runtime = runtime
	handler.detachedMu.Lock()
	lookup, running := handler.detached[key]
	if !running {
		// Detached lookups are bounded like the requests that start them, so
		// a flood of names that never resolve cannot pile up work.
		if len(handler.detached) >= runtime.maxConcurrent || !handler.startBackground() {
			handler.detachedMu.Unlock()
			return handler.fetchAndValidate(ctx, request, runtime, nil, wait)
		}
		if handler.detached == nil {
			handler.detached = make(map[inflightKey]*detachedLookup)
		}
		lookup = &detachedLookup{fetched: make(chan struct{}), done: make(chan struct{})}
		handler.detached[key] = lookup
		go handler.finishRecursiveLookup(key, lookup, request.Copy(), runtime)
	}
	lookup.waiting++
	handler.detachedMu.Unlock()
	// The client waits for the network as long as wait allows. Validation
	// then has its own budget, as it does for a lookup a client runs itself.
	waitContext, cancel := context.WithTimeout(ctx, wait)
	defer cancel()
	select {
	case <-lookup.fetched:
	case <-waitContext.Done():
		handler.detachedMu.Lock()
		fetched := lookup.hasFetched
		if !fetched {
			lookup.waiting--
		}
		handler.detachedMu.Unlock()
		if !fetched {
			return nil, validationIndeterminate, fmt.Errorf("%w: %w", errStillRunning, waitContext.Err())
		}
	}
	select {
	case <-lookup.done:
		return lookup.answer()
	case <-ctx.Done():
		return nil, validationIndeterminate, ctx.Err()
	}
}

// finishRecursiveLookup runs a detached lookup to its end. request is the
// question of the client that started it.
func (handler *Handler) finishRecursiveLookup(key inflightKey, lookup *detachedLookup, request *dns.Msg, runtime *Runtime) {
	defer handler.backgroundWG.Done()
	response, err := handler.fetchUpstream(handler.backgroundContext, request, runtime, nil, recursiveFinishBudget(runtime))
	handler.detachedMu.Lock()
	lookup.hasFetched = true
	handler.detachedMu.Unlock()
	close(lookup.fetched)
	response, validation, err := handler.validateUpstream(handler.backgroundContext, request, runtime, response, err)
	handler.detachedMu.Lock()
	lookup.response, lookup.validation, lookup.err = response, validation, err
	lookup.finishedAt = time.Now()
	lookup.finished = true
	abandoned := lookup.waiting == 0
	handler.detachedMu.Unlock()
	close(lookup.done)
	forget := func() {
		handler.detachedMu.Lock()
		if handler.detached[key] == lookup {
			delete(handler.detached, key)
		}
		handler.detachedMu.Unlock()
	}
	if err != nil || response == nil {
		forget()
		return
	}
	// No client is left to cache the answer, so the lookup does, and their
	// retry is a cache hit, validation and all.
	if abandoned {
		runtime.cacheUpstreamAnswer(request, response.Copy(), validation)
	}
	time.AfterFunc(detachedAnswerGrace, forget)
}

// answer returns a client's own copy of a finished lookup's result.
func (lookup *detachedLookup) answer() (*dns.Msg, validationState, error) {
	if lookup.response == nil {
		return nil, lookup.validation, lookup.err
	}
	response := lookup.response.Copy()
	// An answer kept for a retry has aged since it arrived.
	if elapsed := time.Since(lookup.finishedAt) / time.Second; elapsed > 0 {
		decrementTTLs(response, uint32(elapsed))
	}
	return response, lookup.validation, lookup.err
}
