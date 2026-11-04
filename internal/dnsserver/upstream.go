package dnsserver

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"

	"github.com/drudge/sable/internal/forwarding"
)

// forwarderList is the endpoints a query may be forwarded to, in the order of
// their priority.
type forwarderList struct {
	endpoints []string
	// ranks gives each endpoint's priority rank, never decreasing along
	// endpoints. Only endpoints of one rank share the load, and a rank is
	// tried only after every endpoint of the ranks before it. Nil puts every
	// endpoint in one rank, which is how resolver.forwarders, configured
	// routes, and stub zones behave.
	ranks []int
}

func forwardersOf(endpoints []string) forwarderList {
	return forwarderList{endpoints: endpoints}
}

func (list forwarderList) empty() bool { return len(list.endpoints) == 0 }

func (handler *Handler) exchangeContext(ctx context.Context, request *dns.Msg, runtime *Runtime, forwarders forwarderList) (*dns.Msg, error) {
	if forwarders.empty() {
		return nil, errors.New("no forwarding endpoints are available")
	}
	ordered := handler.orderForwarders(runtime, forwarders)
	var exchangeErrors []error
	for index, forwarder := range ordered {
		attemptContext, release := forwarderBudget(ctx, len(ordered)-index)
		var response *dns.Msg
		var err error
		if forwarder == forwarding.ThisServer {
			defaults := forwardersOf(runtime.forwarders)
			if runtime.mode == "recursive" {
				defaults = forwarderList{}
			}
			response, err = handler.resolveNetwork(attemptContext, request, runtime, defaults)
		} else {
			response, err = handler.exchangeWithRetries(attemptContext, request, forwarder, runtime.retryTimeout, runtime.retries, handler.forwarderStats)
		}
		release()
		if err == nil {
			handler.upstreamHealth.markHealthy(forwarder)
			return response, nil
		}
		// A forwarder the query budget never left time to contact says nothing
		// about that forwarder's health. Starting a cooldown for it would
		// deprioritize a working upstream because a different one stalled.
		if !errors.Is(err, errForwarderNotTried) {
			handler.upstreamHealth.markUnhealthy(forwarder)
		}
		exchangeErrors = append(exchangeErrors, fmt.Errorf("%s: %w", forwarder, err))
	}
	return nil, fmt.Errorf("all forwarders failed: %w", errors.Join(exchangeErrors...))
}

// forwarderBudget reserves an equal share of the query's remaining time for
// every forwarder that has not been tried yet.
//
// The whole pool used to share one deadline, so the first upstream to go silent
// spent the entire budget on its own retries and each remaining forwarder was
// dialed with nothing left: the dial itself failed instantly with an i/o
// timeout and the query returned SERVFAIL without a second upstream ever seeing
// a packet. One unreachable forwarder therefore broke resolution as completely
// as having no failover configured at all.
//
// Splitting the budget trades attempts against a stalled upstream for attempts
// against a different one, which is the better trade: a second forwarder covers
// packet loss on the first path as well as a retry does, and covers an upstream
// that is genuinely down, which a retry never does.
func forwarderBudget(ctx context.Context, untried int) (context.Context, context.CancelFunc) {
	deadline, bounded := ctx.Deadline()
	if !bounded || untried <= 1 {
		return context.WithCancel(ctx)
	}
	share := time.Until(deadline) / time.Duration(untried)
	if share <= 0 {
		return context.WithCancel(ctx)
	}
	return context.WithTimeout(ctx, share)
}

// upstreamUnhealthyCooldown is how long a forwarder that just failed is tried
// last instead of first. It is deprioritized, never removed, so a recovered
// upstream is probed again and cleared on the next success.
const upstreamUnhealthyCooldown = 10 * time.Second

// authorityUnhealthyCooldownLimit is the longest an authoritative server that
// keeps failing is tried last. Some name servers never answer from a given
// network, often only over IPv6, and a lookup every few minutes would
// otherwise find each one again as soon as its cooldown ended.
const authorityUnhealthyCooldownLimit = 15 * time.Minute

// upstreamHealthTracker remembers which forwarders recently failed so a query
// does not keep starting at a dead upstream and stalling on it for the whole
// per-attempt timeout. The common case (nothing failing) takes only a read lock
// on an empty map.
type upstreamHealthTracker struct {
	mu         sync.RWMutex
	retryAfter map[string]time.Time
	// failures counts each server's failures in a row, which double its
	// cooldown up to cooldownLimit.
	failures      map[string]int
	cooldownLimit time.Duration
	now           func() time.Time
}

func newUpstreamHealthTracker() *upstreamHealthTracker {
	return &upstreamHealthTracker{retryAfter: make(map[string]time.Time), failures: make(map[string]int),
		cooldownLimit: upstreamUnhealthyCooldown, now: time.Now}
}

// newAuthorityHealthTracker tracks authoritative servers, whose cooldown grows
// while they keep failing.
func newAuthorityHealthTracker() *upstreamHealthTracker {
	tracker := newUpstreamHealthTracker()
	tracker.cooldownLimit = authorityUnhealthyCooldownLimit
	return tracker
}

// fastestExploreEvery is how often fastest-first ordering sends a query to
// the forwarder that has gone longest without one, to keep the response times
// of the slower forwarders current. dnsmasq re-tests its servers every 50
// queries for the same reason.
const fastestExploreEvery = 32

// orderForwarders returns the endpoints one query tries, in order: by
// priority rank, by the configured order within a rank, and then with any
// forwarder cooling down after a failure moved after the healthy ones.
func (handler *Handler) orderForwarders(runtime *Runtime, forwarders forwarderList) []string {
	if len(forwarders.endpoints) <= 1 {
		return forwarders.endpoints
	}
	start := handler.upstreamIndex.Add(1) - 1
	switch runtime.forwarderOrder {
	case forwarding.OrderInOrder:
		start = 0
	case forwarding.OrderFastest:
		ordered := forwarders.fastestFirst(handler.forwarderStats)
		if start%fastestExploreEvery == 0 {
			forwarders.exploreStalest(ordered, handler.forwarderStats)
		}
		return handler.upstreamHealth.deprioritize(ordered)
	}
	return handler.upstreamHealth.order(forwarders, start)
}

// rotated returns a copy of the endpoints with each priority rank rotated to
// begin at its own turn of start, so the endpoints of one rank share the load
// while a later rank is held back as a fallback, the way FWD priority works
// in Technitium.
func (list forwarderList) rotated(start uint64) []string {
	endpoints := list.endpoints
	rotated := make([]string, len(endpoints))
	for first := 0; first < len(endpoints); {
		last := list.rankEnd(first)
		size := uint64(last - first)
		for offset := range last - first {
			rotated[first+offset] = endpoints[first+int((start+uint64(offset))%size)]
		}
		first = last
	}
	return rotated
}

// fastestFirst returns a copy of the endpoints with each priority rank sorted
// by response time; see orderingRTT.
func (list forwarderList) fastestFirst(stats *forwarderStatsTable) []string {
	ordered := slices.Clone(list.endpoints)
	for first := 0; first < len(ordered); {
		last := list.rankEnd(first)
		slices.SortStableFunc(ordered[first:last], func(left, right string) int {
			return cmp.Compare(stats.orderingRTT(left), stats.orderingRTT(right))
		})
		first = last
	}
	return ordered
}

// exploreStalest moves the first rank's forwarder that has gone longest
// without a query to the front, so the forwarders fastest-first passes over
// still get measured, each in its turn.
func (list forwarderList) exploreStalest(ordered []string, stats *forwarderStatsTable) {
	last := list.rankEnd(0)
	stalest := 0
	for index := 1; index < last; index++ {
		if stats.lastUsedAt(ordered[index]) < stats.lastUsedAt(ordered[stalest]) {
			stalest = index
		}
	}
	explored := ordered[stalest]
	copy(ordered[1:stalest+1], ordered[:stalest])
	ordered[0] = explored
}

// rankEnd returns the index just past the priority rank that begins at first.
func (list forwarderList) rankEnd(first int) int {
	if list.ranks == nil {
		return len(list.endpoints)
	}
	last := first + 1
	for last < len(list.endpoints) && list.ranks[last] == list.ranks[first] {
		last++
	}
	return last
}

// order rotates each priority rank to start, then moves the servers cooling
// down after a failure after the healthy ones. The result is only read, so a
// single server comes back as given.
func (tracker *upstreamHealthTracker) order(forwarders forwarderList, start uint64) []string {
	if len(forwarders.endpoints) <= 1 {
		return forwarders.endpoints
	}
	return tracker.deprioritize(forwarders.rotated(start))
}

// deprioritize moves the servers cooling down after a failure after the
// healthy ones, keeping the order within each group. It reorders the slice
// it is given.
func (tracker *upstreamHealthTracker) deprioritize(ordered []string) []string {
	tracker.mu.RLock()
	defer tracker.mu.RUnlock()
	if len(tracker.retryAfter) == 0 {
		return ordered
	}
	now := tracker.now()
	healthy := 0
	var cooling []string
	for _, forwarder := range ordered {
		if until, found := tracker.retryAfter[forwarder]; found && now.Before(until) {
			cooling = append(cooling, forwarder)
		} else {
			ordered[healthy] = forwarder
			healthy++
		}
	}
	copy(ordered[healthy:], cooling)
	return ordered
}

func (tracker *upstreamHealthTracker) markUnhealthy(forwarder string) {
	tracker.mu.Lock()
	now := tracker.now()
	tracker.failures[forwarder]++
	cooldown := upstreamUnhealthyCooldown
	for range min(tracker.failures[forwarder]-1, 16) {
		cooldown = min(2*cooldown, tracker.cooldownLimit)
	}
	tracker.retryAfter[forwarder] = now.Add(cooldown)
	// Authoritative servers are many, so forget ones whose cooldown ended
	// rather than keep every server that ever failed.
	if len(tracker.retryAfter) > maximumTrackedUnhealthy {
		for server, until := range tracker.retryAfter {
			if !now.Before(until) {
				delete(tracker.retryAfter, server)
				delete(tracker.failures, server)
			}
		}
	}
	tracker.mu.Unlock()
}

// maximumTrackedUnhealthy is how many failed servers the tracker holds before
// it clears the ones whose cooldown is over.
const maximumTrackedUnhealthy = 1024

// coolingUntil is when a server that failed lately is tried in its usual
// place again, or zero when it is not cooling down.
func (tracker *upstreamHealthTracker) coolingUntil(forwarder string) time.Time {
	tracker.mu.RLock()
	defer tracker.mu.RUnlock()
	if until, found := tracker.retryAfter[forwarder]; found && tracker.now().Before(until) {
		return until
	}
	return time.Time{}
}

func (tracker *upstreamHealthTracker) markHealthy(forwarder string) {
	tracker.mu.RLock()
	_, tracked := tracker.retryAfter[forwarder]
	tracker.mu.RUnlock()
	if !tracked {
		return
	}
	tracker.mu.Lock()
	delete(tracker.retryAfter, forwarder)
	delete(tracker.failures, forwarder)
	tracker.mu.Unlock()
}

// errForwarderNotTried reports that the surrounding deadline was already spent
// when an endpoint came up for its turn, so no packet was ever sent to it.
var errForwarderNotTried = errors.New("no time left in the query budget")

// exchangeWithRetries sends a request to one endpoint, retrying on a transient
// error (a dropped packet reads as a timeout) until it succeeds, the retry count
// is spent, or the surrounding deadline passes. Each attempt waits up to
// retryTimeout, itself bounded by the caller's context.
//
// When stats is set, every attempt is counted against the endpoint there.
func (handler *Handler) exchangeWithRetries(ctx context.Context, request *dns.Msg, endpoint string, retryTimeout time.Duration, retries int, stats *forwarderStatsTable) (*dns.Msg, error) {
	if retries < 1 {
		retries = 1
	}
	var lastErr error
	for attempt := 0; attempt < retries; attempt++ {
		// A context that is already done leaves no attempt to make. Report why
		// rather than falling out of the loop with no error, which would hand
		// the caller a nil response and a nil error.
		if err := ctx.Err(); err != nil {
			if lastErr == nil {
				// Nothing was sent at all, which is different from an endpoint
				// that answered badly or not in time. The caller distinguishes
				// the two so an untouched endpoint is not judged unhealthy.
				lastErr = fmt.Errorf("%w: %w", errForwarderNotTried, err)
			}
			break
		}
		attemptContext, stopAttempt := context.WithTimeout(ctx, retryTimeout)
		var connected *atomic.Bool
		if stats != nil {
			attemptContext, connected = withConnectionMark(attemptContext)
		}
		started := time.Now()
		response, err := handler.upstreamExchange(attemptContext, request, endpoint, retryTimeout)
		stopAttempt()
		if stats != nil {
			stats.observe(endpoint, time.Since(started), response, err, connected.Load())
		}
		if err == nil && response != nil {
			return response, nil
		}
		if err == nil {
			err = fmt.Errorf("%s returned no response", endpoint)
		}
		lastErr = err
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("%s was not queried", endpoint)
	}
	return nil, lastErr
}

// resolveUpstream resolves and validates a request, waiting up to wait.
// A recursive lookup runs on apart from the wait; see resolveRecursive.
func (handler *Handler) resolveUpstream(ctx context.Context, request *dns.Msg, runtime *Runtime, forwarders forwarderList, wait time.Duration) (*dns.Msg, validationState, error) {
	if forwarders.empty() && runtime.mode == "recursive" && len(request.Question) == 1 {
		return handler.resolveRecursive(ctx, request, runtime, wait)
	}
	return handler.fetchAndValidate(ctx, request, runtime, forwarders, wait)
}

// fetchAndValidate resolves a request, waiting up to wait for the network, and
// validates the answer under its own budget.
func (handler *Handler) fetchAndValidate(ctx context.Context, request *dns.Msg, runtime *Runtime, forwarders forwarderList, wait time.Duration) (*dns.Msg, validationState, error) {
	response, err := handler.fetchUpstream(ctx, request, runtime, forwarders, wait)
	return handler.validateUpstream(ctx, request, runtime, response, err)
}

// fetchUpstream sends a request upstream, with DO and CD set when Sable
// validates, waiting up to wait.
func (handler *Handler) fetchUpstream(ctx context.Context, request *dns.Msg, runtime *Runtime, forwarders forwarderList, wait time.Duration) (*dns.Msg, error) {
	networkContext, cancel := context.WithTimeout(ctx, wait)
	defer cancel()
	if runtime.dnssec != nil {
		request = dnssecUpstreamRequest(request)
	}
	return handler.resolveNetwork(networkContext, request, runtime, forwarders)
}

// validateUpstream validates a fetched answer to request. It has its own
// budget, apart from the client's wait for the network.
func (handler *Handler) validateUpstream(ctx context.Context, request *dns.Msg, runtime *Runtime, response *dns.Msg, err error) (*dns.Msg, validationState, error) {
	if runtime.dnssec == nil {
		if response != nil {
			response.AuthenticatedData = false
		}
		return response, validationIndeterminate, err
	}
	if err != nil {
		return nil, validationIndeterminate, err
	}
	if response == nil {
		return nil, validationIndeterminate, errors.New("upstream returned no response")
	}
	validationContext, cancel := context.WithTimeout(ctx, max(4*runtime.timeout, 2*time.Second))
	defer cancel()
	query := func(ctx context.Context, name string, recordType uint16) (*dns.Msg, error) {
		message := new(dns.Msg)
		message.SetQuestion(dns.Fqdn(name), recordType)
		message.RecursionDesired = true
		message.CheckingDisabled = true
		message.SetEdns0(1232, true)
		queryForwarders, _ := runtime.forwardersFor(name)
		return handler.resolveNetwork(ctx, message, runtime, queryForwarders)
	}
	state, validationErr := runtime.dnssec.validate(validationContext, response, request.Question[0], query)
	return response, state, validationErr
}

// upstreamDNSSEC reports whether the answer to this request was fetched with
// signatures attached. With validation enabled dnssecUpstreamRequest sets DO on
// every upstream query regardless of what the client asked for, so the cached
// copy can serve a DO client too; with it disabled only the client's own DO bit
// decides what came back.
func (runtime *Runtime) upstreamDNSSEC(request *dns.Msg) bool {
	return runtime.dnssec != nil || requestWantsDNSSEC(request)
}

func dnssecUpstreamRequest(request *dns.Msg) *dns.Msg {
	message := request.Copy()
	message.AuthenticatedData = false
	message.CheckingDisabled = true
	option := message.IsEdns0()
	if option == nil {
		message.SetEdns0(1232, true)
	} else {
		option.SetDo()
		if option.UDPSize() < 1232 {
			option.SetUDPSize(1232)
		}
	}
	return message
}

func prepareResponseForClient(response, request *dns.Msg) {
	response.AuthenticatedData = response.AuthenticatedData && (request.AuthenticatedData || requestWantsDNSSEC(request))
	response.CheckingDisabled = request.CheckingDisabled
	requestOption := request.IsEdns0()
	if requestOption == nil {
		response.Extra = slices.DeleteFunc(response.Extra, func(record dns.RR) bool {
			return record.Header().Rrtype == dns.TypeOPT
		})
	} else if responseOption := response.IsEdns0(); responseOption != nil {
		responseOption.SetDo(requestOption.Do())
	}
	if requestWantsDNSSEC(request) {
		return
	}
	explicitType := uint16(0)
	if len(request.Question) > 0 {
		explicitType = request.Question[0].Qtype
	}
	strip := func(records []dns.RR) []dns.RR {
		return slices.DeleteFunc(records, func(record dns.RR) bool {
			return isDNSSECAuthenticationType(record.Header().Rrtype) && record.Header().Rrtype != explicitType
		})
	}
	response.Answer = strip(response.Answer)
	response.Ns = strip(response.Ns)
	response.Extra = strip(response.Extra)
}

func isDNSSECAuthenticationType(recordType uint16) bool {
	switch recordType {
	case dns.TypeDS, dns.TypeRRSIG, dns.TypeNSEC, dns.TypeDNSKEY, dns.TypeNSEC3, dns.TypeNSEC3PARAM, dns.TypeCDS, dns.TypeCDNSKEY:
		return true
	default:
		return false
	}
}

func dnssecBogusResponse(request *dns.Msg, validationErr error) *dns.Msg {
	response := errorResponse(request, dns.RcodeServerFailure)
	response.RecursionAvailable = true
	option := request.IsEdns0()
	if option == nil {
		return response
	}
	response.SetEdns0(option.UDPSize(), requestWantsDNSSEC(request))
	extra := "DNSSEC validation failed"
	if validationErr != nil {
		extra = validationErr.Error()
	}
	if len(extra) > 180 {
		extra = extra[:180]
	}
	response.IsEdns0().Option = append(response.IsEdns0().Option, &dns.EDNS0_EDE{
		InfoCode: dns.ExtendedErrorCodeDNSBogus, ExtraText: extra,
	})
	return response
}

func (runtime *Runtime) forwardersFor(name string) (forwarderList, bool) {
	forwarders, route := runtime.forwardersAndRouteFor(name)
	return forwarders, route != ""
}

// forwardersAndRouteFor returns the selected endpoints and the normalized
// conditional-forwarding suffix that selected them. The endpoints stay in
// memory; only the suffix is safe and useful enough for a persisted decision.
func (runtime *Runtime) forwardersAndRouteFor(name string) (forwarderList, string) {
	name = normalizeName(name)
	for name != "" {
		if forwarders, found := runtime.routes[name]; found {
			return forwarders, name
		}
		separator := strings.IndexByte(name, '.')
		if separator < 0 {
			break
		}
		name = name[separator+1:]
	}
	if runtime.mode == "recursive" {
		return forwarderList{}, ""
	}
	return forwardersOf(runtime.forwarders), ""
}
