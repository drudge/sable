package dnsserver

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"

	"github.com/drudge/sable/internal/forwarding"
)

func (handler *Handler) exchangeContext(ctx context.Context, request *dns.Msg, runtime *Runtime, forwarders []string) (*dns.Msg, error) {
	if len(forwarders) == 0 {
		return nil, errors.New("no forwarding endpoints are available")
	}
	start := handler.upstreamIndex.Add(1) - 1
	ordered := handler.upstreamHealth.order(forwarders, start)
	var exchangeErrors []error
	for index, forwarder := range ordered {
		attemptContext, release := forwarderBudget(ctx, len(ordered)-index)
		var response *dns.Msg
		var err error
		if forwarder == forwarding.ThisServer {
			defaults := runtime.forwarders
			if runtime.mode == "recursive" {
				defaults = nil
			}
			response, err = handler.resolveNetworkContext(attemptContext, request, runtime, defaults)
		} else {
			response, err = handler.exchangeWithRetries(attemptContext, request, forwarder, runtime.retryTimeout, runtime.retries)
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

// order rotates forwarders to begin at start, then moves the ones cooling
// down after the healthy ones, keeping the rotation within each group. The
// result is only read, so a single server comes back as given.
func (tracker *upstreamHealthTracker) order(forwarders []string, start uint64) []string {
	if len(forwarders) <= 1 {
		return forwarders
	}
	rotated := make([]string, len(forwarders))
	for offset := range forwarders {
		rotated[offset] = forwarders[(start+uint64(offset))%uint64(len(forwarders))]
	}
	tracker.mu.RLock()
	defer tracker.mu.RUnlock()
	if len(tracker.retryAfter) == 0 {
		return rotated
	}
	now := tracker.now()
	healthy := 0
	var cooling []string
	for _, forwarder := range rotated {
		if until, found := tracker.retryAfter[forwarder]; found && now.Before(until) {
			cooling = append(cooling, forwarder)
		} else {
			rotated[healthy] = forwarder
			healthy++
		}
	}
	copy(rotated[healthy:], cooling)
	return rotated
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
func (handler *Handler) exchangeWithRetries(ctx context.Context, request *dns.Msg, endpoint string, retryTimeout time.Duration, retries int) (*dns.Msg, error) {
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
		response, err := handler.upstreamExchange(attemptContext, request, endpoint, retryTimeout)
		stopAttempt()
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

func (handler *Handler) resolveUpstream(request *dns.Msg, runtime *Runtime, forwarders []string) (*dns.Msg, validationState, error) {
	return handler.resolveUpstreamContext(context.Background(), request, runtime, forwarders)
}

func (handler *Handler) resolveUpstreamContext(ctx context.Context, request *dns.Msg, runtime *Runtime, forwarders []string) (*dns.Msg, validationState, error) {
	return handler.resolveUpstreamWaiting(ctx, request, runtime, forwarders, runtime.timeout)
}

// resolveUpstreamWaiting resolves and validates a request, waiting up to wait.
// A recursive lookup runs on apart from the wait; see resolveRecursiveWaiting.
func (handler *Handler) resolveUpstreamWaiting(ctx context.Context, request *dns.Msg, runtime *Runtime, forwarders []string, wait time.Duration) (*dns.Msg, validationState, error) {
	if len(forwarders) == 0 && runtime.mode == "recursive" && len(request.Question) == 1 {
		return handler.resolveRecursiveWaiting(ctx, request, runtime, wait)
	}
	return handler.fetchAndValidate(ctx, request, runtime, forwarders, wait)
}

// fetchAndValidate resolves a request, waiting up to wait for the network, and
// validates the answer under its own budget.
func (handler *Handler) fetchAndValidate(ctx context.Context, request *dns.Msg, runtime *Runtime, forwarders []string, wait time.Duration) (*dns.Msg, validationState, error) {
	response, err := handler.fetchUpstream(ctx, request, runtime, forwarders, wait)
	return handler.validateUpstream(ctx, request, runtime, response, err)
}

// fetchUpstream sends a request upstream, with DO and CD set when Sable
// validates, waiting up to wait.
func (handler *Handler) fetchUpstream(ctx context.Context, request *dns.Msg, runtime *Runtime, forwarders []string, wait time.Duration) (*dns.Msg, error) {
	networkContext, cancel := context.WithTimeout(ctx, wait)
	defer cancel()
	if runtime.dnssec != nil {
		request = dnssecUpstreamRequest(request)
	}
	return handler.resolveNetworkContext(networkContext, request, runtime, forwarders)
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
		return handler.resolveNetworkContext(ctx, message, runtime, queryForwarders)
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

func (runtime *Runtime) forwardersFor(name string) ([]string, bool) {
	forwarders, route := runtime.forwardersAndRouteFor(name)
	return forwarders, route != ""
}

// forwardersAndRouteFor returns the selected endpoints and the normalized
// conditional-forwarding suffix that selected them. The endpoints stay in
// memory; only the suffix is safe and useful enough for a persisted decision.
func (runtime *Runtime) forwardersAndRouteFor(name string) ([]string, string) {
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
		return nil, ""
	}
	return runtime.forwarders, ""
}
