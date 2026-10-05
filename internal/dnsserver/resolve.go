package dnsserver

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"runtime/debug"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"

	"github.com/drudge/sable/internal/querylog"
)

func (handler *Handler) DNSSECTrustAnchorQuery(ctx context.Context, name string, recordType uint16) (*dns.Msg, error) {
	runtime := handler.runtime.Load()
	if runtime == nil {
		return nil, errors.New("DNS runtime is unavailable")
	}
	message := new(dns.Msg)
	message.SetQuestion(dns.Fqdn(name), recordType)
	message.RecursionDesired = true
	message.CheckingDisabled = true
	message.SetEdns0(1232, true)
	forwarders, _ := runtime.forwardersFor(name)
	return handler.resolveNetwork(ctx, message, runtime, forwarders)
}

// ReverseLookup resolves the PTR name for an address the way a client query
// would: the authoritative zones first, then the host overrides, then the cache,
// and only then the network. It deliberately skips the query counters and the
// query log, because a name the console prints beside a client is not traffic
// that client sent, and recording it would make the console a top talker in its
// own rankings.
//
// An empty name and a nil error mean the lookup succeeded and there is no PTR.
func (handler *Handler) ReverseLookup(ctx context.Context, address netip.Addr) (string, error) {
	runtime := handler.runtime.Load()
	if runtime == nil {
		return "", errors.New("DNS runtime is unavailable")
	}
	reverseName, err := dns.ReverseAddr(address.Unmap().WithZone("").String())
	if err != nil {
		return "", fmt.Errorf("reverse name for %s: %w", address, err)
	}
	response, err := handler.lookupUnrecorded(ctx, runtime, reverseName, dns.TypePTR)
	if err != nil {
		return "", err
	}
	return firstPTRTarget(response), nil
}

// LookupAddresses resolves a host name to its IPv4 and IPv6 addresses through
// Sable's own resolution path, the same way ReverseLookup does. Sable's own
// outbound HTTPS uses it so that reaching GitHub and other services does not
// depend on the host's resolver, which on some networks is a router that drops
// queries. Like ReverseLookup it bypasses blocking and stays out of the query
// log and counters.
func (handler *Handler) LookupAddresses(ctx context.Context, host string) ([]netip.Addr, error) {
	runtime := handler.runtime.Load()
	if runtime == nil {
		return nil, errors.New("DNS runtime is unavailable")
	}
	type answer struct {
		response *dns.Msg
		err      error
	}
	recordTypes := []uint16{dns.TypeA, dns.TypeAAAA}
	answers := make([]answer, len(recordTypes))
	var group sync.WaitGroup
	for index, recordType := range recordTypes {
		group.Go(func() {
			response, err := handler.lookupUnrecorded(ctx, runtime, host, recordType)
			answers[index] = answer{response: response, err: err}
		})
	}
	group.Wait()
	var addresses []netip.Addr
	var failures []error
	for _, answer := range answers {
		if answer.err != nil {
			failures = append(failures, answer.err)
			continue
		}
		for _, record := range answer.response.Answer {
			var address netip.Addr
			switch record := record.(type) {
			case *dns.A:
				address, _ = netip.AddrFromSlice(record.A.To4())
			case *dns.AAAA:
				address, _ = netip.AddrFromSlice(record.AAAA)
			}
			if address.IsValid() {
				addresses = append(addresses, address)
			}
		}
	}
	if len(addresses) > 0 {
		return addresses, nil
	}
	if len(failures) > 0 {
		return nil, errors.Join(failures...)
	}
	return nil, fmt.Errorf("resolve %s: no addresses", host)
}

// lookupUnrecorded answers one question the way a client query would, from the
// authoritative zones, then the host overrides, then the cache, and only then
// the network, without touching blocking, the query log, or the counters.
func (handler *Handler) lookupUnrecorded(ctx context.Context, runtime *Runtime, name string, recordType uint16) (*dns.Msg, error) {
	request := new(dns.Msg)
	request.SetQuestion(dns.Fqdn(name), recordType)
	request.RecursionDesired = true
	if response, found := runtime.authoritativeResponse(request); found {
		return response, nil
	}
	if response, found := runtime.localResponse(request); found {
		return response, nil
	}
	if response, found := runtime.cache.Get(request); found {
		return response, nil
	}
	forwarders, _ := runtime.forwardersFor(name)
	response, err := handler.resolveNetwork(ctx, request, runtime, forwarders)
	if err != nil {
		return nil, fmt.Errorf("resolve %s: %w", name, err)
	}
	return response, nil
}

func firstPTRTarget(response *dns.Msg) string {
	if response == nil {
		return ""
	}
	for _, record := range response.Answer {
		if pointer, ok := record.(*dns.PTR); ok {
			return strings.TrimSuffix(pointer.Ptr, ".")
		}
	}
	return ""
}

func (handler *Handler) ServeDNS(writer dns.ResponseWriter, request *dns.Msg) {
	startedAt := time.Now()
	latencySource := querylog.Source("control")
	if request.Opcode == dns.OpcodeUpdate {
		latencySource = querylog.SourceAuthoritative
	} else if request.Opcode == dns.OpcodeQuery {
		latencySource = querylog.SourceError
		if len(request.Question) == 1 && (request.Question[0].Qtype == dns.TypeAXFR || request.Question[0].Qtype == dns.TypeIXFR) {
			latencySource = querylog.Source("control")
		}
	}
	protocol := queryProtocol(writer)
	client := queryClient{ip: responseWriterClientIP(writer), protocol: protocol}
	latencyCache := querylog.CacheDecision("")
	latencyResponseCode := -1
	defer func() {
		handler.latency.observe(latencySource, protocol, latencyCache, latencyResponseCode, time.Since(startedAt))
	}()
	// Runs before the latency observer so a recovered query is timed as the
	// SERVFAIL it answers.
	defer func() {
		if value := recover(); value != nil {
			latencySource = querylog.SourceError
			latencyResponseCode = dns.RcodeServerFailure
			handler.recoverQuery(writer, request, client.ip, value)
		}
	}()

	observer := handler.activeQueryObserver()
	handler.queries.Add(1)
	runtime := handler.runtime.Load()
	// Every step below matches on the lowercase name, so it is worked out once
	// here rather than again in each one. A 0x20 mixed-case query would
	// otherwise allocate a fresh copy at every step.
	name := questionName(request)
	if handler.serveDynamicUpdate(writer, request, runtime, observer, client, startedAt) {
		return
	}
	if handler.serveNotify(writer, request, runtime, client.ip) {
		return
	}
	if handler.serveZoneTransfer(writer, request, runtime, client.ip) {
		return
	}
	if len(request.Question) == 1 && handler.zoneExpired(runtime, name) {
		result := resolution{response: errorResponse(request, dns.RcodeServerFailure), source: querylog.SourceError}
		latencyResponseCode = result.response.Rcode
		handler.logResolutionFailure(request, client.ip, "authoritative zone expired")
		handler.recordResponseCode(result.response.Rcode)
		handler.writeResponse(writer, request, result.response)
		if observer != nil {
			handler.recordQuery(observer, client, request, name, result, startedAt)
		}
		return
	}
	result := handler.resolveNameForClient(request, name, runtime, client.ip)
	latencySource = result.source
	latencyCache = result.decision.Cache
	latencyResponseCode = result.response.Rcode
	handler.recordResponseCode(result.response.Rcode)
	handler.writeResponse(writer, request, result.response)
	if observer != nil {
		handler.recordQuery(observer, client, request, name, result, startedAt)
	}
}

// recoverQuery answers a query whose handling panicked with SERVFAIL, so one
// odd packet cannot take down the UDP, TCP, DoT, or DoQ listeners. DoH already
// survives through net/http, but this answers it properly too.
func (handler *Handler) recoverQuery(writer dns.ResponseWriter, request *dns.Msg, clientIP string, value any) {
	handler.panics.Add(1)
	handler.recordResponseCode(dns.RcodeServerFailure)
	if logger := handler.logger.Load(); logger != nil {
		name, recordType := questionDescription(request)
		logger.Error("dns query handler panicked", "name", name, "type", recordType, "client", clientIP,
			"panic", fmt.Sprint(value), "stack", string(debug.Stack()))
	}
	// The writer may be what panicked. Writing the SERVFAIL is best effort.
	defer func() { _ = recover() }()
	handler.writeResponse(writer, request, errorResponse(request, dns.RcodeServerFailure))
}

func (handler *Handler) recordResponseCode(code int) {
	switch code {
	case dns.RcodeSuccess:
		handler.noError.Add(1)
	case dns.RcodeServerFailure:
		handler.serverFailures.Add(1)
	case dns.RcodeNameError:
		handler.nxDomain.Add(1)
	case dns.RcodeRefused:
		handler.refused.Add(1)
	}
}

func (handler *Handler) resolve(request *dns.Msg, runtime *Runtime) resolution {
	// In-process lookups do not inherit a network client's recursion grant.
	return handler.resolveRequest(request, questionName(request), runtime, "", true)
}

// resolveNameForClient resolves request for a network client. name is its
// question name as questionName returns it.
func (handler *Handler) resolveNameForClient(request *dns.Msg, name string, runtime *Runtime, clientIP string) resolution {
	var attached []netip.Prefix
	if networks := handler.attached.Load(); networks != nil {
		attached = *networks
	}
	return handler.resolveRequest(request, name, runtime, clientIP, runtime.recursion.AllowsFrom(clientIP, attached))
}

// resolveRequest answers request. name is its question name as questionName
// returns it.
func (handler *Handler) resolveRequest(request *dns.Msg, name string, runtime *Runtime, clientIP string, recursionAllowed bool) (result resolution) {
	defer func() {
		if result.response != nil {
			result.response.RecursionAvailable = recursionAllowed
		}
	}()
	if len(request.Question) == 0 {
		return unevaluatedResolution(errorResponse(request, dns.RcodeFormatError), querylog.SourceError, querylog.ResolverError)
	}
	if response, found := handler.resolveANAME(request, name, runtime, clientIP); found {
		handler.authoritativeAnswers.Add(1)
		return unevaluatedResolution(response, querylog.SourceAuthoritative, querylog.ResolverAuthoritative)
	}
	if response, found := runtime.authoritativeResponseFor(request, name); found {
		handler.authoritativeAnswers.Add(1)
		return unevaluatedResolution(response, querylog.SourceAuthoritative, querylog.ResolverAuthoritative)
	}
	if response, found := runtime.localResponseFor(request, name); found {
		handler.localAnswers.Add(1)
		return unevaluatedResolution(response, querylog.SourceLocal, querylog.ResolverLocal)
	}

	// Authoritative and local answers remain public, but neither fresh nor cached
	// recursive data is available outside the client's grant.
	if !recursionAllowed {
		return recursionNotAllowed(request)
	}
	policy, policyRule, policySources := runtime.policyDecision(name, clientIP, handler.BlockingPaused())
	if policy == querylog.PolicyBlocked {
		handler.blocked.Add(1)
		return resolution{response: runtime.blockedResponse(request), source: querylog.SourceBlocked,
			decision: querylog.Decision{Policy: policy, PolicyRule: policyRule, PolicySources: policySources, Resolver: querylog.ResolverBlocked}}
	}
	if response, found, prefetch := runtime.cache.GetWithPrefetch(request); found {
		handler.cacheHits.Add(1)
		if prefetch {
			if request.RecursionDesired {
				handler.prefetch(request, runtime)
			} else {
				runtime.cache.CancelPrefetch(request)
			}
		}
		return resolution{response: response, source: querylog.SourceCache,
			decision: querylog.Decision{Policy: policy, PolicyRule: policyRule, Cache: querylog.CacheHit, Resolver: querylog.ResolverCache}}
	}
	if !request.RecursionDesired {
		return recursionRefused(request)
	}
	handler.cacheMisses.Add(1)

	forwarders, route := runtime.forwardersAndRouteFor(name)
	if route != "" {
		handler.routedQueries.Add(1)
	}
	// A name only a local network can answer never goes to the internet. A
	// route or a forwarder zone for it still wins, since that names a server
	// that does know it.
	if len(forwarders) == 0 && runtime.mode == "recursive" {
		if zone, found := locallyServedZone(request.Question[0].Name); found {
			handler.localAnswers.Add(1)
			return resolution{response: locallyServedResponse(request, zone), source: querylog.SourceLocal,
				decision: querylog.Decision{Policy: policy, PolicyRule: policyRule, Cache: querylog.CacheMiss, Resolver: querylog.ResolverLocallyServed}}
		}
	}
	release, admitted := handler.admission.acquire(clientIP, runtime.maxConcurrent, runtime.maxConcurrentPerClient)
	if !admitted {
		return recursionRefused(request)
	}
	if runtime.staleMaxWait > 0 && runtime.cache.HasStale(request) {
		result = handler.resolveWithStaleWait(request, name, runtime, forwarders, clientIP, release)
	} else {
		defer release()
		result = handler.resolveShared(context.Background(), request, name, runtime, forwarders, true, clientIP)
	}
	result.decision.Policy = policy
	result.decision.PolicyRule = policyRule
	if result.decision.Cache == "" {
		result.decision.Cache = querylog.CacheMiss
	}
	if result.decision.Resolver == "" {
		result.decision.Resolver = resolverDecision(runtime, forwarders)
	}
	result.decision.Route = route
	return result
}

// recursionNotAllowed refuses a client the recursion policy leaves out, and
// says so in the query log, apart from a refusal for load or an RD=0 miss.
func recursionNotAllowed(request *dns.Msg) resolution {
	return unevaluatedResolution(errorResponse(request, dns.RcodeRefused), querylog.SourceError, querylog.ResolverNotAllowed)
}

func recursionRefused(request *dns.Msg) resolution {
	return unevaluatedResolution(errorResponse(request, dns.RcodeRefused), querylog.SourceError, querylog.ResolverError)
}

// resolveShared coalesces concurrent identical cache misses so only one upstream
// resolution (and one DNSSEC validation) runs for a given question at a time. The
// followers wait for the leader's result and each receive their own copy prepared
// for their request.
//
// Only the leader runs the resolution, so a failure is logged against the client
// that started it. Followers asking the same question at the same moment share
// that outcome without appearing in the line.
func (handler *Handler) resolveShared(ctx context.Context, request *dns.Msg, name string, runtime *Runtime, forwarders []string, staleFallback bool, clientIP string) resolution {
	arrived := time.Now()
	key := coalesceKeyFor(request, name)
	key.runtime = runtime
	result, follower, shared := handler.inflight.doContext(ctx, key, func() resolution {
		return handler.resolveLiveUpstream(ctx, request, runtime, forwarders, staleFallback, clientIP, runtime.timeout)
	})
	if follower && result.stillRunning {
		// The client that started the lookup stopped waiting, but this one
		// asked later, often as that device's own retry. It waits on the same
		// recursive lookup for the rest of its own time instead of ending
		// with the first.
		if wait := runtime.timeout - time.Since(arrived); wait > 0 {
			result = handler.resolveLiveUpstream(ctx, request, runtime, forwarders, staleFallback, clientIP, wait)
		}
	}
	if result.response == nil {
		return result
	}
	// A shared result is copied by every caller, the leader included, so
	// client-specific flags never change it while another caller is copying
	// it. A leader nobody joined owns its response outright.
	response := result.response
	if shared {
		response = response.Copy()
	}
	response.Id = request.Id
	response.Question = append(response.Question[:0], request.Question...)
	prepareResponseForClient(response, request)
	result.response = response
	return result
}

// inflightGroup collapses concurrent calls sharing a key into one execution, so
// a stampede of identical cache misses performs a single upstream resolution.
// The first caller runs the work; the rest wait and receive its result.
type inflightGroup struct {
	mu    sync.Mutex
	calls map[inflightKey]*inflightCall
}

type inflightKey struct {
	runtime          *Runtime
	name             string
	recordType       uint16
	class            uint16
	dnssecOK         bool
	checkingDisabled bool
}

type inflightCall struct {
	wait   chan struct{}
	result resolution
	// followers counts the callers that joined this one. It changes only
	// under the group's lock, while the call is still in the map.
	followers int
}

func newInflightGroup() *inflightGroup {
	return &inflightGroup{calls: make(map[inflightKey]*inflightCall)}
}

// doContext runs fn for key unless a call is already in flight, in which case
// it waits for that call, or for ctx, and returns its result. follower reports
// that this caller waited on another's call. shared reports whether another
// caller holds the same result: always for a follower, and for the caller that
// ran fn when anyone joined it. A caller must copy a shared response before
// changing it.
func (group *inflightGroup) doContext(ctx context.Context, key inflightKey, fn func() resolution) (result resolution, follower, shared bool) {
	group.mu.Lock()
	if call, ok := group.calls[key]; ok {
		call.followers++
		group.mu.Unlock()
		select {
		case <-call.wait:
			return call.result, true, true
		case <-ctx.Done():
			return resolution{}, true, true
		}
	}
	call := &inflightCall{wait: make(chan struct{})}
	group.calls[key] = call
	group.mu.Unlock()

	// Release the key and the waiters even if fn panics. Waiters reached
	// through resolveShared wait on context.Background, so a call left in the
	// map would hang every later identical query. Once the key is gone nobody
	// else can join, so the follower count read here is final.
	defer func() {
		group.mu.Lock()
		delete(group.calls, key)
		shared = call.followers > 0
		group.mu.Unlock()
		close(call.wait)
	}()
	call.result = fn()
	return call.result, false, false
}

// coalesceKey identifies queries that share an upstream answer: the same name,
// type, and class, and the same DNSSEC intent (DO/CD), since those change what a
// resolver returns and caches.
func coalesceKey(request *dns.Msg) inflightKey {
	return coalesceKeyFor(request, normalizeName(request.Question[0].Name))
}

// coalesceKeyFor is coalesceKey for a request whose question name is already
// normalized.
func coalesceKeyFor(request *dns.Msg, name string) inflightKey {
	question := request.Question[0]
	dnssecOK := false
	if option := request.IsEdns0(); option != nil {
		dnssecOK = option.Do()
	}
	return inflightKey{
		name:             name,
		recordType:       question.Qtype,
		class:            question.Qclass,
		dnssecOK:         dnssecOK,
		checkingDisabled: request.CheckingDisabled,
	}
}

func (handler *Handler) resolveWithStaleWait(request *dns.Msg, name string, runtime *Runtime, forwarders []string, clientIP string, release func()) resolution {
	if !handler.startBackground() {
		release()
		return handler.resolveUpstreamFailure(request, runtime)
	}
	result := make(chan resolution, 1)
	go func() {
		defer handler.backgroundWG.Done()
		// Keep the permit until work finishes, even after a stale answer returns.
		defer release()
		result <- handler.resolveShared(handler.backgroundContext, request.Copy(), name, runtime, forwarders, false, clientIP)
	}()
	timer := time.NewTimer(runtime.staleMaxWait)
	defer timer.Stop()
	select {
	case resolved := <-result:
		if resolved.response == nil || resolved.transientFailure {
			return handler.staleOrFailure(request, runtime, !resolved.stillRunning)
		}
		return resolved
	case <-timer.C:
		if response, found := runtime.cache.GetStale(request); found {
			handler.cacheHits.Add(1)
			prepareResponseForClient(response, request)
			return staleResolution(response)
		}
		return <-result
	}
}

// resolveLiveUpstream resolves a cache miss, waiting up to wait for the
// network.
func (handler *Handler) resolveLiveUpstream(ctx context.Context, request *dns.Msg, runtime *Runtime, forwarders []string, staleFallback bool, clientIP string, wait time.Duration) resolution {
	response, validation, validationErr := handler.resolveUpstream(ctx, request, runtime, forwarders, wait)
	decision := querylog.Decision{Resolver: resolverDecision(runtime, forwarders), DNSSEC: dnssecDecision(validation)}
	if validation == validationBogus {
		handler.dnssecBogus.Add(1)
		if !request.CheckingDisabled {
			handler.logUpstreamFailure(request, clientIP, "DNSSEC validation failed",
				upstreamFailure{runtime: runtime, forwarders: forwarders, err: validationErr})
			decision.Resolver = querylog.ResolverError
			return resolution{response: dnssecBogusResponse(request, validationErr), source: querylog.SourceError, decision: decision}
		}
	} else if validation == validationSecure {
		handler.dnssecSecure.Add(1)
	} else if validation == validationInsecure {
		handler.dnssecInsecure.Add(1)
	}
	if validationErr != nil && validation != validationBogus {
		handler.upstreamErrors.Add(1)
		handler.logUpstreamFailure(request, clientIP, "upstream resolution failed",
			upstreamFailure{runtime: runtime, forwarders: forwarders, err: validationErr})
		// A lookup still running will answer a retry, so its failure is
		// neither cached nor final.
		stillRunning := errors.Is(validationErr, errStillRunning)
		if !staleFallback {
			decision.Resolver = querylog.ResolverError
			return resolution{response: errorResponse(request, fallbackErrorCode), source: querylog.SourceError, decision: decision, transientFailure: true, stillRunning: stillRunning}
		}
		return handler.staleOrFailure(request, runtime, !stillRunning)
	}
	if response == nil {
		handler.upstreamErrors.Add(1)
		handler.logUpstreamFailure(request, clientIP, "upstream returned no response",
			upstreamFailure{runtime: runtime, forwarders: forwarders})
		if !staleFallback {
			decision.Resolver = querylog.ResolverError
			return resolution{response: errorResponse(request, fallbackErrorCode), source: querylog.SourceError, decision: decision, transientFailure: true}
		}
		return handler.resolveUpstreamFailure(request, runtime)
	}
	if response.Rcode == dns.RcodeServerFailure {
		handler.logUpstreamFailure(request, clientIP, "upstream answered SERVFAIL",
			upstreamFailure{runtime: runtime, forwarders: forwarders})
	}
	runtime.cacheUpstreamAnswer(request, response, validation)
	prepareResponseForClient(response, request)
	return resolution{response: response, source: querylog.SourceUpstream, decision: decision}
}

// cacheUpstreamAnswer readies a fetched answer for request and caches it. It
// reports whether the answer was stored.
func (runtime *Runtime) cacheUpstreamAnswer(request, response *dns.Msg, validation validationState) bool {
	response.Id = request.Id
	response.Question = append(response.Question[:0], request.Question...)
	response.CheckingDisabled = request.CheckingDisabled
	response.AuthenticatedData = validation == validationSecure
	// CD is a diagnostic escape hatch, not permission to poison the shared
	// cache with data that failed validation for every other client. With local
	// validation on, every upstream fetch already sets CD and bogus answers never
	// reach here, so a CD client's answer is what everyone else would get and is
	// safe to share. With validation off the upstream did the validating and a CD
	// fetch went around it, so that answer stays private to the client that asked.
	if validation == validationBogus || (runtime.dnssec == nil && request.CheckingDisabled) {
		return false
	}
	return runtime.cache.Set(request, response, runtime.upstreamDNSSEC(request))
}

func (handler *Handler) prefetch(request *dns.Msg, runtime *Runtime) {
	if !handler.startBackground() {
		runtime.cache.CancelPrefetch(request)
		return
	}
	release, admitted := handler.admission.acquire("", runtime.maxConcurrent, runtime.maxConcurrentPerClient)
	if !admitted {
		handler.backgroundWG.Done()
		runtime.cache.CancelPrefetch(request)
		return
	}
	request = request.Copy()
	go func() {
		defer handler.backgroundWG.Done()
		defer release()
		forwarders, _ := runtime.forwardersFor(request.Question[0].Name)
		response, validation, err := handler.resolveUpstream(handler.backgroundContext, request, runtime, forwarders, runtime.timeout)
		if err != nil || response == nil || !runtime.cacheUpstreamAnswer(request, response, validation) {
			runtime.cache.CancelPrefetch(request)
		}
	}()
}

func (handler *Handler) resolveUpstreamFailure(request *dns.Msg, runtime *Runtime) resolution {
	return handler.staleOrFailure(request, runtime, true)
}

// staleOrFailure answers a failed lookup with a stale answer when one is
// kept, or else SERVFAIL, cached when cacheFailure is set. A lookup that is
// still running leaves its failure uncached, or a retry would find it there
// instead of the answer, and marks it so clients sharing it wait on.
func (handler *Handler) staleOrFailure(request *dns.Msg, runtime *Runtime, cacheFailure bool) resolution {
	if stale, found := handler.staleResponse(request, runtime); found {
		return stale
	}
	response := errorResponse(request, fallbackErrorCode)
	if cacheFailure {
		// A synthesised failure carries no records, so there is nothing a
		// client that set DO would be missing and no reason to make it
		// refetch the same failure.
		runtime.cache.Set(request, response, true)
	}
	return resolution{response: response, source: querylog.SourceError,
		decision: querylog.Decision{Resolver: querylog.ResolverError}, stillRunning: !cacheFailure}
}

func (handler *Handler) staleResponse(request *dns.Msg, runtime *Runtime) (resolution, bool) {
	response, found := runtime.cache.GetStale(request)
	if !found {
		return resolution{}, false
	}
	handler.cacheHits.Add(1)
	prepareResponseForClient(response, request)
	return staleResolution(response), true
}

func (handler *Handler) resolveANAME(request *dns.Msg, name string, runtime *Runtime, clientIP string) (*dns.Msg, bool) {
	alias, found := runtime.authoritativeANAMEFor(request, name)
	if !found {
		return nil, false
	}
	if response, cached := runtime.cache.Get(request); cached {
		handler.cacheHits.Add(1)
		response.Authoritative = true
		return response, true
	}
	handler.cacheMisses.Add(1)
	targetRequest := request.Copy()
	targetRequest.Question[0].Name = dns.Fqdn(alias.target)
	// Flattening an administrator-configured ANAME is authoritative service,
	// including queries from other recursive resolvers (which send RD=0).
	targetRequest.RecursionDesired = true
	targetResponse, local := runtime.authoritativeResponse(targetRequest)
	if !local {
		release, admitted := handler.admission.acquire(clientIP, runtime.maxConcurrent, runtime.maxConcurrentPerClient)
		if !admitted {
			return errorResponse(request, dns.RcodeRefused), true
		}
		defer release()
		forwarders, routed := runtime.forwardersFor(alias.target)
		if routed {
			handler.routedQueries.Add(1)
		}
		var err error
		var validation validationState
		targetResponse, validation, err = handler.resolveUpstream(context.Background(), targetRequest, runtime, forwarders, runtime.timeout)
		if err != nil {
			handler.upstreamErrors.Add(1)
			handler.logUpstreamFailure(request, clientIP, "ANAME target resolution failed",
				upstreamFailure{runtime: runtime, forwarders: forwarders, err: err}, "target", alias.target)
			return errorResponse(request, fallbackErrorCode), true
		}
		if validation == validationBogus {
			handler.dnssecBogus.Add(1)
			handler.logResolutionFailure(request, clientIP, "ANAME target failed DNSSEC validation", "target", alias.target)
			return dnssecBogusResponse(request, errors.New("ANAME target failed DNSSEC validation")), true
		}
	}
	response := new(dns.Msg)
	response.SetReply(request)
	response.Authoritative = true
	response.RecursionAvailable = true
	if targetResponse.Rcode != dns.RcodeSuccess {
		handler.logResolutionFailure(request, clientIP, "ANAME target did not resolve",
			"target", alias.target, "target_rcode", rcodeDescription(targetResponse.Rcode))
		response.Rcode = dns.RcodeServerFailure
		return response, true
	}
	for _, answer := range targetResponse.Answer {
		typeCode := answer.Header().Rrtype
		if typeCode != request.Question[0].Qtype || (typeCode != dns.TypeA && typeCode != dns.TypeAAAA) {
			continue
		}
		clone := dns.Copy(answer)
		clone.Header().Name = request.Question[0].Name
		clone.Header().Ttl = min(clone.Header().Ttl, alias.ttl)
		response.Answer = append(response.Answer, clone)
	}
	if len(response.Answer) == 0 {
		if zone := runtime.authoritativeZoneFor(name); zone != nil {
			response.Ns = cloneRecords(zone.soa, "", time.Now())
		}
	}
	// The synthesised answer is unsigned however the client asked for it, so the
	// cached copy is exactly what a fresh synthesis would produce for anyone.
	runtime.cache.Set(request, response, true)
	return response, true
}

// LookupResult is the answer an in-process lookup produced and the path Sable
// took to reach it.
type LookupResult struct {
	Response *dns.Msg
	Source   querylog.Source
	Decision querylog.Decision
}

// Lookup answers a question exactly as a client with recursion access and no
// blocking bypass would see it: zones, local names, blocking, the cache, then
// the network. It is not a client query, so it stays out of the query log and
// never shows up as a device in Insights.
func (handler *Handler) Lookup(name string, recordType uint16) (LookupResult, error) {
	runtime := handler.runtime.Load()
	if runtime == nil {
		return LookupResult{}, errors.New("DNS runtime is unavailable")
	}
	request := new(dns.Msg)
	request.SetQuestion(dns.Fqdn(name), recordType)
	request.RecursionDesired = true
	result := handler.resolve(request, runtime)
	if result.response == nil {
		return LookupResult{}, fmt.Errorf("resolve %s: no response", name)
	}
	return LookupResult{Response: result.response, Source: result.source, Decision: result.decision}, nil
}

func (handler *Handler) writeResponse(writer dns.ResponseWriter, request, response *dns.Msg) {
	localAddress := writer.LocalAddr()
	if localAddress != nil && strings.HasPrefix(localAddress.Network(), "udp") {
		maximumSize := minimumDNSUDPSize
		if option := request.IsEdns0(); option != nil {
			maximumSize = int(option.UDPSize())
		}
		response.Truncate(maximumSize)
	}
	if err := writer.WriteMsg(response); err != nil {
		handler.failures.Add(1)
	}
}

// unevaluatedResolution is an answer given before policy ran: a malformed
// request, an authoritative or local answer, or a refusal.
func unevaluatedResolution(response *dns.Msg, source querylog.Source, resolver querylog.ResolverDecision) resolution {
	return resolution{response: response, source: source,
		decision: querylog.Decision{Policy: querylog.PolicyNotEvaluated, Resolver: resolver}}
}

// staleResolution is an expired cache answer served while upstream fails or
// catches up.
func staleResolution(response *dns.Msg) resolution {
	return resolution{response: response, source: querylog.SourceCache,
		decision: querylog.Decision{Cache: querylog.CacheStale, Resolver: querylog.ResolverCache}}
}
