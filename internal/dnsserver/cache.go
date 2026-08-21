package dnsserver

import (
	"container/list"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
)

const (
	maximumCacheShards = 64
	minimumDNSUDPSize  = 512
	// Refreshes are issued by the resolver itself, so they advertise the same
	// buffer size it uses for its own iterative queries rather than whatever the
	// client that first populated the entry happened to ask for.
	prefetchUDPSize = 1232
	// Expired entries are reaped on this cadence so a cache nobody reads again
	// still releases its slots. A minute also keeps the entry count the console
	// shows from drifting far ahead of the entries it lists, and still costs one
	// walk per minute instead of one per metrics scrape as it used to.
	cacheSweepInterval = time.Minute
	// The refresh scan has to fire several times inside the prefetch trigger
	// window, or a popular entry slips between two scans and expires cold. Two
	// seconds gives four passes at the default nine-second trigger.
	cacheRefreshInterval = 2 * time.Second
	// An upper bound on refreshes started per scan, so a cache full of expiring
	// popular entries cannot spawn tens of thousands of upstream queries at once.
	maximumPrefetchBatch = 64
)

// cacheKey identifies an answer, not the client that asked for it. The EDNS
// buffer size, DO bit, and CD bit deliberately stay out of it: they describe how
// a client wants the answer delivered, not which answer it gets, and keying on
// them split a single question across six entries for no gain.
type cacheKey struct {
	name       string
	recordType uint16
	class      uint16
}

type cacheEntry struct {
	key      cacheKey
	response *dns.Msg
	// dnssecOK records whether the stored copy was fetched with signatures
	// attached. A client that set DO can only be served from an entry that has
	// them; a client that did not gets them stripped on the way out.
	dnssecOK   bool
	storedAt   time.Time
	expiresAt  time.Time
	staleUntil time.Time
	retryAfter time.Time
	hitWindow  time.Time
	hits       uint32
	refreshing bool
}

type cacheShard struct {
	mu       sync.Mutex
	entries  map[cacheKey]*list.Element
	recency  list.List
	capacity int
}

type ResponseCache struct {
	shards   []cacheShard
	capacity int
	options  CacheOptions
	now      func() time.Time
}

// CacheOptions controls resolver cache lifetime policy. Zero-valued options
// preserve the DNS TTLs supplied by upstream servers.
type CacheOptions struct {
	MinimumTTL     uint32
	MaximumTTL     uint32
	NegativeTTL    uint32
	FailureTTL     uint32
	ServeStale     bool
	StaleTTL       uint32
	StaleAnswerTTL uint32
	StaleResetTTL  uint32
	PrefetchMinTTL uint32
	PrefetchAtTTL  uint32
	PrefetchSample time.Duration
	PrefetchHits   uint32
}

// CachedResponse is an immutable, presentation-safe view of a cached DNS
// response. It deliberately excludes the internal cache key and message
// pointers so callers cannot mutate live resolver state.
type CachedResponse struct {
	Name         string
	RecordType   string
	RemainingTTL uint32
	Records      []CachedRecord
}

type CachedRecord struct {
	Section string
	Value   string
	TTL     uint32
}

// PersistedResponse is the storage-neutral wire representation used to retain
// a warm cache across controlled restarts. It is never used on the lookup path.
type PersistedResponse struct {
	RequestWire  []byte
	ResponseWire []byte
	StoredAt     time.Time
	ExpiresAt    time.Time
	StaleUntil   time.Time
}

func NewResponseCache(capacity int) *ResponseCache {
	return NewResponseCacheWithOptions(capacity, CacheOptions{})
}

func NewResponseCacheWithOptions(capacity int, options CacheOptions) *ResponseCache {
	capacity = max(capacity, 1)
	shardCount := min(capacity, maximumCacheShards)
	cache := &ResponseCache{shards: make([]cacheShard, shardCount), capacity: capacity, options: options, now: time.Now}
	baseCapacity := capacity / shardCount
	extraSlots := capacity % shardCount
	for index := range cache.shards {
		shardCapacity := baseCapacity
		if index < extraSlots {
			shardCapacity++
		}
		cache.shards[index] = cacheShard{
			entries:  make(map[cacheKey]*list.Element, shardCapacity),
			capacity: shardCapacity,
		}
	}
	return cache
}

func (cache *ResponseCache) Compatible(other *ResponseCache) bool {
	return other != nil && cache.capacity == other.capacity && cache.options == other.options
}

func (cache *ResponseCache) Capacity() int {
	return cache.capacity
}

func (cache *ResponseCache) Get(request *dns.Msg) (*dns.Msg, bool) {
	response, found, _ := cache.GetWithPrefetch(request)
	return response, found
}

// GetWithPrefetch returns a normal cache lookup and atomically elects at most
// one caller to refresh a popular response approaching expiration.
func (cache *ResponseCache) GetWithPrefetch(request *dns.Msg) (*dns.Msg, bool, bool) {
	key, eligible := responseCacheKey(request)
	if !eligible {
		return nil, false, false
	}
	shard := cache.shard(key)
	now := cache.now()

	shard.mu.Lock()
	element, found := shard.entries[key]
	if !found {
		shard.mu.Unlock()
		return nil, false, false
	}
	entry := element.Value.(*cacheEntry)
	if !entrySatisfies(entry, request) {
		// The stored copy lacks the signatures this client asked for. Leave it in
		// place for the clients it can still serve and resolve afresh.
		shard.mu.Unlock()
		return nil, false, false
	}
	if !now.Before(entry.expiresAt) {
		if cache.options.ServeStale && now.Before(entry.retryAfter) && now.Before(entry.staleUntil) {
			shard.recency.MoveToFront(element)
			response := entry.response.Copy()
			shard.mu.Unlock()
			prepareCachedResponse(response, request)
			setResponseTTLs(response, max(cache.options.StaleAnswerTTL, 1))
			return response, true, false
		}
		if entryDead(entry, now) {
			shard.remove(element)
		}
		shard.mu.Unlock()
		return nil, false, false
	}
	shard.recency.MoveToFront(element)
	cache.recordHit(entry, now)
	prefetch := cache.electPrefetch(entry, now)
	storedResponse := entry.response
	storedAt := entry.storedAt
	shard.mu.Unlock()

	response := storedResponse.Copy()
	prepareCachedResponse(response, request)
	decrementTTLs(response, uint32(now.Sub(storedAt)/time.Second))
	return response, true, prefetch
}

// GetStale returns an expired response retained within the configured stale
// window. It is intended only as fallback after upstream resolution fails.
func (cache *ResponseCache) GetStale(request *dns.Msg) (*dns.Msg, bool) {
	if !cache.options.ServeStale {
		return nil, false
	}
	key, eligible := responseCacheKey(request)
	if !eligible {
		return nil, false
	}
	shard := cache.shard(key)
	now := cache.now()
	shard.mu.Lock()
	element, found := shard.entries[key]
	if !found {
		shard.mu.Unlock()
		return nil, false
	}
	entry := element.Value.(*cacheEntry)
	if now.Before(entry.expiresAt) || entry.staleUntil.IsZero() || !now.Before(entry.staleUntil) ||
		!entrySatisfies(entry, request) {
		if !entry.staleUntil.IsZero() && !now.Before(entry.staleUntil) {
			shard.remove(element)
		}
		shard.mu.Unlock()
		return nil, false
	}
	shard.recency.MoveToFront(element)
	entry.retryAfter = now.Add(time.Duration(max(cache.options.StaleResetTTL, 1)) * time.Second)
	response := entry.response.Copy()
	shard.mu.Unlock()
	prepareCachedResponse(response, request)
	setResponseTTLs(response, max(cache.options.StaleAnswerTTL, 1))
	return response, true
}

// HasStale reports whether a request has an expired response available for an
// outage fallback without changing its retry state.
func (cache *ResponseCache) HasStale(request *dns.Msg) bool {
	if !cache.options.ServeStale {
		return false
	}
	key, eligible := responseCacheKey(request)
	if !eligible {
		return false
	}
	shard := cache.shard(key)
	now := cache.now()
	shard.mu.Lock()
	defer shard.mu.Unlock()
	element := shard.entries[key]
	if element == nil {
		return false
	}
	entry := element.Value.(*cacheEntry)
	return entrySatisfies(entry, request) && !now.Before(entry.expiresAt) && now.Before(entry.staleUntil)
}

// entrySatisfies reports whether a stored copy carries enough detail for this
// request. A client that set DO needs the signatures the entry may not have; a
// client that did not can be served either copy, because prepareCachedResponse
// strips the extra records on the way out.
func entrySatisfies(entry *cacheEntry, request *dns.Msg) bool {
	return entry.dnssecOK || !requestWantsDNSSEC(request)
}

// entryDead reports whether both an entry's fresh and stale windows have closed,
// which is the only point at which it is safe to drop.
func entryDead(entry *cacheEntry, now time.Time) bool {
	return !now.Before(entry.expiresAt) && (entry.staleUntil.IsZero() || !now.Before(entry.staleUntil))
}

// CancelPrefetch releases the per-entry refresh election after an upstream
// failure so a later eligible hit can retry.
func (cache *ResponseCache) CancelPrefetch(request *dns.Msg) {
	key, eligible := responseCacheKey(request)
	if !eligible {
		return
	}
	shard := cache.shard(key)
	shard.mu.Lock()
	if element := shard.entries[key]; element != nil {
		element.Value.(*cacheEntry).refreshing = false
	}
	shard.mu.Unlock()
}

func (cache *ResponseCache) prefetchConfigured() bool {
	options := cache.options
	return options.PrefetchAtTTL > 0 && options.PrefetchHits > 0 && options.PrefetchSample > 0
}

// recordHit samples how often an entry is asked for. The count restarts every
// sample interval, so popularity reflects current demand rather than a lifetime
// total that never decays. The caller must hold the shard lock.
func (cache *ResponseCache) recordHit(entry *cacheEntry, now time.Time) {
	if !cache.prefetchConfigured() {
		return
	}
	if entry.hitWindow.IsZero() || now.Sub(entry.hitWindow) >= cache.options.PrefetchSample {
		entry.hitWindow = now
		entry.hits = 0
	}
	entry.hits++
}

// electPrefetch claims an entry for refresh once it is popular enough and close
// enough to expiry. Election is exclusive, so a client hit and the background
// scan can never both refresh the same entry. The caller must hold the shard lock.
func (cache *ResponseCache) electPrefetch(entry *cacheEntry, now time.Time) bool {
	if !cache.prefetchConfigured() || entry.refreshing {
		return false
	}
	options := cache.options
	if entry.expiresAt.Sub(entry.storedAt) < time.Duration(options.PrefetchMinTTL)*time.Second ||
		entry.expiresAt.Sub(now) > time.Duration(options.PrefetchAtTTL)*time.Second {
		return false
	}
	// A hit window that has already lapsed means nothing asked for this entry in
	// the current sample, so it is not popular however many hits it once had.
	if entry.hitWindow.IsZero() || now.Sub(entry.hitWindow) >= options.PrefetchSample {
		return false
	}
	if uint64(entry.hits) < cache.requiredPrefetchHits() {
		return false
	}
	entry.refreshing = true
	return true
}

func (cache *ResponseCache) requiredPrefetchHits() uint64 {
	const secondsPerHour = uint64(time.Hour / time.Second)
	sampleSeconds := max(uint64(cache.options.PrefetchSample/time.Second), 1)
	required := (uint64(cache.options.PrefetchHits)*sampleSeconds + secondsPerHour - 1) / secondsPerHour
	return max(required, 1)
}

// PrefetchCandidates elects popular entries nearing expiry and returns the
// questions that renew them. Refreshing on a client hit only ever catches
// entries that happen to be queried inside the trigger window; a background
// caller uses this to renew the rest before anybody has to wait on them.
func (cache *ResponseCache) PrefetchCandidates(limit int) []*dns.Msg {
	if !cache.prefetchConfigured() || limit <= 0 {
		return nil
	}
	now := cache.now()
	var requests []*dns.Msg
	for index := range cache.shards {
		shard := &cache.shards[index]
		shard.mu.Lock()
		for element := shard.recency.Front(); element != nil && len(requests) < limit; element = element.Next() {
			entry := element.Value.(*cacheEntry)
			if entryDead(entry, now) || !cache.electPrefetch(entry, now) {
				continue
			}
			requests = append(requests, requestFromCacheKey(entry.key, entry.dnssecOK))
		}
		shard.mu.Unlock()
		if len(requests) >= limit {
			break
		}
	}
	return requests
}

func prepareCachedResponse(response, request *dns.Msg) {
	response.Id = request.Id
	response.Question = append(response.Question[:0], request.Question...)
	response.RecursionDesired = request.RecursionDesired
	// One stored copy now serves clients that asked for different levels of
	// DNSSEC detail, so give each the same view a live resolution would: the
	// signatures it asked for, and nothing more.
	prepareResponseForClient(response, request)
}

// Set stores a response. dnssecOK states whether the stored copy was fetched
// with signatures attached, which decides whether it can later serve a client
// that set DO.
func (cache *ResponseCache) Set(request, response *dns.Msg, dnssecOK bool) bool {
	key, eligible := responseCacheKey(request)
	if !eligible {
		return false
	}
	storedResponse := response.Copy()
	stripHopByHopEDNS(storedResponse)
	ttl, cacheable := cache.responseTTL(storedResponse)
	if !cacheable {
		return false
	}
	now := cache.now()
	entry := &cacheEntry{
		key:       key,
		response:  storedResponse,
		dnssecOK:  dnssecOK,
		storedAt:  now,
		expiresAt: now.Add(time.Duration(ttl) * time.Second),
	}
	if cache.options.ServeStale && cache.options.StaleTTL > 0 && response.Rcode != dns.RcodeServerFailure {
		entry.staleUntil = entry.expiresAt.Add(time.Duration(cache.options.StaleTTL) * time.Second)
	}
	shard := cache.shard(key)

	shard.mu.Lock()
	defer shard.mu.Unlock()
	if element, found := shard.entries[key]; found {
		// Carry the popularity sample across a refresh. Starting from zero would
		// make a hot entry re-earn its eligibility every TTL, so prefetching would
		// stutter on exactly the entries it exists to keep warm.
		previous := element.Value.(*cacheEntry)
		entry.hits, entry.hitWindow = previous.hits, previous.hitWindow
		element.Value = entry
		shard.recency.MoveToFront(element)
		return true
	}
	element := shard.recency.PushFront(entry)
	shard.entries[key] = element
	if shard.recency.Len() > shard.capacity {
		shard.remove(shard.recency.Back())
	}
	return true
}

// Len reports how many entries are retained. It counts what the sweeper has
// left in place instead of walking every entry, because it backs the stats
// endpoint and a metrics scrape should not drag the whole cache under lock.
func (cache *ResponseCache) Len() int {
	total := 0
	for index := range cache.shards {
		shard := &cache.shards[index]
		shard.mu.Lock()
		total += len(shard.entries)
		shard.mu.Unlock()
	}
	return total
}

// SweepExpired drops entries whose fresh and stale windows have both closed.
// Lookups evict on contact, but an entry nobody asks for again would otherwise
// hold its slot until the shard filled up and evicted something still useful.
func (cache *ResponseCache) SweepExpired() int {
	now := cache.now()
	removed := 0
	for index := range cache.shards {
		shard := &cache.shards[index]
		shard.mu.Lock()
		for element := shard.recency.Back(); element != nil; {
			previous := element.Prev()
			if entryDead(element.Value.(*cacheEntry), now) {
				shard.remove(element)
				removed++
			}
			element = previous
		}
		shard.mu.Unlock()
	}
	return removed
}

func (cache *ResponseCache) Snapshot() []CachedResponse {
	now := cache.now()
	responses := make([]CachedResponse, 0, cache.Len())
	for index := range cache.shards {
		shard := &cache.shards[index]
		shard.mu.Lock()
		for element := shard.recency.Front(); element != nil; element = element.Next() {
			entry := element.Value.(*cacheEntry)
			// Reading the cache for the console must not mutate it; SweepExpired
			// owns removal so this walk only needs to skip what it should not show.
			if !now.Before(entry.expiresAt) {
				continue
			}
			message := entry.response.Copy()
			elapsed := uint32(now.Sub(entry.storedAt) / time.Second)
			decrementTTLs(message, elapsed)
			remaining := uint32(entry.expiresAt.Sub(now) / time.Second)
			responses = append(responses, CachedResponse{
				Name:         entry.key.name,
				RecordType:   dns.TypeToString[entry.key.recordType],
				RemainingTTL: remaining,
				Records:      cachedRecords(message),
			})
		}
		shard.mu.Unlock()
	}
	slices.SortFunc(responses, func(left, right CachedResponse) int {
		if comparison := strings.Compare(left.Name, right.Name); comparison != 0 {
			return comparison
		}
		return strings.Compare(left.RecordType, right.RecordType)
	})
	return responses
}

func cachedRecords(message *dns.Msg) []CachedRecord {
	count := len(message.Answer) + len(message.Ns) + len(message.Extra)
	records := make([]CachedRecord, 0, count)
	appendSection := func(section string, values []dns.RR) {
		for _, record := range values {
			if record.Header().Rrtype == dns.TypeOPT {
				continue
			}
			records = append(records, CachedRecord{
				Section: section,
				Value:   record.String(),
				TTL:     record.Header().Ttl,
			})
		}
	}
	appendSection("Answer", message.Answer)
	appendSection("Authority", message.Ns)
	appendSection("Additional", message.Extra)
	return records
}

func (cache *ResponseCache) Clear() int {
	removed := 0
	for index := range cache.shards {
		shard := &cache.shards[index]
		shard.mu.Lock()
		removed += len(shard.entries)
		clear(shard.entries)
		shard.recency.Init()
		shard.mu.Unlock()
	}
	return removed
}

// Export returns all fresh entries and any expired entries still inside their
// configured stale window.
func (cache *ResponseCache) Export() ([]PersistedResponse, error) {
	now := cache.now()
	entries := make([]PersistedResponse, 0, cache.Len())
	var exportErrors []error
	for index := range cache.shards {
		shard := &cache.shards[index]
		shard.mu.Lock()
		for element := shard.recency.Front(); element != nil; element = element.Next() {
			entry := element.Value.(*cacheEntry)
			if entryDead(entry, now) {
				continue
			}
			request := requestFromCacheKey(entry.key, entry.dnssecOK)
			requestWire, err := request.Pack()
			if err != nil {
				exportErrors = append(exportErrors, fmt.Errorf("pack cached request %q: %w", entry.key.name, err))
				continue
			}
			responseWire, err := entry.response.Pack()
			if err != nil {
				exportErrors = append(exportErrors, fmt.Errorf("pack cached response %q: %w", entry.key.name, err))
				continue
			}
			entries = append(entries, PersistedResponse{
				RequestWire: requestWire, ResponseWire: responseWire,
				StoredAt: entry.storedAt, ExpiresAt: entry.expiresAt, StaleUntil: entry.staleUntil,
			})
		}
		shard.mu.Unlock()
	}
	return entries, errors.Join(exportErrors...)
}

// Restore imports valid, unexpired entries up to the configured cache bound.
// Malformed rows are reported while valid rows are still restored.
func (cache *ResponseCache) Restore(entries []PersistedResponse) (int, error) {
	now := cache.now()
	restored := 0
	var restoreErrors []error
	for index, persisted := range entries {
		request := new(dns.Msg)
		if err := request.Unpack(persisted.RequestWire); err != nil {
			restoreErrors = append(restoreErrors, fmt.Errorf("unpack cached request %d: %w", index, err))
			continue
		}
		key, eligible := responseCacheKey(request)
		if !eligible || persisted.StoredAt.After(now) || !persisted.ExpiresAt.After(persisted.StoredAt) {
			restoreErrors = append(restoreErrors, fmt.Errorf("cached response %d has invalid metadata", index))
			continue
		}
		if !now.Before(persisted.ExpiresAt) && (!cache.options.ServeStale || !now.Before(persisted.StaleUntil)) {
			continue
		}
		response := new(dns.Msg)
		if err := response.Unpack(persisted.ResponseWire); err != nil {
			restoreErrors = append(restoreErrors, fmt.Errorf("unpack cached response %d: %w", index, err))
			continue
		}
		entry := &cacheEntry{
			key: key, response: response, dnssecOK: requestWantsDNSSEC(request),
			storedAt:  persisted.StoredAt,
			expiresAt: persisted.ExpiresAt, staleUntil: persisted.StaleUntil,
		}
		shard := cache.shard(key)
		shard.mu.Lock()
		if existing := shard.entries[key]; existing != nil {
			existing.Value = entry
			shard.recency.MoveToFront(existing)
		} else {
			element := shard.recency.PushFront(entry)
			shard.entries[key] = element
			if shard.recency.Len() > shard.capacity {
				shard.remove(shard.recency.Back())
			}
		}
		shard.mu.Unlock()
		restored++
	}
	return restored, errors.Join(restoreErrors...)
}

// requestFromCacheKey rebuilds the question that produced an entry, for
// refreshing it upstream or persisting it across a restart. The DO bit comes
// from the entry rather than the key, and round-trips through the packed request
// so a restored entry knows whether it still carries signatures.
func requestFromCacheKey(key cacheKey, dnssecOK bool) *dns.Msg {
	request := new(dns.Msg)
	request.SetQuestion(key.name, key.recordType)
	request.Question[0].Qclass = key.class
	request.RecursionDesired = true
	request.SetEdns0(prefetchUDPSize, dnssecOK)
	return request
}

func (cache *ResponseCache) shard(key cacheKey) *cacheShard {
	return &cache.shards[cacheKeyHash(key)%uint64(len(cache.shards))]
}

func (shard *cacheShard) remove(element *list.Element) {
	if element == nil {
		return
	}
	entry := element.Value.(*cacheEntry)
	delete(shard.entries, entry.key)
	shard.recency.Remove(element)
}

func responseCacheKey(request *dns.Msg) (cacheKey, bool) {
	if request.Opcode != dns.OpcodeQuery || len(request.Question) != 1 {
		return cacheKey{}, false
	}
	question := request.Question[0]
	if option := request.IsEdns0(); option != nil {
		for _, edns := range option.Option {
			if !hopByHopEDNSOption(edns.Option()) {
				return cacheKey{}, false
			}
		}
	}
	return cacheKey{
		name:       strings.ToLower(question.Name),
		recordType: question.Qtype,
		class:      question.Qclass,
	}, true
}

// hopByHopEDNSOption reports whether an EDNS option describes the transport hop
// rather than the answer. Cookies and padding are rewritten by every hop, so
// keying on them would leave every DoH, DoT, and cookie-aware stub permanently
// uncacheable. Options that vary the answer, such as client subnet, still
// bypass the cache entirely.
func hopByHopEDNSOption(code uint16) bool {
	switch code {
	case dns.EDNS0COOKIE, dns.EDNS0PADDING, dns.EDNS0TCPKEEPALIVE:
		return true
	default:
		return false
	}
}

// stripHopByHopEDNS removes hop-scoped options from a response before it is
// shared, so one client's cookie or padding is never replayed to another.
func stripHopByHopEDNS(message *dns.Msg) {
	option := message.IsEdns0()
	if option == nil {
		return
	}
	option.Option = slices.DeleteFunc(option.Option, func(edns dns.EDNS0) bool {
		return hopByHopEDNSOption(edns.Option())
	})
}

func (cache *ResponseCache) responseTTL(response *dns.Msg) (uint32, bool) {
	switch response.Rcode {
	case dns.RcodeSuccess:
		if len(response.Answer) == 0 {
			return cache.negativeTTL(response)
		}
		clampResponseTTLs(response, cache.options.MinimumTTL, cache.options.MaximumTTL)
		ttl, found := minimumAnswerTTL(response)
		return ttl, found && ttl > 0
	case dns.RcodeNameError:
		return cache.negativeTTL(response)
	case dns.RcodeServerFailure:
		if cache.options.FailureTTL == 0 {
			return 0, false
		}
		setResponseTTLs(response, cache.options.FailureTTL)
		return cache.options.FailureTTL, true
	default:
		return 0, false
	}
}

func responseTTL(response *dns.Msg) (uint32, bool) {
	return (&ResponseCache{}).responseTTL(response)
}

// negativeTTL derives how long a NODATA or NXDOMAIN answer may be held. RFC 2308
// puts that in the zone's own SOA, so the configured value caps it rather than
// replacing it: a zone that asks to be forgotten in thirty seconds must not be
// remembered for five minutes because the resolver prefers a rounder number.
func (cache *ResponseCache) negativeTTL(response *dns.Msg) (uint32, bool) {
	ttl, found := negativeResponseTTL(response)
	switch {
	case found && cache.options.NegativeTTL > 0:
		ttl = min(ttl, cache.options.NegativeTTL)
	case !found:
		if cache.options.NegativeTTL == 0 {
			return 0, false
		}
		ttl = cache.options.NegativeTTL
	}
	// The floor applies here for the same reason it applies to answers: it stops
	// a pathologically short SOA from making the cache useless.
	ttl = max(ttl, cache.options.MinimumTTL)
	if ttl == 0 {
		return 0, false
	}
	setResponseTTLs(response, ttl)
	return ttl, true
}

func clampResponseTTLs(response *dns.Msg, minimum, maximum uint32) {
	for _, records := range [][]dns.RR{response.Answer, response.Ns, response.Extra} {
		for _, record := range records {
			if record.Header().Rrtype == dns.TypeOPT {
				continue
			}
			if maximum > 0 {
				record.Header().Ttl = min(record.Header().Ttl, maximum)
			}
			if minimum > 0 {
				record.Header().Ttl = max(record.Header().Ttl, minimum)
			}
		}
	}
}

func setResponseTTLs(response *dns.Msg, ttl uint32) {
	for _, records := range [][]dns.RR{response.Answer, response.Ns, response.Extra} {
		for _, record := range records {
			if record.Header().Rrtype != dns.TypeOPT {
				record.Header().Ttl = ttl
			}
		}
	}
}

// minimumAnswerTTL bounds an entry by its answer section alone. A short-lived NS
// or glue record riding along in the authority or additional section says nothing
// about how long the answer is good for, and letting it shorten the entry threw
// away answers that were still valid for hours.
func minimumAnswerTTL(response *dns.Msg) (uint32, bool) {
	minimum := ^uint32(0)
	found := false
	for _, record := range response.Answer {
		if record.Header().Rrtype == dns.TypeOPT {
			continue
		}
		minimum = min(minimum, record.Header().Ttl)
		found = true
	}
	if !found {
		return 0, false
	}
	return minimum, true
}

// negativeResponseTTL reports the zone's own view of how long a negative answer
// may be held, per RFC 2308: the lesser of the SOA record's TTL and its MINIMUM
// field. The boolean reports whether an SOA was present at all, which is a
// different question from whether the TTL it carried was usable.
func negativeResponseTTL(response *dns.Msg) (uint32, bool) {
	for _, record := range response.Ns {
		soa, ok := record.(*dns.SOA)
		if !ok {
			continue
		}
		return min(soa.Hdr.Ttl, soa.Minttl), true
	}
	return 0, false
}

func decrementTTLs(response *dns.Msg, elapsed uint32) {
	if elapsed == 0 {
		return
	}
	for _, records := range [][]dns.RR{response.Answer, response.Ns, response.Extra} {
		for _, record := range records {
			if record.Header().Rrtype == dns.TypeOPT {
				continue
			}
			if record.Header().Ttl > elapsed {
				record.Header().Ttl -= elapsed
			} else {
				record.Header().Ttl = 0
			}
		}
	}
}

func cacheKeyHash(key cacheKey) uint64 {
	const (
		offset = 14695981039346656037
		prime  = 1099511628211
	)
	hash := uint64(offset)
	for index := range len(key.name) {
		hash ^= uint64(key.name[index])
		hash *= prime
	}
	hash ^= uint64(key.recordType)<<48 | uint64(key.class)<<32
	return hash
}
