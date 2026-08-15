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
)

type cacheKey struct {
	name             string
	recordType       uint16
	class            uint16
	udpSize          uint16
	dnssecOK         bool
	checkingDisabled bool
}

type cacheEntry struct {
	key        cacheKey
	response   *dns.Msg
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
	if !now.Before(entry.expiresAt) {
		if cache.options.ServeStale && now.Before(entry.retryAfter) && now.Before(entry.staleUntil) {
			shard.recency.MoveToFront(element)
			response := entry.response.Copy()
			shard.mu.Unlock()
			prepareCachedResponse(response, request)
			setResponseTTLs(response, max(cache.options.StaleAnswerTTL, 1))
			return response, true, false
		}
		if entry.staleUntil.IsZero() || !now.Before(entry.staleUntil) {
			shard.remove(element)
		}
		shard.mu.Unlock()
		return nil, false, false
	}
	shard.recency.MoveToFront(element)
	prefetch := cache.startPrefetch(entry, now)
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
	if now.Before(entry.expiresAt) || entry.staleUntil.IsZero() || !now.Before(entry.staleUntil) {
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
	return !now.Before(entry.expiresAt) && now.Before(entry.staleUntil)
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

func (cache *ResponseCache) startPrefetch(entry *cacheEntry, now time.Time) bool {
	options := cache.options
	if options.PrefetchAtTTL == 0 || options.PrefetchHits == 0 || options.PrefetchSample <= 0 || entry.refreshing {
		return false
	}
	if entry.expiresAt.Sub(entry.storedAt) < time.Duration(options.PrefetchMinTTL)*time.Second ||
		entry.expiresAt.Sub(now) > time.Duration(options.PrefetchAtTTL)*time.Second {
		return false
	}
	if entry.hitWindow.IsZero() || now.Sub(entry.hitWindow) >= options.PrefetchSample {
		entry.hitWindow = now
		entry.hits = 0
	}
	entry.hits++
	sampleSeconds := max(uint64(options.PrefetchSample/time.Second), 1)
	requiredHits := (uint64(options.PrefetchHits)*sampleSeconds + uint64(time.Hour/time.Second) - 1) / uint64(time.Hour/time.Second)
	requiredHits = max(requiredHits, 1)
	if uint64(entry.hits) < requiredHits {
		return false
	}
	entry.refreshing = true
	return true
}

func prepareCachedResponse(response, request *dns.Msg) {
	response.Id = request.Id
	response.Question = append(response.Question[:0], request.Question...)
	response.RecursionDesired = request.RecursionDesired
	response.CheckingDisabled = request.CheckingDisabled
	response.AuthenticatedData = response.AuthenticatedData && (request.AuthenticatedData || requestWantsDNSSEC(request))
}

func (cache *ResponseCache) Set(request, response *dns.Msg) bool {
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

func (cache *ResponseCache) Len() int {
	total := 0
	now := cache.now()
	for index := range cache.shards {
		shard := &cache.shards[index]
		shard.mu.Lock()
		for element := shard.recency.Back(); element != nil; {
			previous := element.Prev()
			entry := element.Value.(*cacheEntry)
			if !now.Before(entry.expiresAt) && (entry.staleUntil.IsZero() || !now.Before(entry.staleUntil)) {
				shard.remove(element)
			}
			element = previous
		}
		total += len(shard.entries)
		shard.mu.Unlock()
	}
	return total
}

func (cache *ResponseCache) Snapshot() []CachedResponse {
	now := cache.now()
	responses := make([]CachedResponse, 0, cache.Len())
	for index := range cache.shards {
		shard := &cache.shards[index]
		shard.mu.Lock()
		for element := shard.recency.Front(); element != nil; {
			next := element.Next()
			entry := element.Value.(*cacheEntry)
			if !now.Before(entry.expiresAt) && (entry.staleUntil.IsZero() || !now.Before(entry.staleUntil)) {
				shard.remove(element)
				element = next
				continue
			}
			if !now.Before(entry.expiresAt) {
				element = next
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
			element = next
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
			if !now.Before(entry.expiresAt) && (entry.staleUntil.IsZero() || !now.Before(entry.staleUntil)) {
				continue
			}
			request := requestFromCacheKey(entry.key)
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
			key: key, response: response, storedAt: persisted.StoredAt,
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

func requestFromCacheKey(key cacheKey) *dns.Msg {
	request := new(dns.Msg)
	request.SetQuestion(key.name, key.recordType)
	request.Question[0].Qclass = key.class
	request.CheckingDisabled = key.checkingDisabled
	if key.udpSize != minimumDNSUDPSize || key.dnssecOK {
		request.SetEdns0(key.udpSize, key.dnssecOK)
	}
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
	key := cacheKey{
		name:             strings.ToLower(question.Name),
		recordType:       question.Qtype,
		class:            question.Qclass,
		udpSize:          minimumDNSUDPSize,
		checkingDisabled: request.CheckingDisabled,
	}
	if option := request.IsEdns0(); option != nil {
		for _, edns := range option.Option {
			if !hopByHopEDNSOption(edns.Option()) {
				return cacheKey{}, false
			}
		}
		key.udpSize = option.UDPSize()
		key.dnssecOK = option.Do()
	}
	return key, true
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
		ttl := minimumResponseTTL(response)
		return ttl, ttl > 0
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

func (cache *ResponseCache) negativeTTL(response *dns.Msg) (uint32, bool) {
	if cache.options.NegativeTTL > 0 {
		setResponseTTLs(response, cache.options.NegativeTTL)
		return cache.options.NegativeTTL, true
	}
	return negativeResponseTTL(response)
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

func minimumResponseTTL(response *dns.Msg) uint32 {
	minimum := ^uint32(0)
	found := false
	for _, records := range [][]dns.RR{response.Answer, response.Ns, response.Extra} {
		for _, record := range records {
			if record.Header().Rrtype == dns.TypeOPT {
				continue
			}
			minimum = min(minimum, record.Header().Ttl)
			found = true
		}
	}
	if !found {
		return 0
	}
	return minimum
}

func negativeResponseTTL(response *dns.Msg) (uint32, bool) {
	for _, record := range response.Ns {
		soa, ok := record.(*dns.SOA)
		if !ok {
			continue
		}
		ttl := min(soa.Hdr.Ttl, soa.Minttl)
		return ttl, ttl > 0
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
	hash ^= uint64(key.recordType)<<48 | uint64(key.class)<<32 | uint64(key.udpSize)<<16
	if key.dnssecOK {
		hash ^= 1
	}
	if key.checkingDisabled {
		hash ^= 2
	}
	return hash
}
