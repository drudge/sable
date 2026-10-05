package dnsserver

import (
	"cmp"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"strings"
	"time"

	"github.com/miekg/dns"

	"github.com/drudge/sable/internal/clientaccess"
	"github.com/drudge/sable/internal/dnsname"
	"github.com/drudge/sable/internal/forwarding"
	zonemodel "github.com/drudge/sable/internal/zone"
)

// Compile validates configuration and builds the Runtime that serves it. It
// runs in the same order the checks have always run, so the first invalid
// setting is still the one reported.
func Compile(configuration RuntimeConfig) (*Runtime, error) {
	runtime, err := compileResolver(configuration)
	if err != nil {
		return nil, err
	}
	if err := runtime.compilePolicy(configuration); err != nil {
		return nil, err
	}
	if runtime.routes, err = compileRoutes(configuration.Routes); err != nil {
		return nil, err
	}
	if runtime.hosts, err = compileHosts(configuration.Hosts); err != nil {
		return nil, err
	}
	if runtime.tsigKeys, err = compileTSIGKeys(configuration.TSIGKeys); err != nil {
		return nil, err
	}
	if err := runtime.compileZones(configuration.Zones); err != nil {
		return nil, err
	}
	if runtime.dnssec != nil {
		runtime.dnssec.setZoneInsecure(runtime.zoneInsecure)
	}
	runtime.upstreams = upstreamSignature(configuration.Forwarders, runtime.routes) + "|mode=" + runtime.mode +
		"|roots=" + strings.Join(runtime.rootHints, ",") + dnssecRuntimeSignature(configuration)
	return runtime, nil
}

// compileResolver checks the resolver limits, mode, recursion access, root
// hints, timeouts and DNSSEC validator, and returns a Runtime holding them and
// the response cache.
func compileResolver(configuration RuntimeConfig) (*Runtime, error) {
	totalLimit := cmp.Or(configuration.MaxConcurrent, defaultMaxConcurrent)
	clientLimit := cmp.Or(configuration.MaxConcurrentPerClient, defaultMaxConcurrentPerClient)
	if totalLimit < 1 || totalLimit > maximumConcurrentResolutions || clientLimit < 1 || clientLimit > totalLimit {
		return nil, fmt.Errorf("resolver concurrency must be between 1 and %d, with the client limit no greater than the total", maximumConcurrentResolutions)
	}
	mode := strings.ToLower(strings.TrimSpace(configuration.Mode))
	if mode == "" {
		mode = "forward"
	}
	if mode != "forward" && mode != "recursive" {
		return nil, errors.New("resolver mode must be forward or recursive")
	}
	if mode == "forward" && len(configuration.Forwarders) == 0 {
		return nil, errors.New("at least one forwarder is required in forward mode")
	}
	recursion, err := clientaccess.Compile(configuration.Recursion, configuration.RecursionClients)
	if err != nil {
		return nil, err
	}
	rootHints, err := normalizeRootHints(configuration.RootHints)
	if err != nil {
		return nil, err
	}
	if configuration.Timeout <= 0 {
		return nil, errors.New("resolver timeout must be positive")
	}
	if configuration.CacheSize <= 0 {
		return nil, errors.New("cache size must be positive")
	}
	var validator *dnssecValidator
	if configuration.DNSSECValidation {
		validator, err = newDNSSECValidator(configuration.DNSSECTrustAnchors, configuration.DNSSECNegativeTrustAnchors)
		if err != nil {
			return nil, fmt.Errorf("compile DNSSEC validator: %w", err)
		}
	}
	return &Runtime{
		maxConcurrent: totalLimit, maxConcurrentPerClient: clientLimit,
		recursion:         recursion,
		mode:              mode,
		forwarders:        append([]string(nil), configuration.Forwarders...),
		rootHints:         rootHints,
		qnameMinimization: !configuration.DisableQNAMEMinimization,
		delegations:       newDelegationCache(4096),
		zoneCuts:          newZoneCutCache(4096),
		nameServers:       newAddressCache(4096),
		baseRoutes:        cloneForwardingRoutes(configuration.Routes),
		timeout:           configuration.Timeout,
		retries:           cmp.Or(configuration.Retries, defaultRuntimeRetries),
		retryTimeout:      cmp.Or(configuration.RetryTimeout, defaultRuntimeRetryTimeout),
		staleMaxWait:      configuration.CacheStaleMaxWait,
		cache: NewResponseCacheWithOptions(configuration.CacheSize, CacheOptions{
			MinimumTTL: configuration.CacheMinimumTTL, MaximumTTL: configuration.CacheMaximumTTL,
			NegativeTTL: configuration.CacheNegativeTTL, FailureTTL: configuration.CacheFailureTTL,
			ServeStale: configuration.ServeStale, StaleTTL: configuration.CacheStaleTTL,
			StaleAnswerTTL: configuration.CacheStaleAnswerTTL, StaleResetTTL: configuration.CacheStaleResetTTL,
			PrefetchMinTTL: configuration.CachePrefetchMinimumTTL, PrefetchAtTTL: configuration.CachePrefetchTriggerTTL,
			PrefetchSample: configuration.CachePrefetchSample, PrefetchHits: configuration.CachePrefetchHitsPerHour,
		}),
		blockLists:          append([]BlockListStats(nil), configuration.BlockLists...),
		dnssec:              validator,
		managedTrustAnchors: configuration.DNSSECValidation && configuration.DNSSECTrustAnchorUpdates && len(configuration.DNSSECTrustAnchors) == 0,
		zoneSource:          configuration.Zones,
		keySource:           configuration.TSIGKeys,
	}, nil
}

// compilePolicy fills in the block and allow lists, the blocking response and
// the clients that bypass blocking.
func (runtime *Runtime) compilePolicy(configuration RuntimeConfig) error {
	blocked := make(map[string]uint32, len(configuration.BlockedDomains))
	attributed := len(configuration.BlockedDomainOwners) == len(configuration.BlockedDomains)
	for index, domain := range configuration.BlockedDomains {
		owner := uint32(0)
		if attributed && int(configuration.BlockedDomainOwners[index]) < len(configuration.BlockedDomainOwnerSets) {
			owner = configuration.BlockedDomainOwners[index]
		}
		trimmed := strings.TrimPrefix(strings.TrimSpace(domain), "*.")
		// Block lists arrive already normalized by the block-list compiler, which
		// ran the same IDNA pass. Skip the expensive second idna.ToASCII for a
		// name that is already in canonical form; only re-normalize the rest.
		if isCanonicalDomain(trimmed) {
			blocked[trimmed] = owner
			continue
		}
		normalized, err := dnsname.Normalize(trimmed)
		if err != nil {
			return fmt.Errorf("invalid blocked domain %q: %w", domain, err)
		}
		blocked[normalized] = owner
	}
	allowedExact := make(map[string]struct{}, len(configuration.AllowedDomains))
	allowedWildcard := make(map[string]struct{}, len(configuration.AllowedDomains))
	for _, domain := range configuration.AllowedDomains {
		domain = strings.TrimSpace(domain)
		wildcard := strings.HasPrefix(domain, "*.")
		normalized, err := dnsname.Normalize(strings.TrimPrefix(domain, "*."))
		if err != nil {
			return fmt.Errorf("invalid allowed domain %q: %w", domain, err)
		}
		if wildcard {
			allowedWildcard[normalized] = struct{}{}
		} else {
			allowedExact[normalized] = struct{}{}
		}
	}
	blockingType := configuration.BlockingType
	if blockingType == "" {
		blockingType = "nxdomain"
	}
	if blockingType != "nxdomain" && blockingType != "zero" && blockingType != "custom" {
		return fmt.Errorf("invalid blocking response type %q", configuration.BlockingType)
	}
	blockAddresses := make([]netip.Addr, 0, len(configuration.BlockingAddrs)+2)
	if blockingType == "zero" {
		blockAddresses = append(blockAddresses, netip.IPv4Unspecified(), netip.IPv6Unspecified())
	} else if blockingType == "custom" {
		for _, value := range configuration.BlockingAddrs {
			address, err := netip.ParseAddr(value)
			if err != nil || address.Zone() != "" {
				return fmt.Errorf("invalid custom blocking address %q", value)
			}
			blockAddresses = append(blockAddresses, address.Unmap())
		}
	}
	bypass := make([]netip.Prefix, 0, len(configuration.BypassClients))
	for _, value := range configuration.BypassClients {
		prefix, err := netip.ParsePrefix(value)
		if err != nil {
			address, addressErr := netip.ParseAddr(value)
			if addressErr != nil || address.Zone() != "" {
				return fmt.Errorf("invalid blocking bypass client %q", value)
			}
			prefix = netip.PrefixFrom(address.Unmap(), address.Unmap().BitLen())
		}
		bypass = append(bypass, prefix.Masked())
	}
	runtime.blocked = blocked
	runtime.blockedOwners = configuration.BlockedDomainOwnerSets
	runtime.allowedExact = allowedExact
	runtime.allowedWildcard = allowedWildcard
	runtime.blocking = configuration.Blocking
	runtime.blockType = blockingType
	runtime.blockTTL = configuration.BlockingTTL
	runtime.blockAddrs = blockAddresses
	runtime.bypass = bypass
	runtime.blockTXT = configuration.AllowTXTReport
	return nil
}

// compileRoutes builds the conditional forwarding table, keyed by the
// normalized domain.
func compileRoutes(configured []ForwardingRoute) (map[string][]string, error) {
	routes := make(map[string][]string, len(configured))
	for _, route := range configured {
		domain, err := dnsname.Normalize(route.Domain)
		if err != nil || len(route.Forwarders) == 0 {
			return nil, fmt.Errorf("conditional forwarding route %q is invalid", route.Domain)
		}
		if _, duplicate := routes[domain]; duplicate {
			return nil, fmt.Errorf("duplicate conditional forwarding route %q", route.Domain)
		}
		routes[domain] = append([]string(nil), route.Forwarders...)
	}
	return routes, nil
}

// compileHosts turns the local host overrides into ready-made A and AAAA
// records.
func compileHosts(configured []HostOverride) (map[string]localHostRecords, error) {
	hosts := make(map[string]localHostRecords, len(configured))
	for _, host := range configured {
		name, err := dnsname.Normalize(host.Name)
		if err != nil || host.TTL == 0 || len(host.Addresses) == 0 {
			return nil, fmt.Errorf("local host override %q is invalid", host.Name)
		}
		if _, duplicate := hosts[name]; duplicate {
			return nil, fmt.Errorf("duplicate local host override %q", host.Name)
		}
		records := localHostRecords{}
		for _, rawAddress := range host.Addresses {
			address, err := netip.ParseAddr(rawAddress)
			if err != nil || address.Zone() != "" {
				return nil, fmt.Errorf("local host override %q has invalid address %q", host.Name, rawAddress)
			}
			address = address.Unmap()
			header := dns.RR_Header{Name: dns.Fqdn(name), Class: dns.ClassINET, Ttl: host.TTL}
			if address.Is4() {
				header.Rrtype = dns.TypeA
				records.ipv4 = append(records.ipv4, &dns.A{Hdr: header, A: net.IP(address.AsSlice())})
			} else {
				header.Rrtype = dns.TypeAAAA
				records.ipv6 = append(records.ipv6, &dns.AAAA{Hdr: header, AAAA: net.IP(address.AsSlice())})
			}
		}
		hosts[name] = records
	}
	return hosts, nil
}

// compileTSIGKeys indexes the TSIG keys by their canonical name, defaulting
// the algorithm to HMAC-SHA256.
func compileTSIGKeys(configured []TSIGKey) (map[string]tsigKey, error) {
	tsigKeys := make(map[string]tsigKey, len(configured))
	for _, key := range configured {
		name := strings.ToLower(dns.Fqdn(strings.TrimSpace(key.Name)))
		if _, duplicate := tsigKeys[name]; duplicate {
			return nil, fmt.Errorf("duplicate TSIG key %q", name)
		}
		algorithm := strings.ToLower(dns.Fqdn(strings.TrimSpace(key.Algorithm)))
		if algorithm == "." {
			algorithm = dns.HmacSHA256
		}
		tsigKeys[name] = tsigKey{algorithm: algorithm, secret: key.Secret}
	}
	return tsigKeys, nil
}

// compileZones compiles every enabled zone. Stub zones and FWD records add to
// runtime.routes, so compileRoutes must run first.
func (runtime *Runtime) compileZones(configured []AuthoritativeZone) error {
	runtime.zones = make(map[string]*authoritativeZone, len(configured))
	runtime.managedZones = make(map[string]managedZone)
	runtime.zoneInsecure = make([]string, 0)
	for _, configuredZone := range configured {
		if configuredZone.Disabled || configuredZone.AwaitingTransfer {
			continue
		}
		runtime.zoneCount++
		if err := runtime.compileZone(configuredZone); err != nil {
			return err
		}
	}
	slices.Sort(runtime.zoneInsecure)
	return nil
}

// compileZone compiles one enabled zone into runtime. A stub zone only adds a
// forwarding route to its primaries; every other type is compiled into the
// zone map.
func (runtime *Runtime) compileZone(configuredZone AuthoritativeZone) error {
	zoneName, err := dnsname.Normalize(configuredZone.Name)
	if err != nil || len(configuredZone.Records) == 0 {
		return fmt.Errorf("authoritative zone %q is invalid", configuredZone.Name)
	}
	if _, duplicate := runtime.zones[zoneName]; duplicate {
		return fmt.Errorf("duplicate authoritative zone %q", configuredZone.Name)
	}
	zoneType := strings.ToLower(strings.TrimSpace(configuredZone.Type))
	if zoneType == "" {
		zoneType = "primary"
	}
	if configuredZone.DNSSECValidationDisabled {
		if !zonemodel.IsForwarderType(zoneType) && zoneType != "stub" {
			return fmt.Errorf("authoritative zone %q may not disable DNSSEC validation for a %s zone", zoneName, zoneType)
		}
		runtime.zoneInsecure = append(runtime.zoneInsecure, zoneName)
	}
	zoneTSIGKey := ""
	if strings.TrimSpace(configuredZone.TSIGKey) != "" {
		zoneTSIGKey = strings.ToLower(dns.Fqdn(strings.TrimSpace(configuredZone.TSIGKey)))
		if _, found := runtime.tsigKeys[zoneTSIGKey]; !found {
			return fmt.Errorf("authoritative zone %q references unknown TSIG key %q", zoneName, zoneTSIGKey)
		}
	}
	if zoneType == "stub" {
		return runtime.compileStubZone(configuredZone, zoneName, zoneTSIGKey)
	}
	// A catalog zone with primary servers is transferred exactly like a
	// secondary. It is compiled into the zone map either way so that a
	// published catalog can be served over AXFR/IXFR and journaled for
	// incremental transfers.
	if zoneType == "secondary" || zoneType == zonemodel.TypeSecondaryForwarder || (zoneType == "catalog" && len(configuredZone.PrimaryServers) > 0) {
		runtime.managedZones[zoneName] = managedZone{kind: zoneType, primaries: append([]string(nil), configuredZone.PrimaryServers...), tsigKey: zoneTSIGKey}
	}
	zone := &authoritativeZone{
		name: zoneName, records: make(map[string]map[uint16][]authoritativeRecord),
		anames: make(map[string][]authoritativeANAME), forwarders: make(map[string][]authoritativeForwarder),
		owners:       make(map[string]struct{}),
		transferMode: configuredZone.ZoneTransfer,
		tsigKey:      zoneTSIGKey,
		kind:         zoneType,
		dynamic:      configuredZone.DynamicUpdates,
	}
	if zone.transferMode == "" {
		zone.transferMode = "deny"
	}
	for _, rawPrefix := range configuredZone.TransferACL {
		prefix, parseErr := netip.ParsePrefix(rawPrefix)
		if parseErr != nil {
			address, addressErr := netip.ParseAddr(rawPrefix)
			if addressErr != nil || address.Zone() != "" {
				return fmt.Errorf("authoritative zone %q transfer ACL %q is invalid", zoneName, rawPrefix)
			}
			prefix = netip.PrefixFrom(address, address.BitLen())
		}
		zone.transferACL = append(zone.transferACL, prefix)
	}
	if err := zone.compileRecords(configuredZone.Records); err != nil {
		return err
	}
	if len(zone.soa) != 1 || (!zonemodel.IsForwarderType(zoneType) && len(zone.records[zoneName][dns.TypeNS]) == 0) {
		return fmt.Errorf("authoritative zone %q has invalid authority records", zoneName)
	}
	if zonemodel.IsForwarderType(zoneType) && len(zone.forwarders[zoneName]) == 0 {
		return fmt.Errorf("forwarder zone %q requires an active apex FWD record", zoneName)
	}
	if err := runtime.routeZoneForwarders(zone); err != nil {
		return err
	}
	runtime.zones[zoneName] = zone
	return nil
}

// routeZoneForwarders orders each FWD owner's forwarders by priority and adds
// them to the forwarding table, refusing an owner that already has a route.
func (runtime *Runtime) routeZoneForwarders(zone *authoritativeZone) error {
	for owner, ordered := range zone.forwarders {
		slices.SortFunc(ordered, func(left, right authoritativeForwarder) int {
			return int(left.priority) - int(right.priority)
		})
		if _, duplicate := runtime.routes[owner]; duplicate {
			return fmt.Errorf("authoritative zone %q FWD owner duplicates forwarding route %q", zone.name, owner)
		}
		endpoints := make([]string, 0, len(ordered))
		for _, forwarder := range ordered {
			endpoints = append(endpoints, forwarder.endpoint)
		}
		runtime.routes[owner] = endpoints
		zone.forwarders[owner] = ordered
	}
	return nil
}

// compileStubZone records a stub zone and routes its name to the zone's
// primary servers.
func (runtime *Runtime) compileStubZone(configuredZone AuthoritativeZone, zoneName, zoneTSIGKey string) error {
	runtime.managedZones[zoneName] = managedZone{kind: "stub", primaries: append([]string(nil), configuredZone.PrimaryServers...), tsigKey: zoneTSIGKey}
	if _, duplicate := runtime.routes[zoneName]; duplicate {
		return fmt.Errorf("stub zone %q duplicates a forwarding route", zoneName)
	}
	protocol := configuredZone.PrimaryProtocol
	if protocol == "" {
		protocol = "udp"
	}
	for _, primary := range configuredZone.PrimaryServers {
		runtime.routes[zoneName] = append(runtime.routes[zoneName], protocol+"://"+primary)
	}
	if len(runtime.routes[zoneName]) == 0 {
		return fmt.Errorf("stub zone %q requires at least one primary server", zoneName)
	}
	return nil
}

// compileRecords adds the zone's active records, ANAMEs and FWDs, and marks
// the zone signed when it carries both DNSKEY and RRSIG records.
func (zone *authoritativeZone) compileRecords(records []ZoneRecord) error {
	zoneName := zone.name
	hasDNSKEY, hasRRSIG := false, false
	for _, record := range records {
		if record.Disabled || (!record.ExpiresAt.IsZero() && !record.ExpiresAt.After(time.Now())) {
			continue
		}
		owner, err := authoritativeOwner(zoneName, record.Name)
		if err != nil {
			return fmt.Errorf("authoritative zone %q record owner %q: %w", zoneName, record.Name, err)
		}
		recordType := strings.ToUpper(strings.TrimSpace(record.Type))
		if recordType == "ANAME" {
			target, normalizeErr := dnsname.Normalize(record.Value)
			if normalizeErr != nil {
				return fmt.Errorf("compile authoritative zone %q ANAME record: %w", zoneName, normalizeErr)
			}
			zone.anames[owner] = append(zone.anames[owner], authoritativeANAME{
				target: target, ttl: record.TTL, expiresAt: record.ExpiresAt,
			})
			zone.owners[owner] = struct{}{}
			continue
		}
		if recordType == "FWD" {
			forwarder, parseErr := forwarding.ParseRecord(record.Value)
			if parseErr != nil {
				return fmt.Errorf("compile authoritative zone %q FWD record: %w", zoneName, parseErr)
			}
			zone.forwarders[owner] = append(zone.forwarders[owner], authoritativeForwarder{
				priority: forwarder.Priority, endpoint: forwarder.Endpoint(),
			})
			zone.owners[owner] = struct{}{}
			continue
		}
		if _, found := dns.StringToType[recordType]; !found {
			return fmt.Errorf("authoritative zone %q has unsupported record type %q", zoneName, record.Type)
		}
		rr, err := dns.NewRR(fmt.Sprintf("%s %d IN %s %s", dns.Fqdn(owner), record.TTL, recordType, record.Value))
		if err != nil {
			return fmt.Errorf("compile authoritative zone %q record: %w", zoneName, err)
		}
		if owner != zoneName && !strings.HasSuffix(owner, "."+zoneName) {
			return fmt.Errorf("authoritative record owner %q is outside zone %q", owner, zoneName)
		}
		zone.addRecord(owner, rr, record.ExpiresAt)
		switch rr.Header().Rrtype {
		case dns.TypeDNSKEY:
			hasDNSKEY = true
		case dns.TypeRRSIG:
			hasRRSIG = true
		}
	}
	zone.signed = hasDNSKEY && hasRRSIG
	return nil
}

// addRecord indexes rr under its owner and type, marks the owner and its
// ancestors inside the zone as existing, and keeps the SOA and NSEC/NSEC3
// records in their own lists for negative answers.
func (zone *authoritativeZone) addRecord(owner string, rr dns.RR, expiresAt time.Time) {
	byType := zone.records[owner]
	if byType == nil {
		byType = make(map[uint16][]authoritativeRecord)
		zone.records[owner] = byType
	}
	compiledRecord := authoritativeRecord{record: rr, expiresAt: expiresAt}
	byType[rr.Header().Rrtype] = append(byType[rr.Header().Rrtype], compiledRecord)
	zone.owners[owner] = struct{}{}
	for ancestor := owner; ancestor != zone.name; {
		separator := strings.IndexByte(ancestor, '.')
		if separator < 0 {
			break
		}
		ancestor = ancestor[separator+1:]
		zone.owners[ancestor] = struct{}{}
	}
	switch rr.Header().Rrtype {
	case dns.TypeSOA:
		if owner == zone.name {
			zone.soa = append(zone.soa, compiledRecord)
		}
	case dns.TypeNSEC:
		zone.nsecs = append(zone.nsecs, compiledRecord)
	case dns.TypeNSEC3:
		zone.nsec3s = append(zone.nsec3s, compiledRecord)
	}
}

// withZones returns a copy of base serving zones, with keys available for
// zone TSIG. base, and everything it shares with queries already running, is
// left untouched; a changed set of zone-derived DNSSEC exceptions gets a new
// validator rather than a change to the shared one.
func withZones(base *Runtime, zones []AuthoritativeZone, keys []TSIGKey) (*Runtime, error) {
	compiled, err := Compile(RuntimeConfig{
		Mode:       base.mode,
		Forwarders: append([]string(nil), base.forwarders...),
		RootHints:  append([]string(nil), base.rootHints...),
		Routes:     cloneForwardingRoutes(base.baseRoutes),
		Timeout:    base.timeout,
		CacheSize:  base.cache.Capacity(),
		Zones:      zones,
		TSIGKeys:   keys,
	})
	if err != nil {
		return nil, err
	}
	candidate := *base
	candidate.routes = compiled.routes
	candidate.zones = compiled.zones
	candidate.managedZones = compiled.managedZones
	candidate.tsigKeys = compiled.tsigKeys
	candidate.zoneCount = compiled.zoneCount
	candidate.zoneInsecure = compiled.zoneInsecure
	candidate.zoneSource = zones
	candidate.keySource = keys
	routesChanged := !forwardingRouteMapsEqual(base.routes, candidate.routes)
	zoneInsecureChanged := !slices.Equal(base.zoneInsecure, candidate.zoneInsecure)
	if zoneInsecureChanged && base.dnssec != nil {
		candidate.dnssec = base.dnssec.withZoneInsecure(compiled.zoneInsecure)
	}
	if routesChanged || zoneInsecureChanged {
		candidate.upstreams = base.upstreams + "|zone-routes=" + upstreamSignature(nil, candidate.routes) +
			"|zone-insecure=" + strings.Join(candidate.zoneInsecure, ",")
		// Zone-derived routes and DNSSEC policy change the meaning of recursive
		// answers. Do not reuse the active cache, since an in-flight resolver can
		// still publish into it after this runtime is activated.
		candidate.cache = NewResponseCacheWithOptions(base.cache.Capacity(), base.cache.options)
		candidate.delegations = compiled.delegations
		candidate.zoneCuts = compiled.zoneCuts
		candidate.nameServers = compiled.nameServers
	}
	return &candidate, nil
}

func forwardingRouteMapsEqual(left, right map[string][]string) bool {
	if len(left) != len(right) {
		return false
	}
	for domain, leftForwarders := range left {
		if !slices.Equal(leftForwarders, right[domain]) {
			return false
		}
	}
	return true
}

func cloneForwardingRoutes(routes []ForwardingRoute) []ForwardingRoute {
	cloned := make([]ForwardingRoute, len(routes))
	for index, route := range routes {
		cloned[index] = route
		cloned[index].Forwarders = append([]string(nil), route.Forwarders...)
	}
	return cloned
}

// Defaults applied by Compile when a RuntimeConfig leaves the retry settings at
// their zero value (for example a hand-built config in a test).
const (
	defaultRuntimeRetries      = 2
	defaultRuntimeRetryTimeout = 1500 * time.Millisecond
)

func dnssecRuntimeSignature(configuration RuntimeConfig) string {
	return fmt.Sprintf("|dnssec=%t|rfc5011=%t|anchors=%s|negative=%s", configuration.DNSSECValidation, configuration.DNSSECTrustAnchorUpdates,
		strings.Join(configuration.DNSSECTrustAnchors, "\x00"), strings.Join(configuration.DNSSECNegativeTrustAnchors, "\x00"))
}

func upstreamSignature(forwarders []string, routes map[string][]string) string {
	var signature strings.Builder
	for _, forwarder := range forwarders {
		signature.WriteString(forwarder)
		signature.WriteByte(0)
	}
	domains := make([]string, 0, len(routes))
	for domain := range routes {
		domains = append(domains, domain)
	}
	slices.Sort(domains)
	for _, domain := range domains {
		signature.WriteString(domain)
		signature.WriteByte(1)
		for _, forwarder := range routes[domain] {
			signature.WriteString(forwarder)
			signature.WriteByte(0)
		}
	}
	return signature.String()
}
