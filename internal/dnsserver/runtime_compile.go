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

func Compile(configuration RuntimeConfig) (*Runtime, error) {
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
		var err error
		validator, err = newDNSSECValidator(configuration.DNSSECTrustAnchors, configuration.DNSSECNegativeTrustAnchors)
		if err != nil {
			return nil, fmt.Errorf("compile DNSSEC validator: %w", err)
		}
	}
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
			return nil, fmt.Errorf("invalid blocked domain %q: %w", domain, err)
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
			return nil, fmt.Errorf("invalid allowed domain %q: %w", domain, err)
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
		return nil, fmt.Errorf("invalid blocking response type %q", configuration.BlockingType)
	}
	blockAddresses := make([]netip.Addr, 0, len(configuration.BlockingAddrs)+2)
	if blockingType == "zero" {
		blockAddresses = append(blockAddresses, netip.IPv4Unspecified(), netip.IPv6Unspecified())
	} else if blockingType == "custom" {
		for _, value := range configuration.BlockingAddrs {
			address, err := netip.ParseAddr(value)
			if err != nil || address.Zone() != "" {
				return nil, fmt.Errorf("invalid custom blocking address %q", value)
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
				return nil, fmt.Errorf("invalid blocking bypass client %q", value)
			}
			prefix = netip.PrefixFrom(address.Unmap(), address.Unmap().BitLen())
		}
		bypass = append(bypass, prefix.Masked())
	}
	routes := make(map[string][]string, len(configuration.Routes))
	for _, route := range configuration.Routes {
		domain, err := dnsname.Normalize(route.Domain)
		if err != nil || len(route.Forwarders) == 0 {
			return nil, fmt.Errorf("conditional forwarding route %q is invalid", route.Domain)
		}
		if _, duplicate := routes[domain]; duplicate {
			return nil, fmt.Errorf("duplicate conditional forwarding route %q", route.Domain)
		}
		routes[domain] = append([]string(nil), route.Forwarders...)
	}
	hosts := make(map[string]localHostRecords, len(configuration.Hosts))
	for _, host := range configuration.Hosts {
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
	zones := make(map[string]*authoritativeZone, len(configuration.Zones))
	managedZones := make(map[string]managedZone)
	tsigKeys := make(map[string]tsigKey, len(configuration.TSIGKeys))
	for _, key := range configuration.TSIGKeys {
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
	zoneCount := 0
	zoneInsecure := make([]string, 0)
	for _, configuredZone := range configuration.Zones {
		if configuredZone.Disabled || configuredZone.AwaitingTransfer {
			continue
		}
		zoneCount++
		zoneName, err := dnsname.Normalize(configuredZone.Name)
		if err != nil || len(configuredZone.Records) == 0 {
			return nil, fmt.Errorf("authoritative zone %q is invalid", configuredZone.Name)
		}
		if _, duplicate := zones[zoneName]; duplicate {
			return nil, fmt.Errorf("duplicate authoritative zone %q", configuredZone.Name)
		}
		zoneType := strings.ToLower(strings.TrimSpace(configuredZone.Type))
		if zoneType == "" {
			zoneType = "primary"
		}
		if configuredZone.DNSSECValidationDisabled {
			if !zonemodel.IsForwarderType(zoneType) && zoneType != "stub" {
				return nil, fmt.Errorf("authoritative zone %q may not disable DNSSEC validation for a %s zone", zoneName, zoneType)
			}
			zoneInsecure = append(zoneInsecure, zoneName)
		}
		zoneTSIGKey := ""
		if strings.TrimSpace(configuredZone.TSIGKey) != "" {
			zoneTSIGKey = strings.ToLower(dns.Fqdn(strings.TrimSpace(configuredZone.TSIGKey)))
			if _, found := tsigKeys[zoneTSIGKey]; !found {
				return nil, fmt.Errorf("authoritative zone %q references unknown TSIG key %q", zoneName, zoneTSIGKey)
			}
		}
		if zoneType == "stub" {
			managedZones[zoneName] = managedZone{kind: zoneType, primaries: append([]string(nil), configuredZone.PrimaryServers...), tsigKey: zoneTSIGKey}
			if _, duplicate := routes[zoneName]; duplicate {
				return nil, fmt.Errorf("stub zone %q duplicates a forwarding route", zoneName)
			}
			protocol := configuredZone.PrimaryProtocol
			if protocol == "" {
				protocol = "udp"
			}
			for _, primary := range configuredZone.PrimaryServers {
				routes[zoneName] = append(routes[zoneName], protocol+"://"+primary)
			}
			if len(routes[zoneName]) == 0 {
				return nil, fmt.Errorf("stub zone %q requires at least one primary server", zoneName)
			}
			continue
		}
		// A catalog zone with primary servers is transferred exactly like a
		// secondary. It is compiled into the zone map either way so that a
		// published catalog can be served over AXFR/IXFR and journaled for
		// incremental transfers.
		if zoneType == "secondary" || zoneType == zonemodel.TypeSecondaryForwarder || (zoneType == "catalog" && len(configuredZone.PrimaryServers) > 0) {
			managedZones[zoneName] = managedZone{kind: zoneType, primaries: append([]string(nil), configuredZone.PrimaryServers...), tsigKey: zoneTSIGKey}
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
					return nil, fmt.Errorf("authoritative zone %q transfer ACL %q is invalid", zoneName, rawPrefix)
				}
				prefix = netip.PrefixFrom(address, address.BitLen())
			}
			zone.transferACL = append(zone.transferACL, prefix)
		}
		hasDNSKEY, hasRRSIG := false, false
		for _, record := range configuredZone.Records {
			if record.Disabled || (!record.ExpiresAt.IsZero() && !record.ExpiresAt.After(time.Now())) {
				continue
			}
			owner, err := authoritativeOwner(zoneName, record.Name)
			if err != nil {
				return nil, fmt.Errorf("authoritative zone %q record owner %q: %w", zoneName, record.Name, err)
			}
			recordType := strings.ToUpper(strings.TrimSpace(record.Type))
			if recordType == "ANAME" {
				target, normalizeErr := dnsname.Normalize(record.Value)
				if normalizeErr != nil {
					return nil, fmt.Errorf("compile authoritative zone %q ANAME record: %w", zoneName, normalizeErr)
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
					return nil, fmt.Errorf("compile authoritative zone %q FWD record: %w", zoneName, parseErr)
				}
				zone.forwarders[owner] = append(zone.forwarders[owner], authoritativeForwarder{
					priority: forwarder.Priority, endpoint: forwarder.Endpoint(),
				})
				zone.owners[owner] = struct{}{}
				continue
			}
			if _, found := dns.StringToType[recordType]; !found {
				return nil, fmt.Errorf("authoritative zone %q has unsupported record type %q", zoneName, record.Type)
			}
			rr, err := dns.NewRR(fmt.Sprintf("%s %d IN %s %s", dns.Fqdn(owner), record.TTL, recordType, record.Value))
			if err != nil {
				return nil, fmt.Errorf("compile authoritative zone %q record: %w", zoneName, err)
			}
			if owner != zoneName && !strings.HasSuffix(owner, "."+zoneName) {
				return nil, fmt.Errorf("authoritative record owner %q is outside zone %q", owner, zoneName)
			}
			byType := zone.records[owner]
			if byType == nil {
				byType = make(map[uint16][]authoritativeRecord)
				zone.records[owner] = byType
			}
			compiledRecord := authoritativeRecord{record: rr, expiresAt: record.ExpiresAt}
			byType[rr.Header().Rrtype] = append(byType[rr.Header().Rrtype], compiledRecord)
			zone.owners[owner] = struct{}{}
			for ancestor := owner; ancestor != zoneName; {
				separator := strings.IndexByte(ancestor, '.')
				if separator < 0 {
					break
				}
				ancestor = ancestor[separator+1:]
				zone.owners[ancestor] = struct{}{}
			}
			if owner == zoneName && rr.Header().Rrtype == dns.TypeSOA {
				zone.soa = append(zone.soa, compiledRecord)
			}
			if rr.Header().Rrtype == dns.TypeNSEC {
				zone.nsecs = append(zone.nsecs, compiledRecord)
			}
			if rr.Header().Rrtype == dns.TypeNSEC3 {
				zone.nsec3s = append(zone.nsec3s, compiledRecord)
			}
			if rr.Header().Rrtype == dns.TypeDNSKEY {
				hasDNSKEY = true
			}
			if rr.Header().Rrtype == dns.TypeRRSIG {
				hasRRSIG = true
			}
		}
		zone.signed = hasDNSKEY && hasRRSIG
		if len(zone.soa) != 1 || (!zonemodel.IsForwarderType(zoneType) && len(zone.records[zoneName][dns.TypeNS]) == 0) {
			return nil, fmt.Errorf("authoritative zone %q has invalid authority records", zoneName)
		}
		if zonemodel.IsForwarderType(zoneType) && len(zone.forwarders[zoneName]) == 0 {
			return nil, fmt.Errorf("forwarder zone %q requires an active apex FWD record", zoneName)
		}
		for owner, ordered := range zone.forwarders {
			slices.SortFunc(ordered, func(left, right authoritativeForwarder) int {
				return int(left.priority) - int(right.priority)
			})
			if _, duplicate := routes[owner]; duplicate {
				return nil, fmt.Errorf("authoritative zone %q FWD owner duplicates forwarding route %q", zoneName, owner)
			}
			endpoints := make([]string, 0, len(ordered))
			for _, forwarder := range ordered {
				endpoints = append(endpoints, forwarder.endpoint)
			}
			routes[owner] = endpoints
			zone.forwarders[owner] = ordered
		}
		zones[zoneName] = zone
	}
	slices.Sort(zoneInsecure)
	if validator != nil {
		validator.setZoneInsecure(zoneInsecure)
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
		routes:            routes,
		upstreams:         upstreamSignature(configuration.Forwarders, routes) + "|mode=" + mode + "|roots=" + strings.Join(rootHints, ",") + dnssecRuntimeSignature(configuration),
		timeout:           configuration.Timeout,
		retries:           cmp.Or(configuration.Retries, defaultRuntimeRetries),
		retryTimeout:      cmp.Or(configuration.RetryTimeout, defaultRuntimeRetryTimeout),
		staleMaxWait:      configuration.CacheStaleMaxWait,
		blocked:           blocked,
		blockedOwners:     configuration.BlockedDomainOwnerSets,
		allowedExact:      allowedExact,
		allowedWildcard:   allowedWildcard,
		blocking:          configuration.Blocking,
		blockType:         blockingType,
		blockTTL:          configuration.BlockingTTL,
		blockAddrs:        blockAddresses,
		bypass:            bypass,
		blockTXT:          configuration.AllowTXTReport,
		cache: NewResponseCacheWithOptions(configuration.CacheSize, CacheOptions{
			MinimumTTL: configuration.CacheMinimumTTL, MaximumTTL: configuration.CacheMaximumTTL,
			NegativeTTL: configuration.CacheNegativeTTL, FailureTTL: configuration.CacheFailureTTL,
			ServeStale: configuration.ServeStale, StaleTTL: configuration.CacheStaleTTL,
			StaleAnswerTTL: configuration.CacheStaleAnswerTTL, StaleResetTTL: configuration.CacheStaleResetTTL,
			PrefetchMinTTL: configuration.CachePrefetchMinimumTTL, PrefetchAtTTL: configuration.CachePrefetchTriggerTTL,
			PrefetchSample: configuration.CachePrefetchSample, PrefetchHits: configuration.CachePrefetchHitsPerHour,
		}),
		blockLists:          append([]BlockListStats(nil), configuration.BlockLists...),
		hosts:               hosts,
		zones:               zones,
		managedZones:        managedZones,
		tsigKeys:            tsigKeys,
		zoneCount:           zoneCount,
		dnssec:              validator,
		zoneInsecure:        zoneInsecure,
		managedTrustAnchors: configuration.DNSSECValidation && configuration.DNSSECTrustAnchorUpdates && len(configuration.DNSSECTrustAnchors) == 0,
		zoneSource:          configuration.Zones,
		keySource:           configuration.TSIGKeys,
	}, nil
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
