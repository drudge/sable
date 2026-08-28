package dnsserver

import (
	"strings"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"

	"github.com/drudge/sable/internal/querylog"
)

const (
	dnsLatencySourceCache = iota
	dnsLatencySourceBlocked
	dnsLatencySourceLocal
	dnsLatencySourceAuthoritative
	dnsLatencySourceUpstream
	dnsLatencySourceError
	dnsLatencySourceControl
	dnsLatencySourceOther
	dnsLatencySourceCount
)

const (
	dnsLatencyCacheNone = iota
	dnsLatencyCacheHit
	dnsLatencyCacheMiss
	dnsLatencyCacheStale
	dnsLatencyCacheOther
	dnsLatencyCacheCount
)

const (
	dnsLatencyRCodeNoError = iota
	dnsLatencyRCodeFormatError
	dnsLatencyRCodeServerFailure
	dnsLatencyRCodeNameError
	dnsLatencyRCodeNotImplemented
	dnsLatencyRCodeRefused
	dnsLatencyRCodeOther
	dnsLatencyRCodeCount
)

const (
	dnsLatencyProtocolUDP = iota
	dnsLatencyProtocolTCP
	dnsLatencyProtocolHTTPS
	dnsLatencyProtocolQUIC
	dnsLatencyProtocolOther
	dnsLatencyProtocolCount
)

var dnsLatencyBucketBounds = [...]time.Duration{
	100 * time.Microsecond,
	250 * time.Microsecond,
	500 * time.Microsecond,
	time.Millisecond,
	2500 * time.Microsecond,
	5 * time.Millisecond,
	10 * time.Millisecond,
	25 * time.Millisecond,
	50 * time.Millisecond,
	100 * time.Millisecond,
	250 * time.Millisecond,
	500 * time.Millisecond,
	time.Second,
	2 * time.Second,
}

const dnsLatencyBucketCount = len(dnsLatencyBucketBounds) + 1

type DNSLatencyBucket struct {
	UpperBoundNanoseconds uint64 `json:"upper_bound_ns"`
	Count                 uint64 `json:"count"`
}

type DNSLatencyHistogram struct {
	Source         string             `json:"source"`
	Protocol       string             `json:"protocol"`
	Cache          string             `json:"cache"`
	ResponseCode   string             `json:"response_code"`
	Count          uint64             `json:"count"`
	SumNanoseconds uint64             `json:"sum_ns"`
	Buckets        []DNSLatencyBucket `json:"buckets"`
}

type dnsLatencyHistogram struct {
	buckets [dnsLatencyBucketCount]atomic.Uint64
	count   atomic.Uint64
	sum     atomic.Uint64
}

type dnsLatencyHistograms struct {
	values [dnsLatencySourceCount][dnsLatencyProtocolCount][dnsLatencyCacheCount][dnsLatencyRCodeCount]dnsLatencyHistogram
}

func (histograms *dnsLatencyHistograms) observe(
	source querylog.Source,
	protocol string,
	cache querylog.CacheDecision,
	responseCode int,
	duration time.Duration,
) {
	if duration < 0 {
		duration = 0
	}
	histogram := &histograms.values[dnsLatencySourceIndex(source)][dnsLatencyProtocolIndex(protocol)][dnsLatencyCacheIndex(cache)][dnsLatencyRCodeIndex(responseCode)]
	bucket := len(dnsLatencyBucketBounds)
	for index, bound := range dnsLatencyBucketBounds {
		if duration <= bound {
			bucket = index
			break
		}
	}
	histogram.buckets[bucket].Add(1)
	histogram.count.Add(1)
	histogram.sum.Add(uint64(duration))
}

func (histograms *dnsLatencyHistograms) snapshot() []DNSLatencyHistogram {
	result := make([]DNSLatencyHistogram, 0)
	for source := 0; source < dnsLatencySourceCount; source++ {
		for protocol := 0; protocol < dnsLatencyProtocolCount; protocol++ {
			for cache := 0; cache < dnsLatencyCacheCount; cache++ {
				for responseCode := 0; responseCode < dnsLatencyRCodeCount; responseCode++ {
					histogram := &histograms.values[source][protocol][cache][responseCode]
					count := histogram.count.Load()
					if count == 0 {
						continue
					}
					buckets := make([]DNSLatencyBucket, len(dnsLatencyBucketBounds))
					var cumulative uint64
					for index, bound := range dnsLatencyBucketBounds {
						cumulative += histogram.buckets[index].Load()
						buckets[index] = DNSLatencyBucket{UpperBoundNanoseconds: uint64(bound), Count: cumulative}
					}
					result = append(result, DNSLatencyHistogram{
						Source: dnsLatencySourceName(source), Protocol: dnsLatencyProtocolName(protocol),
						Cache: dnsLatencyCacheName(cache), ResponseCode: dnsLatencyRCodeName(responseCode),
						Count: count, SumNanoseconds: histogram.sum.Load(), Buckets: buckets,
					})
				}
			}
		}
	}
	return result
}

func dnsLatencySourceIndex(source querylog.Source) int {
	switch source {
	case querylog.SourceCache:
		return dnsLatencySourceCache
	case querylog.SourceBlocked:
		return dnsLatencySourceBlocked
	case querylog.SourceLocal:
		return dnsLatencySourceLocal
	case querylog.SourceAuthoritative:
		return dnsLatencySourceAuthoritative
	case querylog.SourceUpstream:
		return dnsLatencySourceUpstream
	case querylog.SourceError:
		return dnsLatencySourceError
	case querylog.Source("control"):
		return dnsLatencySourceControl
	default:
		return dnsLatencySourceOther
	}
}

func dnsLatencySourceName(index int) string {
	return [...]string{"cache", "blocked", "local", "authoritative", "upstream", "error", "control", "other"}[index]
}

func dnsLatencyProtocolIndex(protocol string) int {
	switch strings.ToUpper(protocol) {
	case "UDP":
		return dnsLatencyProtocolUDP
	case "TCP", "TLS":
		return dnsLatencyProtocolTCP
	case "HTTPS":
		return dnsLatencyProtocolHTTPS
	case "QUIC":
		return dnsLatencyProtocolQUIC
	default:
		return dnsLatencyProtocolOther
	}
}

func dnsLatencyProtocolName(index int) string {
	return [...]string{"udp", "tcp", "https", "quic", "other"}[index]
}

func dnsLatencyCacheIndex(cache querylog.CacheDecision) int {
	switch cache {
	case "":
		return dnsLatencyCacheNone
	case querylog.CacheHit:
		return dnsLatencyCacheHit
	case querylog.CacheMiss:
		return dnsLatencyCacheMiss
	case querylog.CacheStale:
		return dnsLatencyCacheStale
	default:
		return dnsLatencyCacheOther
	}
}

func dnsLatencyCacheName(index int) string {
	return [...]string{"none", "hit", "miss", "stale", "other"}[index]
}

func dnsLatencyRCodeIndex(responseCode int) int {
	switch responseCode {
	case dns.RcodeSuccess:
		return dnsLatencyRCodeNoError
	case dns.RcodeFormatError:
		return dnsLatencyRCodeFormatError
	case dns.RcodeServerFailure:
		return dnsLatencyRCodeServerFailure
	case dns.RcodeNameError:
		return dnsLatencyRCodeNameError
	case dns.RcodeNotImplemented:
		return dnsLatencyRCodeNotImplemented
	case dns.RcodeRefused:
		return dnsLatencyRCodeRefused
	default:
		return dnsLatencyRCodeOther
	}
}

func dnsLatencyRCodeName(index int) string {
	return [...]string{"NOERROR", "FORMERR", "SERVFAIL", "NXDOMAIN", "NOTIMP", "REFUSED", "OTHER"}[index]
}
