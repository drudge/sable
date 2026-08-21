package main

import (
	"context"
	"fmt"
	"math"
	"math/rand"
	"time"

	"github.com/drudge/sable/internal/querylog"
	"github.com/drudge/sable/internal/store"
)

const (
	// The dashboard reads the newest thousand query events, so a slightly
	// larger sample guarantees a full set of rankings.
	seededQueryEvents = 1_400
	seededQueryWindow = 75 * time.Minute
	// Chart history reaches back far enough for the Month range to be drawn.
	chartHistoryLength = 30 * 24 * time.Hour
	// Buckets run slightly past the present so the newest slot on the live
	// chart is filled rather than falling off a cliff while the demo server
	// itself answers nothing.
	chartHistoryLead = 20 * time.Minute
	// Peak business hour, and how sharply traffic falls away from it.
	trafficPeakHour   = 13.0
	trafficPeakSpread = 30.0
)

// seedTraffic fills the query log and the chart history. It runs before the
// node starts, because the console adopts the stored lifetime totals as its
// baseline at startup and would otherwise overwrite them on its first flush.
func seedTraffic(ctx context.Context, dsn string) error {
	backing, err := store.Open(ctx, "sqlite", dsn)
	if err != nil {
		return fmt.Errorf("open demo database: %w", err)
	}
	defer backing.Close()

	random := rand.New(rand.NewSource(20260820))
	now := time.Now().Truncate(time.Second)
	if err := backing.WriteQueryEvents(ctx, seedQueryEvents(random, now)); err != nil {
		return fmt.Errorf("write demo query events: %w", err)
	}
	buckets, totals := seedChartHistory(random, now)
	if err := backing.RecordQueryStats(ctx, buckets, totals); err != nil {
		return fmt.Errorf("write demo chart history: %w", err)
	}
	fmt.Printf("seeded %d query events and %d chart buckets (%d lifetime queries)\n",
		seededQueryEvents, len(buckets), totals.Queries)
	return nil
}

func seedQueryEvents(random *rand.Rand, now time.Time) []querylog.Event {
	clients := newWeightedClients(queryClients)
	resolved := newWeightedDomains(resolvedDomains)
	local := newWeightedDomains(localDomains)
	blocked := newWeightedDomains(blockedTraffic)

	events := make([]querylog.Event, 0, seededQueryEvents)
	for range seededQueryEvents {
		at := now.Add(-time.Duration(random.Int63n(int64(seededQueryWindow))))
		var domain queryDomain
		switch roll := random.Intn(100); {
		case roll < 16:
			domain = blocked.pick(random)
		case roll < 34:
			domain = local.pick(random)
		default:
			domain = resolved.pick(random)
		}
		events = append(events, seedQueryEvent(random, at, clients.pick(random), domain))
	}
	return events
}

func seedQueryEvent(random *rand.Rand, at time.Time, client clientWeight, domain queryDomain) querylog.Event {
	responseCode, answer, duration := 0, "", time.Duration(0)
	switch domain.source {
	case querylog.SourceBlocked:
		responseCode = 3
		duration = microseconds(random, 120, 400)
	case querylog.SourceAuthoritative:
		answer = fmt.Sprintf("10.20.%d.%d", 10+10*random.Intn(3), 11+random.Intn(40))
		duration = microseconds(random, 200, 900)
	case querylog.SourceCache:
		answer = fmt.Sprintf("104.18.%d.%d", random.Intn(60), random.Intn(255))
		duration = microseconds(random, 90, 500)
	default:
		answer = fmt.Sprintf("151.101.%d.%d", random.Intn(80), random.Intn(255))
		duration = microseconds(random, 8_000, 52_000)
		// A small share of upstream lookups genuinely do not exist.
		if random.Intn(100) < 3 {
			responseCode, answer = 3, ""
		}
	}
	return querylog.Event{
		OccurredAt: at, ClientIP: client.address, Name: domain.name + ".",
		RecordType: seedRecordType(random), Class: 1, ResponseCode: responseCode,
		Source: domain.source, Protocol: seedProtocol(random), Answer: answer, Duration: duration,
	}
}

func microseconds(random *rand.Rand, low, high int) time.Duration {
	return time.Duration(low+random.Intn(high-low)) * time.Microsecond
}

// seedRecordType mirrors the mix a browser-heavy office produces: mostly A and
// AAAA, with a tail of HTTPS, TXT, MX, and PTR.
func seedRecordType(random *rand.Rand) uint16 {
	switch roll := random.Intn(100); {
	case roll < 62:
		return 1
	case roll < 88:
		return 28
	case roll < 93:
		return 65
	case roll < 96:
		return 16
	case roll < 98:
		return 15
	default:
		return 12
	}
}

func seedProtocol(random *rand.Rand) string {
	switch roll := random.Intn(100); {
	case roll < 8:
		return "tcp"
	case roll < 14:
		return "dot"
	case roll < 18:
		return "doh"
	default:
		return "udp"
	}
}

// seedChartHistory writes one bucket per minute across the charted history and
// the lifetime totals those buckets add up to.
func seedChartHistory(random *rand.Rand, now time.Time) ([]store.QueryStatsBucket, store.QueryStatsTotals) {
	start := now.Add(-chartHistoryLength).Truncate(time.Minute)
	end := now.Add(chartHistoryLead)
	buckets := make([]store.QueryStatsBucket, 0, int(chartHistoryLength/time.Minute))
	totals := store.QueryStatsTotals{}
	for at := start; at.Before(end); at = at.Add(time.Minute) {
		rate := businessHourShape(at) * 46
		queries := uint64(math.Max(0, rate+random.NormFloat64()*rate*0.22))
		if queries == 0 {
			continue
		}
		blocked := uint64(float64(queries) * (0.13 + random.Float64()*0.06))
		nxDomain := blocked + uint64(float64(queries)*random.Float64()*0.015)
		serverFailures := uint64(0)
		if random.Intn(14) == 0 {
			serverFailures = uint64(random.Intn(3))
		}
		refused := uint64(0)
		if random.Intn(40) == 0 {
			refused = 1
		}
		cacheHits := uint64(float64(queries) * (0.58 + random.Float64()*0.14))
		delta := store.QueryStatsDelta{
			Queries:        queries,
			NoError:        saturatingSub(queries, nxDomain+serverFailures+refused),
			ServerFailures: serverFailures,
			NXDomain:       nxDomain,
			Refused:        refused,
			Blocked:        blocked,
			CacheHits:      cacheHits,
			CacheMisses:    saturatingSub(queries, blocked+cacheHits),
		}
		buckets = append(buckets, store.QueryStatsBucket{Start: at.UTC(), QueryStatsDelta: delta})
		addDelta(&totals, delta)
	}
	completeTotals(&totals)
	return buckets, totals
}

// businessHourShape returns the share of peak traffic a moment in the week
// carries, so the chart reads like an office rather than a flat line.
func businessHourShape(at time.Time) float64 {
	hour := float64(at.Hour()) + float64(at.Minute())/60
	share := 0.34 + 0.66*math.Exp(-math.Pow(hour-trafficPeakHour, 2)/trafficPeakSpread)
	if hour < 6 {
		share = 0.16
	}
	if weekday := at.Weekday(); weekday == time.Saturday || weekday == time.Sunday {
		share *= 0.28
	}
	return share
}

func addDelta(totals *store.QueryStatsTotals, delta store.QueryStatsDelta) {
	totals.Queries += delta.Queries
	totals.NoError += delta.NoError
	totals.ServerFailures += delta.ServerFailures
	totals.NXDomain += delta.NXDomain
	totals.Refused += delta.Refused
	totals.Blocked += delta.Blocked
	totals.CacheHits += delta.CacheHits
	totals.CacheMisses += delta.CacheMisses
}

// completeTotals derives the counters the chart does not bucket but the stat
// cards still show, keeping them in proportion to the charted traffic.
func completeTotals(totals *store.QueryStatsTotals) {
	totals.Failures = totals.ServerFailures
	totals.UpstreamErrors = totals.ServerFailures + totals.Queries/900
	totals.RoutedQueries = totals.Queries / 26
	totals.LocalAnswers = totals.Queries / 18
	totals.AuthoritativeAnswers = uint64(float64(totals.Queries) * 0.17)
	totals.DNSSECSecure = uint64(float64(totals.CacheMisses) * 0.41)
	totals.DNSSECInsecure = uint64(float64(totals.CacheMisses) * 0.58)
	totals.DNSSECBogus = totals.CacheMisses / 700
}

// saturatingSub keeps a thin bucket from wrapping an unsigned counter around.
func saturatingSub(value, subtract uint64) uint64 {
	if subtract >= value {
		return 0
	}
	return value - subtract
}

// weighted draws from a fixture in proportion to each entry's weight.
type weighted[T any] struct {
	items      []T
	cumulative []int
	total      int
}

func newWeighted[T any](items []T, weight func(T) int) *weighted[T] {
	table := &weighted[T]{items: items}
	for _, item := range items {
		table.total += weight(item)
		table.cumulative = append(table.cumulative, table.total)
	}
	return table
}

func newWeightedClients(items []clientWeight) *weighted[clientWeight] {
	return newWeighted(items, func(item clientWeight) int { return item.weight })
}

func newWeightedDomains(items []queryDomain) *weighted[queryDomain] {
	return newWeighted(items, func(item queryDomain) int { return item.weight })
}

func (table *weighted[T]) pick(random *rand.Rand) T {
	target := random.Intn(table.total)
	for index, boundary := range table.cumulative {
		if target < boundary {
			return table.items[index]
		}
	}
	return table.items[len(table.items)-1]
}
