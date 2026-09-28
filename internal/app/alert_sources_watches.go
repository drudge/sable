package app

import (
	"cmp"
	"context"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/drudge/sable/internal/alerts"
	"github.com/drudge/sable/internal/config"
	"github.com/drudge/sable/internal/insights/devices"
	"github.com/drudge/sable/internal/querylog"
)

// Domain watches alert when a device looks up a domain someone picked. Every
// node reads its own query log once a minute for new lookups of watched
// names. A replica hands what it saw to the lead in its heartbeat, and the
// lead weighs every node's lookups together, one quiet window per watch and
// device, so a device that asks both nodes still alerts once.

const (
	// watchReadLimit bounds one reading of the query log. A busier minute
	// leaves the rest for the next reading, which starts where this one ended.
	watchReadLimit = 5_000
	// watchHitKeep is how long a replica keeps handing the lead a hit. The
	// lead trusts a replica's list for three minutes, so a hit outlives a
	// heartbeat or two that went missing.
	watchHitKeep = 3 * time.Minute
	// watchRestartAfter is how long a node can go without reading before it
	// starts again from the newest row rather than catching up. It stopped
	// watching meanwhile, as when alerts had nowhere to go, and what it
	// missed is old news.
	watchRestartAfter = 3 * time.Minute
	// watchIdentityRefresh is how long the lead keeps the hardware addresses
	// it ties clients to devices with.
	watchIdentityRefresh = 5 * time.Minute
	// watchNamesShown is how many looked-up names an alert lists.
	watchNamesShown = 3
	// watchHitKind marks a replica's hits in its report to the lead.
	watchHitKind   = "watches.hit"
	watchAlertKind = "watches.lookup"
)

// watchLookupReader is the part of the database domain watches read.
type watchLookupReader interface {
	LatestQueryID(context.Context) (int64, error)
	WatchedLookups(ctx context.Context, after int64, domains []string, limit int) ([]querylog.WatchedLookup, int64, error)
	ClientIdentities(ctx context.Context, since time.Time) ([]querylog.ClientIdentity, error)
}

// watchSource reads this node's query log for watched domains. On the lead it
// is the source of watch alerts; on a replica, see replicaHits.
type watchSource struct {
	reader        watchLookupReader
	configuration func() config.Config
	node          func() alertNode
	// leading reports whether this node leads the cluster, or runs alone.
	leading func() bool
	// reported returns what the replicas last reported; the lead picks out
	// their watch hits.
	reported func(time.Time) []alerts.Alert

	mu sync.Mutex
	// cursor is the last query log row read, once reading has started.
	cursor   int64
	started  bool
	readAt   time.Time
	recent   []watchReading
	windows  map[string]watchWindow
	lastSent map[string]time.Time
	given    devices.GivenNames
	givenAt  time.Time
}

// watchReading is a hit this node saw, with when it read it.
type watchReading struct {
	id     string
	hit    alerts.WatchHit
	readAt time.Time
}

// watchWindow is one watch's quiet time for one device, which began with the
// alert it carries.
type watchWindow struct {
	end   time.Time
	alert alerts.Alert
}

func newWatchSource(reader watchLookupReader, configuration func() config.Config, node func() alertNode, leading func() bool, reported func(time.Time) []alerts.Alert) *watchSource {
	return &watchSource{
		reader: reader, configuration: configuration, node: node, leading: leading, reported: reported,
		windows: make(map[string]watchWindow), lastSent: make(map[string]time.Time),
	}
}

// alertSources returns the lead's source of watch alerts and every node's
// source of hits to hand the lead.
func (source *watchSource) alertSources() []alerts.Source {
	return []alerts.Source{source, alerts.Place(watchReplicaHits{source}, alerts.OnEachNode)}
}

// LastAlert returns when each watch last alerted, by ID, as this node knows:
// only the lead alerts, and it forgets when it restarts.
func (source *watchSource) LastAlert() map[string]time.Time {
	source.mu.Lock()
	defer source.mu.Unlock()
	last := make(map[string]time.Time, len(source.lastSent))
	for id, at := range source.lastSent {
		last[id] = at
	}
	return last
}

// watchReplicaHits hands a replica's hits to the lead. It runs on every node
// so the dispatcher gathers it for the heartbeat, and says nothing on the
// lead, which reads its own hits as the watch source.
type watchReplicaHits struct{ source *watchSource }

func (hits watchReplicaHits) Alerts(ctx context.Context, now time.Time) ([]alerts.Alert, error) {
	if hits.source.leading() {
		return nil, nil
	}
	readings, err := hits.source.read(ctx, now)
	found := make([]alerts.Alert, 0, len(readings))
	for _, reading := range readings {
		hit := reading.hit
		found = append(found, alerts.Alert{
			ID: reading.id, Group: config.AlertGroupWatches, Kind: watchHitKind, ObservedAt: hit.First, Watch: &hit,
		})
	}
	return found, err
}

// Alerts weighs every node's hits and returns an alert for each watch and
// device still in its quiet window.
func (source *watchSource) Alerts(ctx context.Context, now time.Time) ([]alerts.Alert, error) {
	readings, err := source.read(ctx, now)
	if err != nil {
		return nil, err
	}
	hits := make(map[string]alerts.WatchHit, len(readings))
	for _, reading := range readings {
		hits[reading.id] = reading.hit
	}
	if source.reported != nil {
		for _, alert := range source.reported(now) {
			if alert.Kind == watchHitKind && alert.Watch != nil {
				hit := *alert.Watch
				// A replica's rows are in its own log, not this one.
				hit.FirstQuery = 0
				hits[alert.ID] = hit
			}
		}
	}
	watches := source.enabledWatches()
	var given devices.GivenNames
	if len(hits) > 0 && len(watches) > 0 {
		given, err = source.identities(ctx, now)
		if err != nil {
			return nil, err
		}
	}
	source.mu.Lock()
	defer source.mu.Unlock()
	source.open(watches, hits, given, now)
	current := make([]alerts.Alert, 0, len(source.windows))
	for key, window := range source.windows {
		switch {
		case now.Before(window.end):
			current = append(current, window.alert)
		case now.Sub(window.end) >= watchHitKeep:
			// Kept past its end until no replica can still be repeating a
			// hit from inside it, which would open a new window.
			delete(source.windows, key)
		}
	}
	return current, nil
}

// watchCandidate is a device's new lookups for one watch, gathered over
// every node's hits.
type watchCandidate struct {
	watch   config.AlertWatch
	device  string
	name    string
	first   time.Time
	last    time.Time
	count   int
	blocked int
	names   []string
	clients []string
	nodes   []string
	// query is the first lookup this node logged, and queryName the name it
	// looked up, for the alert to link to.
	query     int64
	queryAt   time.Time
	queryName string
}

// open starts a quiet window, with its alert, for each watch and device that
// looked up a watched name since its last window ended. It is called with
// source.mu held.
func (source *watchSource) open(watches []config.AlertWatch, hits map[string]alerts.WatchHit, given devices.GivenNames, now time.Time) {
	byID := make(map[string]config.AlertWatch, len(watches))
	for _, watch := range watches {
		byID[watch.ID] = watch
	}
	ids := make([]string, 0, len(hits))
	for id := range hits {
		ids = append(ids, id)
	}
	slices.Sort(ids)
	candidates := make(map[string]*watchCandidate)
	order := make([]string, 0)
	for _, id := range ids {
		hit := hits[id]
		watch, found := byID[hit.Watch]
		if !found {
			continue
		}
		device := given.Key(hit.Client)
		if !watch.Covers(device, hit.Client) {
			continue
		}
		key := watch.ID + "\x00" + device
		// Lookups inside a window, or before it, are what it alerted about
		// or older still.
		if window, open := source.windows[key]; open && hit.Last.Before(window.end) {
			continue
		}
		candidate, found := candidates[key]
		if !found {
			candidate = &watchCandidate{watch: watch, device: device, name: cmp.Or(given.Address(hit.Client), hit.Client), first: hit.First, last: hit.Last}
			candidates[key] = candidate
			order = append(order, key)
		}
		if window, open := source.windows[key]; open && hit.First.Before(window.end) {
			// Its first lookup belongs to the window before.
			hit.First, hit.FirstQuery = window.end, 0
		}
		if hit.FirstQuery > 0 && len(hit.Names) > 0 && (candidate.query == 0 || hit.First.Before(candidate.queryAt)) {
			candidate.query, candidate.queryAt, candidate.queryName = hit.FirstQuery, hit.First, hit.Names[0]
		}
		candidate.first = minTime(candidate.first, hit.First)
		candidate.last = maxTime(candidate.last, hit.Last)
		candidate.count += hit.Count
		candidate.blocked += hit.Blocked
		for _, name := range hit.Names {
			if !slices.Contains(candidate.names, name) {
				candidate.names = append(candidate.names, name)
			}
		}
		if !slices.Contains(candidate.clients, hit.Client) {
			candidate.clients = append(candidate.clients, hit.Client)
		}
		if hit.Node != "" && !slices.Contains(candidate.nodes, hit.Node) {
			candidate.nodes = append(candidate.nodes, hit.Node)
		}
	}
	clustered := source.node().Clustered
	for _, key := range order {
		candidate := candidates[key]
		source.windows[key] = watchWindow{end: candidate.first.Add(candidate.watch.Quiet.Duration), alert: watchAlert(*candidate, clustered)}
		source.lastSent[candidate.watch.ID] = maxTime(source.lastSent[candidate.watch.ID], now)
	}
}

// watchAlert words a device's lookups for one watch.
func watchAlert(candidate watchCandidate, clustered bool) alerts.Alert {
	slices.Sort(candidate.clients)
	slices.Sort(candidate.nodes)
	named := candidate.names[0]
	if extra := len(candidate.names) - 1; extra > 0 {
		named += " and " + countOf(extra, "other name", "other names")
	}
	headline := candidate.name + " looked up " + named
	summary := headline + "."
	if candidate.count > 1 {
		summary = headline + " " + countOf(candidate.count, "time", "times") + " in " + alertDuration(candidate.last.Sub(candidate.first)) + "."
	}
	var result string
	switch {
	case candidate.blocked == 0:
		result = "Allowed"
	case candidate.blocked == candidate.count:
		result = "Blocked"
	default:
		result = countOf(candidate.blocked, "lookup", "lookups") + " blocked"
	}
	summary += " " + watchResultSentence(candidate.count, candidate.blocked)
	reasons := []string{"Looked up " + listSome(firstNames(candidate.names)), result, "From " + listSome(candidate.clients)}
	if clustered && len(candidate.nodes) > 0 {
		reasons = append(reasons, "Seen by "+listSome(candidate.nodes))
	}
	return alerts.Alert{
		ID:    "watches:" + candidate.watch.ID + ":" + candidate.device + ":" + strconv.FormatInt(candidate.first.Unix(), 10),
		Group: config.AlertGroupWatches, Kind: watchAlertKind, Tone: alerts.ToneAttention,
		Title: candidate.watch.Label(), Subject: candidate.name, Headline: headline, Summary: summary, Reasons: reasons,
		Path: watchLogPath(candidate), PathLabel: "Open in Query Logs",
		ObservedAt: candidate.first,
	}
}

// watchResultSentence says how blocking answered the lookups.
func watchResultSentence(count, blocked int) string {
	switch {
	case blocked == 0 && count == 1:
		return "It was allowed."
	case blocked == 0:
		return "All were allowed."
	case blocked == count && count == 1:
		return "Blocking stopped it."
	case blocked == count:
		return "Blocking stopped all of them."
	case blocked == 1:
		return "1 was blocked."
	default:
		return strconv.Itoa(blocked) + " were blocked."
	}
}

// firstNames keeps an alert's list of names short.
func firstNames(names []string) []string {
	if len(names) <= watchNamesShown {
		return names
	}
	return names[:watchNamesShown]
}

// watchLogPath opens the first lookup this node logged. Lookups only another
// node logged open Query Logs on the client's lookups of the name instead,
// from a minute before the first, since each node keeps its own log.
func watchLogPath(candidate watchCandidate) string {
	if candidate.query > 0 {
		return "/logs/queries/" + strconv.FormatInt(candidate.query, 10) + "?" + url.Values{"name": []string{candidate.queryName}}.Encode()
	}
	client, name, first := candidate.clients[0], candidate.names[0], candidate.first
	values := url.Values{}
	values.Set("tab", "queries")
	values.Set("client_ip", client)
	values.Set("name", name)
	values.Set("match", "exact")
	values.Set("start", first.Add(-time.Minute).UTC().Format(time.RFC3339))
	return "/logs?" + values.Encode()
}

// enabledWatches returns the watches switched on, or none while the query
// log, which they read, is off.
func (source *watchSource) enabledWatches() []config.AlertWatch {
	configuration := source.configuration()
	if !configuration.QueryLog.Enabled {
		return nil
	}
	watches := make([]config.AlertWatch, 0, len(configuration.Alerts.Watches))
	for _, watch := range configuration.Alerts.Watches {
		if watch.Enabled && len(watch.Domains) > 0 {
			watches = append(watches, watch)
		}
	}
	return watches
}

// read reads the query log rows written since the last reading for watched
// names, and returns this node's hits from the last few minutes.
func (source *watchSource) read(ctx context.Context, now time.Time) ([]watchReading, error) {
	watches := source.enabledWatches()
	domains := make([]string, 0)
	for _, watch := range watches {
		for _, domain := range watch.Domains {
			if !slices.Contains(domains, domain) {
				domains = append(domains, domain)
			}
		}
	}
	source.mu.Lock()
	defer source.mu.Unlock()
	source.recent = slices.DeleteFunc(source.recent, func(reading watchReading) bool {
		return now.Sub(reading.readAt) >= watchHitKeep
	})
	if len(domains) == 0 {
		// Nothing is watched, so a watch added later starts from then.
		source.started, source.recent = false, nil
		return nil, nil
	}
	if !source.started || now.Sub(source.readAt) >= watchRestartAfter {
		latest, err := source.reader.LatestQueryID(ctx)
		if err != nil {
			return slices.Clone(source.recent), err
		}
		source.cursor, source.started, source.readAt = latest, true, now
		return slices.Clone(source.recent), nil
	}
	lookups, next, err := source.reader.WatchedLookups(ctx, source.cursor, domains, watchReadLimit)
	if err != nil {
		return slices.Clone(source.recent), err
	}
	source.cursor, source.readAt = next, now
	node := source.node()
	grouped := make(map[string]*alerts.WatchHit)
	order := make([]string, 0)
	for _, lookup := range lookups {
		for _, watch := range watches {
			if !watchCoversName(watch, lookup.Name) || !watch.Allows(lookup.Blocked) {
				continue
			}
			key := watch.ID + "\x00" + lookup.ClientIP
			hit, found := grouped[key]
			if !found {
				hit = &alerts.WatchHit{Watch: watch.ID, Node: node.Name, Client: lookup.ClientIP, First: lookup.OccurredAt, Last: lookup.OccurredAt, FirstQuery: lookup.ID}
				grouped[key] = hit
				order = append(order, key)
			}
			hit.Count++
			if lookup.Blocked {
				hit.Blocked++
			}
			hit.First, hit.Last = minTime(hit.First, lookup.OccurredAt), maxTime(hit.Last, lookup.OccurredAt)
			if !slices.Contains(hit.Names, lookup.Name) {
				hit.Names = append(hit.Names, lookup.Name)
			}
		}
	}
	for _, key := range order {
		hit := grouped[key]
		source.recent = append(source.recent, watchReading{
			id:     "watches.hit:" + node.key() + ":" + hit.Watch + ":" + hit.Client + ":" + strconv.FormatInt(hit.First.UnixNano(), 10),
			hit:    *hit,
			readAt: now,
		})
	}
	return slices.Clone(source.recent), nil
}

// identities ties clients to devices by the hardware addresses this node
// knows, which on a replica include those the lead handed it.
func (source *watchSource) identities(ctx context.Context, now time.Time) (devices.GivenNames, error) {
	source.mu.Lock()
	given, at := source.given, source.givenAt
	source.mu.Unlock()
	if !at.IsZero() && now.Sub(at) < watchIdentityRefresh {
		return given, nil
	}
	configuration := source.configuration()
	// With Insights off Sable records no hardware, so clients are known by
	// address alone, and watches pick them by address and network.
	var identities []querylog.ClientIdentity
	if configuration.Insights.Enabled {
		var err error
		identities, err = source.reader.ClientIdentities(ctx, now.Add(-devices.Lookback))
		if err != nil {
			return given, err
		}
	}
	given = devices.NewGivenNames(identities, configuration.Clients)
	source.mu.Lock()
	source.given, source.givenAt = given, now
	source.mu.Unlock()
	return given, nil
}

// watchCoversName reports whether a looked-up name is one of a watch's
// domains or under one.
func watchCoversName(watch config.AlertWatch, name string) bool {
	name = strings.TrimSuffix(strings.ToLower(name), ".")
	for _, domain := range watch.Domains {
		if name == domain || strings.HasSuffix(name, "."+domain) {
			return true
		}
	}
	return false
}

func minTime(left, right time.Time) time.Time {
	if left.IsZero() || (!right.IsZero() && right.Before(left)) {
		return right
	}
	return left
}

func maxTime(left, right time.Time) time.Time {
	if right.After(left) {
		return right
	}
	return left
}
