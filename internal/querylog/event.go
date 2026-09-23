package querylog

import "time"

type Source string

const (
	SourceBlocked       Source = "blocked"
	SourceCache         Source = "cache"
	SourceUpstream      Source = "upstream"
	SourceLocal         Source = "local"
	SourceAuthoritative Source = "authoritative"
	SourceError         Source = "error"
)

// PolicyDecision records how the blocking policy treated a query. The values
// are deliberately classifications rather than a trace of the full policy or
// client configuration, keeping persisted explanations useful without turning
// the query log into a configuration snapshot.
type PolicyDecision string

const (
	PolicyNotEvaluated PolicyDecision = "not_evaluated"
	PolicyDisabled     PolicyDecision = "disabled"
	PolicyPaused       PolicyDecision = "paused"
	PolicyClientBypass PolicyDecision = "client_bypass"
	PolicyAllowed      PolicyDecision = "allowed"
	PolicyBlocked      PolicyDecision = "blocked"
	PolicyNoMatch      PolicyDecision = "no_match"
)

type CacheDecision string

const (
	CacheHit   CacheDecision = "hit"
	CacheMiss  CacheDecision = "miss"
	CacheStale CacheDecision = "stale"
)

type ResolverDecision string

const (
	ResolverAuthoritative ResolverDecision = "authoritative"
	ResolverLocal         ResolverDecision = "local"
	ResolverBlocked       ResolverDecision = "blocked"
	ResolverCache         ResolverDecision = "cache"
	ResolverForwarded     ResolverDecision = "forwarded"
	ResolverRecursive     ResolverDecision = "recursive"
	ResolverError         ResolverDecision = "error"
)

type DNSSECDecision string

const (
	DNSSECSecure        DNSSECDecision = "secure"
	DNSSECInsecure      DNSSECDecision = "insecure"
	DNSSECBogus         DNSSECDecision = "bogus"
	DNSSECIndeterminate DNSSECDecision = "indeterminate"
)

// Decision is a bounded, privacy-aware explanation of the resolver path. It
// intentionally omits upstream addresses, retry errors, payloads, and client
// bypass rules. PolicyRule and Route only contain normalized DNS suffixes that
// are already represented by the logged query or Sable's DNS configuration.
type Decision struct {
	Policy     PolicyDecision `json:"policy,omitempty"`
	PolicyRule string         `json:"policy_rule,omitempty"`
	// PolicySources names the block lists that contain PolicyRule, or the
	// custom blocked domains, when a query was blocked. More than one source
	// can list the same rule, and every one is recorded.
	PolicySources []string         `json:"policy_sources,omitempty"`
	Cache         CacheDecision    `json:"cache,omitempty"`
	Resolver      ResolverDecision `json:"resolver,omitempty"`
	Route         string           `json:"route,omitempty"`
	DNSSEC        DNSSECDecision   `json:"dnssec,omitempty"`
}

type Event struct {
	OccurredAt   time.Time     `json:"occurred_at"`
	ClientIP     string        `json:"client_ip"`
	Name         string        `json:"name"`
	RecordType   uint16        `json:"record_type"`
	Class        uint16        `json:"class"`
	ResponseCode int           `json:"response_code"`
	Source       Source        `json:"source"`
	Protocol     string        `json:"protocol"`
	Answer       string        `json:"answer"`
	Duration     time.Duration `json:"duration_ns"`
	Decision     Decision      `json:"decision,omitempty"`
}

type Entry struct {
	ID int64 `json:"id"`
	Event
}

type Filter struct {
	Page     int
	PageSize int
	// Cursor and Direction select an adjacent page by primary key. Page remains
	// the human-facing page number; cursor navigation avoids making the database
	// discard every preceding row as OFFSET does on deep histories.
	Cursor    int64
	Direction string
	// KnownTotal avoids recounting an unchanged result set while paging. AfterID
	// lets a live first page count only rows that arrived since its previous
	// refresh instead of recounting the retained history.
	KnownTotal    int
	UseKnownTotal bool
	AfterID       int64
	Incremental   bool
	ClientIP      string
	Name          string
	RecordTypes   []uint16
	ResponseCode  *int
	Source        Source
	Protocol      string
	// Exact turns the client and domain filters into equality tests. The
	// search boxes want a substring so an operator can type half an address,
	// but a link that arrives from a dashboard ranking already knows the whole
	// value and must not sweep in 10.0.7.168 while asking for 10.0.7.16.
	Exact bool
	// Since and Until bound the window the page counts and reports. A zero
	// time leaves that side of the window open.
	Since time.Time
	Until time.Time
}

// Insights are the query log counts behind the dashboard rankings and
// distributions, aggregated in the database so a window wider than a page of
// rows still reports true totals.
type Insights struct {
	Clients       map[string]uint64
	Domains       map[string]uint64
	Blocked       map[string]uint64
	RecordTypes   map[uint16]uint64
	Sources       map[string]uint64
	ResponseCodes map[int]uint64
}

// BlockingActivity summarizes the blocked queries in a window. The totals are
// exact counts from the query log; the two rankings keep the busiest entries.
type BlockingActivity struct {
	// Queries is every query in the window, blocked or not, so a blocked total
	// can be read as a share of traffic.
	Queries        uint64
	Blocked        uint64
	BlockedDomains uint64
	BlockedClients uint64
	TopDomains     map[string]uint64
	TopClients     map[string]uint64
	// Sources counts blocked queries per block list, from the moment blocked
	// queries began recording their source. SourcesSince is that moment when
	// it falls inside the window, so a partial count is never passed off as
	// the whole period; it is zero when the whole window is covered.
	Sources      map[string]SourceActivity
	SourcesSince time.Time
}

// SourceActivity is how many blocked queries one source accounts for.
type SourceActivity struct {
	// Blocked counts queries whose matching rule this source contained. A rule
	// several lists share counts once for each of them.
	Blocked uint64
	// Sole counts queries no other source would have blocked.
	Sole uint64
}

// BlockedNameEvidence is what the query log retained about one name that was
// blocked in a window: how often, when, and for which clients.
type BlockedNameEvidence struct {
	Name         string
	Blocked      uint64
	FirstBlocked time.Time
	LastBlocked  time.Time
	// ClientCount is every distinct client; Clients keeps only the busiest.
	ClientCount uint64
	Clients     map[string]uint64
}

// ClientActivity is one client address's traffic in a window, with when it was
// first and last seen across all retained history.
type ClientActivity struct {
	Client    string
	Queries   uint64
	Blocked   uint64
	FirstSeen time.Time
	LastSeen  time.Time
	// NewDomains counts names this client queried for the first time inside
	// the window.
	NewDomains uint64
	// Recent counts queries in the 24 hours before the window's end and
	// Baseline the queries in the seven days before that.
	Recent   uint64
	Baseline uint64
	// RecentNewDomains counts names first queried in those 24 hours and
	// BaselineNewDomains the names first queried in the seven days before.
	RecentNewDomains   uint64
	BaselineNewDomains uint64
}

// LookupTimes is when one client looked up one name, oldest first, for
// finding lookups that repeat on a schedule.
type LookupTimes struct {
	Client string
	Name   string
	Times  []time.Time
}

// ClientActivityReport is every client with traffic in a window. SeenSince is
// when first-seen tracking began; a client first seen at that moment may have
// been around before it.
type ClientActivityReport struct {
	Clients   []ClientActivity
	SeenSince time.Time
}

// ClientDomain is a name one client queried.
type ClientDomain struct {
	Name      string
	Queries   uint64
	Blocked   uint64
	FirstSeen time.Time
}

// ClientIdentity ties a client address to a hardware address, as reported by a
// source such as a UniFi controller or the server's neighbor table.
type ClientIdentity struct {
	Address  string
	MAC      string
	Source   string
	Hostname string
	SeenAt   time.Time
	// FirstSeen and LastSeen are filled in when identities are read back.
	FirstSeen time.Time
	LastSeen  time.Time
}

type Page struct {
	Entries      []Entry `json:"entries"`
	Page         int     `json:"page"`
	PageSize     int     `json:"page_size"`
	TotalEntries int     `json:"total_entries"`
	TotalPages   int     `json:"total_pages"`
}

type Observer interface {
	Enabled() bool
	Record(Event)
}
