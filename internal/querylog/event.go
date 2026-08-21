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
}

type Entry struct {
	ID int64 `json:"id"`
	Event
}

type Filter struct {
	Page         int
	PageSize     int
	ClientIP     string
	Name         string
	RecordTypes  []uint16
	ResponseCode *int
	Source       Source
	Protocol     string
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
