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
