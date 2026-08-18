package serverlog

import (
	"context"
	"fmt"
	"log/slog"
	"sort"
	"strings"
	"sync"
	"time"
)

const DefaultCapacity = 5_000

type Entry struct {
	ID         uint64            `json:"id"`
	OccurredAt time.Time         `json:"occurred_at"`
	Level      slog.Level        `json:"level"`
	Message    string            `json:"message"`
	Attributes map[string]string `json:"attributes,omitempty"`
}

type Filter struct {
	Search string
	Level  string
	Limit  int
}

// Query browses persisted entries. The live buffer answers Filter; anything
// older than the buffer holds only exists in the store, so history reads go
// through here instead.
type Query struct {
	Page     int
	PageSize int
	Search   string
	Level    string
	Since    time.Time
	Until    time.Time
}

type Page struct {
	Entries      []Entry `json:"entries"`
	Page         int     `json:"page"`
	PageSize     int     `json:"page_size"`
	TotalEntries int     `json:"total_entries"`
	TotalPages   int     `json:"total_pages"`
}

// Sink receives every entry the buffer accepts so it can outlive the process.
// Record must not block and must not log through the handler feeding this
// buffer: a sink that logs its own failures back into the buffer would queue
// another write for the same broken destination and never settle.
type Sink interface {
	Record(Entry)
}

type Buffer struct {
	mu       sync.RWMutex
	entries  []Entry
	capacity int
	nextID   uint64
	sink     Sink
}

func New(capacity int) *Buffer {
	if capacity <= 0 {
		capacity = DefaultCapacity
	}
	return &Buffer{capacity: capacity, entries: make([]Entry, 0, capacity)}
}

func (buffer *Buffer) Append(entry Entry) {
	buffer.mu.Lock()
	defer buffer.mu.Unlock()
	buffer.nextID++
	entry.ID = buffer.nextID
	if entry.OccurredAt.IsZero() {
		entry.OccurredAt = time.Now()
	}
	if buffer.sink != nil {
		buffer.sink.Record(entry)
	}
	if len(buffer.entries) == buffer.capacity {
		copy(buffer.entries, buffer.entries[1:])
		buffer.entries[len(buffer.entries)-1] = entry
		return
	}
	buffer.entries = append(buffer.entries, entry)
}

// Attach sends every entry to sink from here on, and replays what the buffer
// already holds. The replay matters because logging starts before the database
// is open: configuration loading, migrations, and any failure among them would
// otherwise be the one stretch of startup missing from the history.
//
// The replay runs under the write lock so entries reach the sink in the order
// they were logged. That is safe only because Sink.Record is required not to
// block, which is also why it cannot log back through this buffer.
func (buffer *Buffer) Attach(sink Sink) {
	buffer.mu.Lock()
	defer buffer.mu.Unlock()
	buffer.sink = sink
	if sink == nil {
		return
	}
	for _, entry := range buffer.entries {
		sink.Record(cloneEntry(entry))
	}
}

func (buffer *Buffer) Entries(filter Filter) []Entry {
	buffer.mu.RLock()
	defer buffer.mu.RUnlock()
	limit := filter.Limit
	if limit <= 0 || limit > buffer.capacity {
		limit = buffer.capacity
	}
	search := strings.ToLower(strings.TrimSpace(filter.Search))
	level := strings.ToUpper(strings.TrimSpace(filter.Level))
	result := make([]Entry, 0, min(limit, len(buffer.entries)))
	for index := len(buffer.entries) - 1; index >= 0 && len(result) < limit; index-- {
		entry := buffer.entries[index]
		if level != "" && level != "ALL" && levelName(entry.Level) != level {
			continue
		}
		if search != "" && !entryContains(entry, search) {
			continue
		}
		result = append(result, cloneEntry(entry))
	}
	return result
}

func entryContains(entry Entry, search string) bool {
	if strings.Contains(strings.ToLower(entry.Message), search) || strings.Contains(strings.ToLower(levelName(entry.Level)), search) {
		return true
	}
	for key, value := range entry.Attributes {
		if strings.Contains(strings.ToLower(key), search) || strings.Contains(strings.ToLower(value), search) {
			return true
		}
	}
	return false
}

func cloneEntry(entry Entry) Entry {
	if len(entry.Attributes) == 0 {
		return entry
	}
	original := entry.Attributes
	entry.Attributes = make(map[string]string, len(entry.Attributes))
	for key, value := range original {
		entry.Attributes[key] = value
	}
	return entry
}

func levelName(level slog.Level) string {
	switch {
	case level >= slog.LevelError:
		return "ERROR"
	case level >= slog.LevelWarn:
		return "WARN"
	case level >= slog.LevelInfo:
		return "INFO"
	default:
		return "DEBUG"
	}
}

type Handler struct {
	next   slog.Handler
	buffer *Buffer
	attrs  []slog.Attr
	groups []string
}

func NewHandler(next slog.Handler, buffer *Buffer) *Handler {
	return &Handler{next: next, buffer: buffer}
}

func (handler *Handler) Enabled(ctx context.Context, level slog.Level) bool {
	return handler.next.Enabled(ctx, level)
}

func (handler *Handler) Handle(ctx context.Context, record slog.Record) error {
	attributes := make(map[string]string, len(handler.attrs)+record.NumAttrs())
	for _, attribute := range handler.attrs {
		appendAttribute(attributes, handler.groups, attribute)
	}
	record.Attrs(func(attribute slog.Attr) bool {
		appendAttribute(attributes, handler.groups, attribute)
		return true
	})
	handler.buffer.Append(Entry{
		OccurredAt: record.Time,
		Level:      record.Level,
		Message:    record.Message,
		Attributes: attributes,
	})
	return handler.next.Handle(ctx, record)
}

func (handler *Handler) WithAttrs(attributes []slog.Attr) slog.Handler {
	clone := *handler
	clone.next = handler.next.WithAttrs(attributes)
	clone.attrs = append(append([]slog.Attr(nil), handler.attrs...), attributes...)
	clone.groups = append([]string(nil), handler.groups...)
	return &clone
}

func (handler *Handler) WithGroup(name string) slog.Handler {
	clone := *handler
	clone.next = handler.next.WithGroup(name)
	clone.attrs = append([]slog.Attr(nil), handler.attrs...)
	clone.groups = append(append([]string(nil), handler.groups...), name)
	return &clone
}

func appendAttribute(destination map[string]string, groups []string, attribute slog.Attr) {
	attribute.Value = attribute.Value.Resolve()
	key := strings.Join(append(append([]string(nil), groups...), attribute.Key), ".")
	if attribute.Value.Kind() == slog.KindGroup {
		for _, nested := range attribute.Value.Group() {
			appendAttribute(destination, append(groups, attribute.Key), nested)
		}
		return
	}
	destination[key] = fmt.Sprint(attribute.Value.Any())
}

func AttributeText(attributes map[string]string) string {
	if len(attributes) == 0 {
		return ""
	}
	keys := make([]string, 0, len(attributes))
	for key := range attributes {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, key := range keys {
		parts = append(parts, key+"="+attributes[key])
	}
	return strings.Join(parts, " ")
}
