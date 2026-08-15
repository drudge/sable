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

type Buffer struct {
	mu       sync.RWMutex
	entries  []Entry
	capacity int
	nextID   uint64
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
	if len(buffer.entries) == buffer.capacity {
		copy(buffer.entries, buffer.entries[1:])
		buffer.entries[len(buffer.entries)-1] = entry
		return
	}
	buffer.entries = append(buffer.entries, entry)
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
