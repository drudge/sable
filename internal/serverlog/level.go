package serverlog

import (
	"context"
	"log/slog"
)

// LevelHandler applies a runtime-adjustable minimum level before forwarding a
// record. The downstream handler is still free to impose a stricter limit.
type LevelHandler struct {
	next  slog.Handler
	level *slog.LevelVar
}

func NewLevelHandler(next slog.Handler, level *slog.LevelVar) *LevelHandler {
	return &LevelHandler{next: next, level: level}
}

func (handler *LevelHandler) Enabled(ctx context.Context, level slog.Level) bool {
	return level >= handler.level.Level() && handler.next.Enabled(ctx, level)
}

func (handler *LevelHandler) Handle(ctx context.Context, record slog.Record) error {
	return handler.next.Handle(ctx, record)
}

func (handler *LevelHandler) WithAttrs(attributes []slog.Attr) slog.Handler {
	return &LevelHandler{next: handler.next.WithAttrs(attributes), level: handler.level}
}

func (handler *LevelHandler) WithGroup(name string) slog.Handler {
	return &LevelHandler{next: handler.next.WithGroup(name), level: handler.level}
}
