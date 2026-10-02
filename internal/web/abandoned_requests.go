package web

import (
	"context"
	"errors"
	"log/slog"
	"syscall"
)

// quietAbandoned keeps requests the browser gave up on out of the error log.
// A browser stops waiting whenever a newer search replaces one still running,
// the operator clicks away, or a tab closes. Go then cancels the request, and
// the database read or page render it was doing fails with
// context.Canceled, or with a broken connection if the answer was already on
// its way. Nothing failed, but the handlers logged it as an error, with Go's
// bare "context canceled" for the reason. Those records are kept at debug
// level instead; every other error is logged as before.
func quietAbandoned(logger *slog.Logger) *slog.Logger {
	if logger == nil {
		return nil
	}
	return slog.New(abandonedRequestHandler{logger.Handler()})
}

type abandonedRequestHandler struct {
	slog.Handler
}

func (handler abandonedRequestHandler) Handle(ctx context.Context, record slog.Record) error {
	if record.Level > slog.LevelDebug && recordsAbandonedRequest(record) {
		if !handler.Handler.Enabled(ctx, slog.LevelDebug) {
			return nil
		}
		quiet := slog.NewRecord(record.Time, slog.LevelDebug, record.Message+" (the browser stopped waiting)", record.PC)
		record.Attrs(func(attribute slog.Attr) bool {
			quiet.AddAttrs(attribute)
			return true
		})
		return handler.Handler.Handle(ctx, quiet)
	}
	return handler.Handler.Handle(ctx, record)
}

func (handler abandonedRequestHandler) WithAttrs(attributes []slog.Attr) slog.Handler {
	return abandonedRequestHandler{handler.Handler.WithAttrs(attributes)}
}

func (handler abandonedRequestHandler) WithGroup(name string) slog.Handler {
	return abandonedRequestHandler{handler.Handler.WithGroup(name)}
}

// recordsAbandonedRequest reports a record whose error says only that the
// browser went away.
func recordsAbandonedRequest(record slog.Record) bool {
	abandoned := false
	record.Attrs(func(attribute slog.Attr) bool {
		if err, ok := attribute.Value.Any().(error); ok && abandonedRequest(err) {
			abandoned = true
			return false
		}
		return true
	})
	return abandoned
}

func abandonedRequest(err error) bool {
	return errors.Is(err, context.Canceled) || errors.Is(err, syscall.EPIPE) || errors.Is(err, syscall.ECONNRESET)
}
