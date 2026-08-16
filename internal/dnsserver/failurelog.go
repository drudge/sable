package dnsserver

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
)

// failureLogWindow keeps a burst of identical failures from flooding the
// runtime log ring buffer and evicting unrelated entries.
const failureLogWindow = 30 * time.Second

// failureLogKeys bounds the tracker so a random-subdomain flood cannot grow
// the map without limit.
const failureLogKeys = 4096

type failureLogState struct {
	lastLoggedAt time.Time
	suppressed   uint64
}

type failureLogLimiter struct {
	mu     sync.Mutex
	states map[string]*failureLogState
	now    func() time.Time
}

func newFailureLogLimiter() *failureLogLimiter {
	return &failureLogLimiter{states: make(map[string]*failureLogState), now: time.Now}
}

// allow reports whether the caller should emit a line for key, along with the
// number of identical failures suppressed since the previous line.
func (limiter *failureLogLimiter) allow(key string) (bool, uint64) {
	limiter.mu.Lock()
	defer limiter.mu.Unlock()
	now := limiter.now()
	state, tracked := limiter.states[key]
	if !tracked {
		if len(limiter.states) >= failureLogKeys {
			limiter.pruneLocked(now)
		}
		limiter.states[key] = &failureLogState{lastLoggedAt: now}
		return true, 0
	}
	if now.Sub(state.lastLoggedAt) < failureLogWindow {
		state.suppressed++
		return false, 0
	}
	suppressed := state.suppressed
	state.suppressed = 0
	state.lastLoggedAt = now
	return true, suppressed
}

func (limiter *failureLogLimiter) pruneLocked(now time.Time) {
	for key, state := range limiter.states {
		if now.Sub(state.lastLoggedAt) >= failureLogWindow {
			delete(limiter.states, key)
		}
	}
	if len(limiter.states) < failureLogKeys {
		return
	}
	// Every tracked key is still inside its window, so drop the whole set
	// rather than letting the tracker grow without bound.
	clear(limiter.states)
}

// SetLogger attaches the runtime logger used to explain failed queries. The
// handler stays silent until one is attached.
func (handler *Handler) SetLogger(logger *slog.Logger) {
	handler.logger.Store(logger)
}

// logResolutionFailure records why a query is about to answer SERVFAIL. Query
// logs carry only the response code, so without this the cause is invisible.
func (handler *Handler) logResolutionFailure(request *dns.Msg, reason string, attributes ...any) {
	logger := handler.logger.Load()
	if logger == nil || !logger.Enabled(context.Background(), slog.LevelWarn) {
		return
	}
	name, recordType := questionDescription(request)
	allowed, suppressed := handler.failureLog.allow(name + "|" + recordType + "|" + reason)
	if !allowed {
		return
	}
	fields := make([]any, 0, len(attributes)+8)
	fields = append(fields, "name", name, "type", recordType, "reason", reason)
	fields = append(fields, attributes...)
	if suppressed > 0 {
		fields = append(fields, "suppressed", suppressed)
	}
	logger.Warn("dns query failed", fields...)
}

// upstreamFailureFields describes where a query was sent and how it broke.
func upstreamFailureFields(runtime *Runtime, forwarders []string, err error) []any {
	fields := []any{"mode", runtime.mode}
	if len(forwarders) > 0 {
		fields = append(fields, "forwarders", strings.Join(forwarders, " "))
	}
	if err != nil {
		fields = append(fields, "error", err.Error())
	}
	return fields
}

func questionDescription(request *dns.Msg) (string, string) {
	if request == nil || len(request.Question) == 0 {
		return "", ""
	}
	question := request.Question[0]
	recordType, known := dns.TypeToString[question.Qtype]
	if !known {
		recordType = fmt.Sprintf("TYPE%d", question.Qtype)
	}
	return normalizeName(question.Name), recordType
}

func rcodeDescription(rcode int) string {
	if name, known := dns.RcodeToString[rcode]; known {
		return name
	}
	return fmt.Sprintf("RCODE%d", rcode)
}
