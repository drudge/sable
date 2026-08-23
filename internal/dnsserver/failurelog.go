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
//
// clientIP names the device whose query failed, which is what turns a recurring
// failure into something an operator can act on: the runtime log alone otherwise
// cannot say which device on the network is asking. It is empty for queries
// Sable raises on its own behalf rather than for a client.
func (handler *Handler) logResolutionFailure(request *dns.Msg, clientIP, reason string, attributes ...any) {
	logger := handler.logger.Load()
	if logger == nil || !logger.Enabled(context.Background(), slog.LevelWarn) {
		return
	}
	name, recordType := questionDescription(request)
	// The client belongs in the suppression key. Without it, the same failure
	// hitting two devices logs once and names only whichever got there first,
	// which is precisely the question the line is meant to answer.
	allowed, suppressed := handler.failureLog.allow(name + "|" + recordType + "|" + reason + "|" + clientIP)
	if !allowed {
		return
	}
	fields := make([]any, 0, len(attributes)+10)
	fields = append(fields, "name", name, "type", recordType)
	if clientIP != "" {
		fields = append(fields, "client", clientIP)
	}
	fields = append(fields, "reason", reason)
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
