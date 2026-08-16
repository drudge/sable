package dnsserver

import (
	"context"
	"errors"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"
)

type logCapture struct {
	mu      sync.Mutex
	records []slog.Record
}

func (capture *logCapture) Enabled(context.Context, slog.Level) bool { return true }

func (capture *logCapture) Handle(_ context.Context, record slog.Record) error {
	capture.mu.Lock()
	defer capture.mu.Unlock()
	capture.records = append(capture.records, record.Clone())
	return nil
}

func (capture *logCapture) WithAttrs([]slog.Attr) slog.Handler { return capture }

func (capture *logCapture) WithGroup(string) slog.Handler { return capture }

func (capture *logCapture) entries() []slog.Record {
	capture.mu.Lock()
	defer capture.mu.Unlock()
	return append([]slog.Record(nil), capture.records...)
}

func attributeOf(record slog.Record, key string) (string, bool) {
	var value string
	var found bool
	record.Attrs(func(attribute slog.Attr) bool {
		if attribute.Key == key {
			value, found = attribute.Value.String(), true
			return false
		}
		return true
	})
	return value, found
}

func TestUpstreamFailureIsLogged(t *testing.T) {
	t.Parallel()

	runtime, err := Compile(testRuntimeConfig())
	if err != nil {
		t.Fatalf("Compile() error = %v", err)
	}
	handler := NewHandler(runtime)
	handler.upstreamExchange = func(context.Context, *dns.Msg, string, time.Duration) (*dns.Msg, error) {
		return nil, errors.New("connection refused")
	}
	capture := new(logCapture)
	handler.SetLogger(slog.New(capture))
	request := new(dns.Msg)
	request.SetQuestion("example.com.", dns.TypeA)
	writer := new(responseCapture)

	handler.ServeDNS(writer, request)

	if writer.message == nil || writer.message.Rcode != dns.RcodeServerFailure {
		t.Fatalf("response = %+v, want SERVFAIL", writer.message)
	}
	records := capture.entries()
	if len(records) != 1 {
		t.Fatalf("logged %d records, want 1", len(records))
	}
	if records[0].Level != slog.LevelWarn {
		t.Fatalf("level = %v, want warn", records[0].Level)
	}
	name, found := attributeOf(records[0], "name")
	if !found || name != "example.com" {
		t.Fatalf("name attribute = %q, found = %t", name, found)
	}
	if recordType, _ := attributeOf(records[0], "type"); recordType != "A" {
		t.Fatalf("type attribute = %q, want A", recordType)
	}
	reason, _ := attributeOf(records[0], "reason")
	if reason != "upstream resolution failed" {
		t.Fatalf("reason attribute = %q", reason)
	}
	cause, _ := attributeOf(records[0], "error")
	if !strings.Contains(cause, "connection refused") {
		t.Fatalf("error attribute = %q, want the upstream cause", cause)
	}
}

func TestUpstreamServerFailureRcodeIsLogged(t *testing.T) {
	t.Parallel()

	runtime, err := Compile(testRuntimeConfig())
	if err != nil {
		t.Fatalf("Compile() error = %v", err)
	}
	handler := NewHandler(runtime)
	handler.upstreamExchange = func(_ context.Context, request *dns.Msg, _ string, _ time.Duration) (*dns.Msg, error) {
		response := new(dns.Msg)
		response.SetRcode(request, dns.RcodeServerFailure)
		return response, nil
	}
	capture := new(logCapture)
	handler.SetLogger(slog.New(capture))
	request := new(dns.Msg)
	request.SetQuestion("broken.example.com.", dns.TypeA)

	handler.ServeDNS(new(responseCapture), request)

	records := capture.entries()
	if len(records) != 1 {
		t.Fatalf("logged %d records, want 1", len(records))
	}
	if reason, _ := attributeOf(records[0], "reason"); reason != "upstream answered SERVFAIL" {
		t.Fatalf("reason attribute = %q", reason)
	}
}

func TestResolutionFailureLoggingIsThrottled(t *testing.T) {
	t.Parallel()

	runtime, err := Compile(testRuntimeConfig())
	if err != nil {
		t.Fatalf("Compile() error = %v", err)
	}
	runtime.cache.options.FailureTTL = 0
	handler := NewHandler(runtime)
	handler.upstreamExchange = func(context.Context, *dns.Msg, string, time.Duration) (*dns.Msg, error) {
		return nil, errors.New("i/o timeout")
	}
	capture := new(logCapture)
	handler.SetLogger(slog.New(capture))
	clock := time.Now()
	handler.failureLog.now = func() time.Time { return clock }

	for range 5 {
		request := new(dns.Msg)
		request.SetQuestion("flood.example.com.", dns.TypeA)
		handler.ServeDNS(new(responseCapture), request)
	}
	if count := len(capture.entries()); count != 1 {
		t.Fatalf("logged %d records during the window, want 1", count)
	}

	clock = clock.Add(failureLogWindow + time.Second)
	request := new(dns.Msg)
	request.SetQuestion("flood.example.com.", dns.TypeA)
	handler.ServeDNS(new(responseCapture), request)

	records := capture.entries()
	if len(records) != 2 {
		t.Fatalf("logged %d records after the window, want 2", len(records))
	}
	suppressed, found := attributeOf(records[1], "suppressed")
	if !found || suppressed != "4" {
		t.Fatalf("suppressed attribute = %q, found = %t, want 4", suppressed, found)
	}
}

func TestFailureLogLimiterBoundsTrackedKeys(t *testing.T) {
	t.Parallel()

	limiter := newFailureLogLimiter()
	clock := time.Now()
	limiter.now = func() time.Time { return clock }
	for index := range failureLogKeys + 100 {
		limiter.allow(string(rune(index)) + ".example.com|A|upstream resolution failed")
	}
	if len(limiter.states) > failureLogKeys {
		t.Fatalf("tracked %d keys, want at most %d", len(limiter.states), failureLogKeys)
	}
}

func TestHandlerWithoutLoggerStaysSilent(t *testing.T) {
	t.Parallel()

	runtime, err := Compile(testRuntimeConfig())
	if err != nil {
		t.Fatalf("Compile() error = %v", err)
	}
	handler := NewHandler(runtime)
	handler.upstreamExchange = func(context.Context, *dns.Msg, string, time.Duration) (*dns.Msg, error) {
		return nil, errors.New("connection refused")
	}
	request := new(dns.Msg)
	request.SetQuestion("example.com.", dns.TypeA)
	writer := new(responseCapture)

	handler.ServeDNS(writer, request)

	if writer.message == nil || writer.message.Rcode != dns.RcodeServerFailure {
		t.Fatalf("response = %+v, want SERVFAIL", writer.message)
	}
}
