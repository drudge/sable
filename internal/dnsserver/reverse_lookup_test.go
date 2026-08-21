package dnsserver

import (
	"context"
	"net/netip"
	"sync"
	"testing"

	"github.com/drudge/sable/internal/querylog"
)

type recordingObserver struct {
	mutex     sync.Mutex
	collected []querylog.Event
}

func (observer *recordingObserver) Enabled() bool { return true }

func (observer *recordingObserver) Record(event querylog.Event) {
	observer.mutex.Lock()
	defer observer.mutex.Unlock()
	observer.collected = append(observer.collected, event)
}

func (observer *recordingObserver) events() []querylog.Event {
	observer.mutex.Lock()
	defer observer.mutex.Unlock()
	return append([]querylog.Event(nil), observer.collected...)
}

func testReverseZone() AuthoritativeZone {
	name := "7.0.10.in-addr.arpa"
	return AuthoritativeZone{
		Name: name, Type: "primary", ZoneTransfer: "deny",
		Records: []ZoneRecord{
			{Name: "@", Type: "SOA", TTL: 300, Value: "ns1." + name + ". hostmaster." + name + ". 1 3600 600 1209600 300"},
			{Name: "@", Type: "NS", TTL: 300, Value: "ns1." + name + "."},
			{Name: "16", Type: "PTR", TTL: 300, Value: "laptop.home.arpa."},
		},
	}
}

// The console names its clients with this lookup, so it has to answer from the
// authoritative zones without leaving the process, and without recording the
// query: a name printed next to a client is not traffic that client sent.
func TestReverseLookupAnswersFromZonesWithoutRecordingAQuery(t *testing.T) {
	t.Parallel()

	configuration := testRuntimeConfig()
	configuration.Zones = []AuthoritativeZone{testReverseZone()}
	runtime, err := Compile(configuration)
	if err != nil {
		t.Fatal(err)
	}
	handler := NewHandler(runtime)
	observer := &recordingObserver{}
	handler.SetQueryObserver(observer)

	name, err := handler.ReverseLookup(context.Background(), netip.MustParseAddr("10.0.7.16"))
	if err != nil {
		t.Fatalf("ReverseLookup() error = %v", err)
	}
	if name != "laptop.home.arpa" {
		t.Fatalf("ReverseLookup() = %q, want laptop.home.arpa", name)
	}
	if events := observer.events(); len(events) != 0 {
		t.Fatalf("reverse lookup recorded %d query log events", len(events))
	}
	if handler.Stats().Queries != 0 {
		t.Fatalf("reverse lookup counted %d queries", handler.Stats().Queries)
	}
}

// An address the zone covers but holds no PTR for is an answer, not an error.
func TestReverseLookupReturnsNothingForAnAddressWithNoPointer(t *testing.T) {
	t.Parallel()

	configuration := testRuntimeConfig()
	configuration.Zones = []AuthoritativeZone{testReverseZone()}
	runtime, err := Compile(configuration)
	if err != nil {
		t.Fatal(err)
	}
	handler := NewHandler(runtime)

	name, err := handler.ReverseLookup(context.Background(), netip.MustParseAddr("10.0.7.99"))
	if err != nil {
		t.Fatalf("ReverseLookup() error = %v", err)
	}
	if name != "" {
		t.Fatalf("ReverseLookup() = %q, want an empty name", name)
	}
}
