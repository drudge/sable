package dnsserver

import (
	"fmt"
	"io"
	"maps"
	"net"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// TestConcurrentActivationLosesNoUpdate races configuration reloads against
// zone changes. Each reload's runtime was compiled from the zones it saw at
// startup, as a reload that started before the zone changes would be. When
// both writers finish, the last zone change and the last reload must both be
// live.
func TestConcurrentActivationLosesNoUpdate(t *testing.T) {
	t.Parallel()

	const rounds = 100
	configuration := testRuntimeConfig()
	configuration.Zones = []AuthoritativeZone{testAuthoritativeZone("v0.test", "192.0.2.1")}
	initial, err := Compile(configuration)
	if err != nil {
		t.Fatal(err)
	}
	handler := NewHandler(initial)

	reloads := make([]*Runtime, rounds)
	for round := range reloads {
		reload := configuration
		reload.Forwarders = []string{fmt.Sprintf("192.0.2.%d:53", round+1)}
		if reloads[round], err = Compile(reload); err != nil {
			t.Fatal(err)
		}
	}

	var writers sync.WaitGroup
	start := make(chan struct{})
	writers.Go(func() {
		<-start
		for round := 1; round <= rounds; round++ {
			zone := testAuthoritativeZone(fmt.Sprintf("v%d.test", round), "192.0.2.1")
			if err := handler.ActivateZones([]AuthoritativeZone{zone}, nil); err != nil {
				t.Error(err)
				return
			}
		}
	})
	writers.Go(func() {
		<-start
		for _, reload := range reloads {
			if err := handler.Activate(reload); err != nil {
				t.Error(err)
				return
			}
		}
	})
	close(start)
	writers.Wait()

	final := handler.runtime.Load()
	if _, found := final.zones[fmt.Sprintf("v%d.test", rounds)]; !found || len(final.zones) != 1 {
		t.Errorf("active zones = %v, want only the last zone change", slices.Sorted(maps.Keys(final.zones)))
	}
	if want := []string{fmt.Sprintf("192.0.2.%d:53", rounds)}; !slices.Equal(final.forwarders, want) {
		t.Errorf("active forwarders = %v, want the last reload's %v", final.forwarders, want)
	}
	if final.zoneGeneration != rounds {
		t.Errorf("zone generation = %d, want %d", final.zoneGeneration, rounds)
	}
}

// A reload compiled before a zone change and activated after it must keep the
// zone change, and pick up its own configuration.
func TestActivateKeepsZoneChangeMadeWhileReloadCompiled(t *testing.T) {
	t.Parallel()

	configuration := testRuntimeConfig()
	configuration.Zones = []AuthoritativeZone{testAuthoritativeZone("old.test", "192.0.2.10")}
	initial, err := Compile(configuration)
	if err != nil {
		t.Fatal(err)
	}
	handler := NewHandler(initial)

	reloadConfiguration := configuration
	reloadConfiguration.Routes = []ForwardingRoute{{Domain: "corp.test", Forwarders: []string{"192.0.2.53:53"}}}
	reload, err := Compile(reloadConfiguration)
	if err != nil {
		t.Fatal(err)
	}
	if err := handler.ActivateZones([]AuthoritativeZone{testAuthoritativeZone("new.test", "192.0.2.20")}, nil); err != nil {
		t.Fatal(err)
	}
	if err := handler.Activate(reload); err != nil {
		t.Fatal(err)
	}

	active := handler.runtime.Load()
	if _, found := active.zones["new.test"]; !found {
		t.Fatalf("zone change was lost: zones = %v", slices.Sorted(maps.Keys(active.zones)))
	}
	if _, found := active.zones["old.test"]; found {
		t.Fatal("reload put back a zone the zone change removed")
	}
	if got := active.routes["corp.test"]; !slices.Equal(got, []string{"192.0.2.53:53"}) {
		t.Fatalf("reloaded forwarding route = %v", got)
	}
}

// Queries in flight still hold the active runtime, so a zone change that alters
// the zone-derived DNSSEC exceptions must give the new runtime its own
// validator instead of changing the shared one.
func TestActivateZonesLeavesActiveValidatorAlone(t *testing.T) {
	t.Parallel()

	configuration := testRuntimeConfig()
	configuration.DNSSECValidation = true
	zone := AuthoritativeZone{
		Name: "private.example", Type: "forwarder",
		Records: []ZoneRecord{
			{Name: "@", Type: "SOA", TTL: 300, Value: "ns1.private.example. hostmaster.private.example. 1 3600 600 1209600 300"},
			{Name: "@", Type: "FWD", TTL: 300, Value: "udp 0 192.0.2.53:53"},
		},
	}
	configuration.Zones = []AuthoritativeZone{zone}
	active, err := Compile(configuration)
	if err != nil {
		t.Fatal(err)
	}
	handler := NewHandler(active)
	sharedValidator := active.dnssec

	zone.DNSSECValidationDisabled = true
	if err := handler.ActivateZones([]AuthoritativeZone{zone}, nil); err != nil {
		t.Fatal(err)
	}
	if got := sharedValidator.zoneInsecureDomains(); len(got) != 0 {
		t.Fatalf("active validator exceptions = %v, want unchanged", got)
	}
	next := handler.runtime.Load()
	if next.dnssec == sharedValidator {
		t.Fatal("zone change reused the active validator")
	}
	if got := next.dnssec.zoneInsecureDomains(); !slices.Equal(got, []string{"private.example."}) {
		t.Fatalf("new validator exceptions = %v, want [private.example.]", got)
	}
	if !anchorsEqual(next.dnssec.anchors, sharedValidator.anchors) {
		t.Fatal("new validator lost the active trust anchors")
	}
}

func anchorsEqual(left, right map[string][]dns.RR) bool {
	if len(left) != len(right) {
		return false
	}
	for owner, records := range left {
		if len(records) != len(right[owner]) {
			return false
		}
		for index := range records {
			if records[index].String() != right[owner][index].String() {
				return false
			}
		}
	}
	return true
}

func TestLimitListenerClosesConnectionsPastTheCap(t *testing.T) {
	t.Parallel()

	base, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	listener := limitListener(base, newConnectionSlots(1))
	t.Cleanup(func() { _ = listener.Close() })
	accepted := make(chan net.Conn)
	go func() {
		for {
			connection, err := listener.Accept()
			if err != nil {
				close(accepted)
				return
			}
			accepted <- connection
		}
	}()

	first := dialForLimit(t, base.Addr().String())
	held := <-accepted

	// The cap is full, so the next connection is closed on arrival.
	refused := dialForLimit(t, base.Addr().String())
	_ = refused.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := refused.Read(make([]byte, 1)); err != io.EOF {
		t.Fatalf("read on refused connection = %v, want EOF", err)
	}

	// Closing the held connection frees its slot for the next one.
	_ = held.Close()
	_ = first.Close()
	dialForLimit(t, base.Addr().String())
	select {
	case connection := <-accepted:
		_ = connection.Close()
	case <-time.After(5 * time.Second):
		t.Fatal("connection after a slot was freed was not accepted")
	}
}

func dialForLimit(t *testing.T, address string) net.Conn {
	t.Helper()
	connection, err := net.Dial("tcp", address)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = connection.Close() })
	return connection
}

func TestForwarderPoolReapsIdleConnectionsWithoutTake(t *testing.T) {
	t.Parallel()

	pool := newForwarderPool()
	t.Cleanup(pool.Close)
	server, client := net.Pipe()
	t.Cleanup(func() { _ = server.Close() })
	expiredServer, expiredClient := net.Pipe()
	t.Cleanup(func() { _ = expiredServer.Close() })

	now := time.Now()
	pool.idle["tcp://192.0.2.1:53"] = []idleConnection{
		{connection: &dns.Conn{Conn: expiredClient}, expiry: now.Add(-time.Second)},
		{connection: &dns.Conn{Conn: client}, expiry: now.Add(time.Minute)},
	}
	pool.idle["tcp://192.0.2.2:53"] = []idleConnection{
		{connection: &dns.Conn{Conn: expiredClient}, expiry: now.Add(-time.Second)},
	}
	pool.reapIdle(now)

	if got := len(pool.idle["tcp://192.0.2.1:53"]); got != 1 {
		t.Fatalf("live endpoint kept %d connections, want 1", got)
	}
	if _, found := pool.idle["tcp://192.0.2.2:53"]; found {
		t.Fatal("endpoint with only expired connections was not dropped")
	}
	if _, err := expiredServer.Write([]byte{0}); err == nil {
		t.Fatal("expired connection is still open")
	}
}
