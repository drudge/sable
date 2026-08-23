package dnsserver

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/drudge/sable/internal/querylog"
	"github.com/drudge/sable/internal/trustanchor"
)

type eventCollector struct {
	events chan querylog.Event
}

func (collector *eventCollector) Enabled() bool { return true }

func (collector *eventCollector) Record(event querylog.Event) { collector.events <- event }

type responseCapture struct {
	message *dns.Msg
}

func (capture *responseCapture) LocalAddr() net.Addr {
	return &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 8053}
}
func (capture *responseCapture) RemoteAddr() net.Addr {
	return &net.UDPAddr{IP: net.ParseIP("192.0.2.44"), Port: 53000}
}
func (capture *responseCapture) WriteMsg(message *dns.Msg) error {
	capture.message = message.Copy()
	return nil
}
func (capture *responseCapture) Write(buffer []byte) (int, error) { return len(buffer), nil }
func (capture *responseCapture) Close() error                     { return nil }
func (capture *responseCapture) TsigStatus() error                { return nil }
func (capture *responseCapture) TsigTimersOnly(bool)              {}
func (capture *responseCapture) Hijack()                          {}

// discardWriter drops the reply so a handler benchmark measures resolution
// rather than the copy responseCapture makes to inspect it.
type discardWriter struct{}

func (discardWriter) LocalAddr() net.Addr {
	return &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 8053}
}
func (discardWriter) RemoteAddr() net.Addr {
	return &net.UDPAddr{IP: net.ParseIP("192.0.2.44"), Port: 53000}
}
func (discardWriter) WriteMsg(*dns.Msg) error          { return nil }
func (discardWriter) Write(buffer []byte) (int, error) { return len(buffer), nil }
func (discardWriter) Close() error                     { return nil }
func (discardWriter) TsigStatus() error                { return nil }
func (discardWriter) TsigTimersOnly(bool)              {}
func (discardWriter) Hijack()                          {}

type transferCapture struct {
	remote   net.Addr
	messages []*dns.Msg
}

func (capture *transferCapture) LocalAddr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 8053}
}
func (capture *transferCapture) RemoteAddr() net.Addr { return capture.remote }
func (capture *transferCapture) WriteMsg(message *dns.Msg) error {
	capture.messages = append(capture.messages, message.Copy())
	return nil
}
func (capture *transferCapture) Write(buffer []byte) (int, error) { return len(buffer), nil }
func (capture *transferCapture) Close() error                     { return nil }
func (capture *transferCapture) TsigStatus() error                { return nil }
func (capture *transferCapture) TsigTimersOnly(bool)              {}
func (capture *transferCapture) Hijack()                          {}

func TestActivateZonesReusesCompiledPolicyAndCache(t *testing.T) {
	t.Parallel()
	configuration := testRuntimeConfig()
	configuration.BlockedDomains = []string{"blocked.test"}
	configuration.Routes = []ForwardingRoute{{Domain: "corp.test", Forwarders: []string{"192.0.2.53:53"}}}
	configuration.Zones = []AuthoritativeZone{testAuthoritativeZone("old.test", "192.0.2.10")}
	runtime, err := Compile(configuration)
	if err != nil {
		t.Fatal(err)
	}
	handler := NewHandler(runtime)
	activeCache := runtime.cache
	activeBlocked := runtime.blocked
	if err := handler.ActivateZones([]AuthoritativeZone{testAuthoritativeZone("new.test", "192.0.2.20")}, nil); err != nil {
		t.Fatal(err)
	}
	activated := handler.runtime.Load()
	if activated.cache != activeCache || len(activated.blocked) != len(activeBlocked) {
		t.Fatal("zone activation rebuilt the response cache or blocking policy")
	}
	if _, found := activated.zones["new.test"]; !found {
		t.Fatalf("new zone was not activated: %#v", activated.zones)
	}
	if _, found := activated.zones["old.test"]; found {
		t.Fatal("old zone remains active")
	}
	if got := activated.routes["corp.test"]; !slices.Equal(got, []string{"192.0.2.53:53"}) {
		t.Fatalf("base forwarding route = %v", got)
	}
}

func testAuthoritativeZone(name, address string) AuthoritativeZone {
	return AuthoritativeZone{
		Name: name, Type: "primary", ZoneTransfer: "deny",
		Records: []ZoneRecord{
			{Name: "@", Type: "SOA", TTL: 300, Value: "ns1." + name + ". hostmaster." + name + ". 1 3600 600 1209600 300"},
			{Name: "@", Type: "NS", TTL: 300, Value: "ns1." + name + "."},
			{Name: "www", Type: "A", TTL: 300, Value: address},
		},
	}
}

// Alias zones carry mirrored records of their own, so the handler answers them
// like any other authoritative zone. Only dynamic updates stay reserved for
// primary zones.
func TestHandlerAnswersAliasZonesAuthoritativelyAndRefusesDynamicUpdates(t *testing.T) {
	t.Parallel()

	configuration := testRuntimeConfig()
	alias := testAuthoritativeZone("example.lan", "192.0.2.10")
	alias.Type = "alias"
	alias.DynamicUpdates = true
	configuration.Zones = []AuthoritativeZone{alias}
	runtime, err := Compile(configuration)
	if err != nil {
		t.Fatalf("Compile() error = %v", err)
	}
	handler := NewHandler(runtime)

	request := new(dns.Msg)
	request.SetQuestion("www.example.lan.", dns.TypeA)
	answered := new(responseCapture)
	handler.ServeDNS(answered, request)
	if answered.message == nil || answered.message.Rcode != dns.RcodeSuccess || !answered.message.Authoritative {
		t.Fatalf("alias zone query = %v, want an authoritative NOERROR", answered.message)
	}
	if !slices.ContainsFunc(answered.message.Answer, func(record dns.RR) bool {
		address, ok := record.(*dns.A)
		return ok && address.A.String() == "192.0.2.10"
	}) {
		t.Fatalf("alias zone answer = %v, want the mirrored A record", answered.message.Answer)
	}

	update := new(dns.Msg)
	update.SetUpdate("example.lan.")
	update.Insert([]dns.RR{testRR(t, "new.example.lan. 300 IN A 192.0.2.99")})
	refused := new(responseCapture)
	handler.ServeDNS(refused, update)
	if refused.message == nil || refused.message.Rcode == dns.RcodeSuccess {
		t.Fatalf("alias zone dynamic update = %v, want a rejection", refused.message)
	}
}

func testRR(t *testing.T, text string) dns.RR {
	t.Helper()
	record, err := dns.NewRR(text)
	if err != nil {
		t.Fatal(err)
	}
	return record
}

func TestHandlerServesAuthorizedZoneTransfersAndRefusesOthers(t *testing.T) {
	t.Parallel()

	configuration := testRuntimeConfig()
	configuration.Zones = []AuthoritativeZone{{
		Name: "example.test", ZoneTransfer: "acl", TransferACL: []string{"192.0.2.0/24"},
		Records: []ZoneRecord{
			{Name: "@", Type: "SOA", TTL: 300, Value: "ns1.example.test. hostmaster.example.test. 2026080801 3600 600 1209600 300"},
			{Name: "@", Type: "NS", TTL: 300, Value: "ns1.example.test."},
			{Name: "www", Type: "A", TTL: 60, Value: "192.0.2.10"},
		},
	}}
	runtime, err := Compile(configuration)
	if err != nil {
		t.Fatalf("Compile() error = %v", err)
	}
	handler := NewHandler(runtime)
	request := new(dns.Msg)
	request.SetAxfr("example.test.")
	authorized := &transferCapture{remote: &net.TCPAddr{IP: net.ParseIP("192.0.2.44"), Port: 53000}}
	handler.ServeDNS(authorized, request)

	var transferred []dns.RR
	for _, message := range authorized.messages {
		transferred = append(transferred, message.Answer...)
	}
	if len(transferred) != 4 || transferred[0].Header().Rrtype != dns.TypeSOA || transferred[len(transferred)-1].Header().Rrtype != dns.TypeSOA {
		t.Fatalf("AXFR records = %v, want opening SOA, body, and closing SOA", transferred)
	}
	if !slices.ContainsFunc(transferred, func(record dns.RR) bool {
		return record.Header().Rrtype == dns.TypeA && record.Header().Name == "www.example.test."
	}) {
		t.Fatalf("AXFR records = %v, want www A record", transferred)
	}

	refused := &transferCapture{remote: &net.TCPAddr{IP: net.ParseIP("198.51.100.9"), Port: 53000}}
	handler.ServeDNS(refused, request)
	if len(refused.messages) != 1 || refused.messages[0].Rcode != dns.RcodeRefused {
		t.Fatalf("unauthorized AXFR messages = %+v, want REFUSED", refused.messages)
	}
	udp := new(responseCapture)
	handler.ServeDNS(udp, request)
	if udp.message == nil || udp.message.Rcode != dns.RcodeRefused {
		t.Fatalf("UDP AXFR response = %+v, want REFUSED", udp.message)
	}
}

func TestHandlerRefusesZoneTransferOverDoH(t *testing.T) {
	t.Parallel()

	configuration := testRuntimeConfig()
	configuration.Zones = []AuthoritativeZone{{
		Name: "example.test", ZoneTransfer: "allow",
		Records: []ZoneRecord{
			{Name: "@", Type: "SOA", TTL: 300, Value: "ns1.example.test. hostmaster.example.test. 2026080801 3600 600 1209600 300"},
			{Name: "@", Type: "NS", TTL: 300, Value: "ns1.example.test."},
			{Name: "www", Type: "A", TTL: 60, Value: "192.0.2.10"},
		},
	}}
	runtime, err := Compile(configuration)
	if err != nil {
		t.Fatalf("Compile() error = %v", err)
	}
	handler := NewHandler(runtime)

	request := new(dns.Msg)
	request.SetAxfr("example.test.")

	// A DoH request whose connection LocalAddr is a *net.TCPAddr, exactly as the
	// HTTP server supplies it. Its network is "tcp", so the transport check alone
	// would let the transfer through if DoH were not refused explicitly. DoH
	// cannot verify a TSIG MAC, so a transfer over it must never be honored.
	ctx := context.WithValue(context.Background(), http.LocalAddrContextKey, &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 443})
	httpRequest := httptest.NewRequest(http.MethodPost, "/dns-query", nil).WithContext(ctx)
	httpRequest.RemoteAddr = "192.0.2.44:53000"
	doh := newDoHResponseWriter(httpRequest)

	handler.ServeDNS(doh, request)
	if doh.message == nil || doh.message.Rcode != dns.RcodeRefused {
		t.Fatalf("DoH AXFR response = %+v, want REFUSED", doh.message)
	}
	if len(doh.message.Answer) != 0 {
		t.Fatalf("DoH AXFR leaked %d answer records", len(doh.message.Answer))
	}

	// The same request over TCP from an allowed source still transfers, so the
	// guard is specific to DoH and does not break ordinary zone transfers.
	tcp := &transferCapture{remote: &net.TCPAddr{IP: net.ParseIP("192.0.2.44"), Port: 53000}}
	handler.ServeDNS(tcp, request)
	var transferred []dns.RR
	for _, message := range tcp.messages {
		transferred = append(transferred, message.Answer...)
	}
	if len(transferred) == 0 {
		t.Fatalf("TCP AXFR = %+v, want a successful transfer", tcp.messages)
	}
}

func TestHandlerServesJournaledIXFRAndFallsBackToAXFR(t *testing.T) {
	t.Parallel()

	configuration := testRuntimeConfig()
	configuration.Zones = []AuthoritativeZone{{
		Name: "example.test", ZoneTransfer: "allow",
		Records: []ZoneRecord{
			{Name: "@", Type: "SOA", TTL: 300, Value: "ns1.example.test. hostmaster.example.test. 1 10 3 30 300"},
			{Name: "@", Type: "NS", TTL: 300, Value: "ns1.example.test."},
			{Name: "old", Type: "A", TTL: 60, Value: "192.0.2.1"},
		},
	}}
	oldRuntime, err := Compile(configuration)
	if err != nil {
		t.Fatalf("Compile(old) error = %v", err)
	}
	handler := NewHandler(oldRuntime)
	configuration.Zones[0].Records = []ZoneRecord{
		{Name: "@", Type: "SOA", TTL: 300, Value: "ns1.example.test. hostmaster.example.test. 2 10 3 30 300"},
		{Name: "@", Type: "NS", TTL: 300, Value: "ns1.example.test."},
		{Name: "new", Type: "AAAA", TTL: 60, Value: "2001:db8::1"},
	}
	newRuntime, err := Compile(configuration)
	if err != nil {
		t.Fatalf("Compile(new) error = %v", err)
	}
	handler.Activate(newRuntime)

	request := new(dns.Msg)
	request.SetIxfr("example.test.", 1, "ns1.example.test.", "hostmaster.example.test.")
	capture := &transferCapture{remote: &net.TCPAddr{IP: net.ParseIP("192.0.2.44"), Port: 53000}}
	handler.ServeDNS(capture, request)
	var records []dns.RR
	for _, message := range capture.messages {
		records = append(records, message.Answer...)
	}
	markers := soaMarkerIndexes(records)
	if len(markers) != 4 {
		t.Fatalf("IXFR SOA markers = %v records=%v, want current/old/new/current", markers, records)
	}
	serials := make([]uint32, 0, len(markers))
	for _, marker := range markers {
		serials = append(serials, records[marker].(*dns.SOA).Serial)
	}
	if !slices.Equal(serials, []uint32{2, 1, 2, 2}) {
		t.Fatalf("IXFR serials = %v", serials)
	}
	if !slices.ContainsFunc(records, func(record dns.RR) bool { return record.Header().Name == "old.example.test." }) ||
		!slices.ContainsFunc(records, func(record dns.RR) bool { return record.Header().Name == "new.example.test." }) {
		t.Fatalf("IXFR records = %v, want deleted old and added new records", records)
	}

	request.SetIxfr("example.test.", 0, "ns1.example.test.", "hostmaster.example.test.")
	fallback := &transferCapture{remote: &net.TCPAddr{IP: net.ParseIP("192.0.2.44"), Port: 53000}}
	handler.ServeDNS(fallback, request)
	records = nil
	for _, message := range fallback.messages {
		records = append(records, message.Answer...)
	}
	if len(soaMarkerIndexes(records)) != 2 || !slices.ContainsFunc(records, func(record dns.RR) bool {
		return record.Header().Name == "new.example.test."
	}) {
		t.Fatalf("IXFR fallback records = %v, want complete AXFR snapshot", records)
	}

	request.SetIxfr("example.test.", 2, "ns1.example.test.", "hostmaster.example.test.")
	current := &transferCapture{remote: &net.TCPAddr{IP: net.ParseIP("192.0.2.44"), Port: 53000}}
	handler.ServeDNS(current, request)
	if len(current.messages) != 1 || len(current.messages[0].Answer) != 1 || current.messages[0].Answer[0].(*dns.SOA).Serial != 2 {
		t.Fatalf("current IXFR response = %+v", current.messages)
	}
}

func TestHandlerNotifiesConfiguredSecondaryServers(t *testing.T) {
	t.Parallel()

	runtime, err := Compile(testRuntimeConfig())
	if err != nil {
		t.Fatalf("Compile() error = %v", err)
	}
	handler := NewHandler(runtime)
	var attempted []string
	handler.upstreamExchange = func(_ context.Context, request *dns.Msg, forwarder string, _ time.Duration) (*dns.Msg, error) {
		if request.Opcode != dns.OpcodeNotify || len(request.Question) != 1 || request.Question[0].Name != "example.test." {
			t.Fatalf("NOTIFY request = %+v", request)
		}
		attempted = append(attempted, forwarder)
		if strings.Contains(forwarder, "192.0.2.54") {
			return nil, errors.New("secondary unavailable")
		}
		response := new(dns.Msg)
		response.SetReply(request)
		return response, nil
	}
	errorsByTarget := handler.NotifyZone(context.Background(), "example.test", []string{"192.0.2.53:53", "192.0.2.54:53"})
	if !slices.Equal(attempted, []string{"udp://192.0.2.53:53", "udp://192.0.2.54:53"}) {
		t.Fatalf("NOTIFY targets = %v", attempted)
	}
	if len(errorsByTarget) != 1 || !strings.Contains(errorsByTarget[0].Error(), "192.0.2.54:53") {
		t.Fatalf("NotifyZone() errors = %v", errorsByTarget)
	}
}

func TestHandlerAcceptsNotifyOnlyFromConfiguredPrimary(t *testing.T) {
	t.Parallel()

	configuration := testRuntimeConfig()
	configuration.Zones = []AuthoritativeZone{{
		Name: "secondary.test", Type: "secondary", PrimaryServers: []string{"192.0.2.44:53"}, PrimaryProtocol: "tcp",
		Records: []ZoneRecord{
			{Name: "@", Type: "SOA", TTL: 300, Value: "ns1.secondary.test. hostmaster.secondary.test. 1 10 3 20 300"},
			{Name: "@", Type: "NS", TTL: 300, Value: "ns1.secondary.test."},
		},
	}}
	runtime, err := Compile(configuration)
	if err != nil {
		t.Fatalf("Compile() error = %v", err)
	}
	handler := NewHandler(runtime)
	request := new(dns.Msg)
	request.SetNotify("secondary.test.")
	authorized := &transferCapture{remote: &net.UDPAddr{IP: net.ParseIP("192.0.2.44"), Port: 53000}}
	handler.ServeDNS(authorized, request)
	if len(authorized.messages) != 1 || authorized.messages[0].Rcode != dns.RcodeSuccess || authorized.messages[0].Opcode != dns.OpcodeNotify {
		t.Fatalf("authorized NOTIFY response = %+v", authorized.messages)
	}
	select {
	case notification := <-handler.Notifications():
		if notification.Zone != "secondary.test" || notification.Source != "192.0.2.44" {
			t.Fatalf("notification = %+v", notification)
		}
	default:
		t.Fatal("authorized NOTIFY did not enqueue a refresh")
	}

	unauthorized := &transferCapture{remote: &net.UDPAddr{IP: net.ParseIP("198.51.100.9"), Port: 53000}}
	handler.ServeDNS(unauthorized, request)
	if len(unauthorized.messages) != 1 || unauthorized.messages[0].Rcode != dns.RcodeRefused {
		t.Fatalf("unauthorized NOTIFY response = %+v", unauthorized.messages)
	}
	unknownRequest := new(dns.Msg)
	unknownRequest.SetNotify("unknown.test.")
	handler.ServeDNS(authorized, unknownRequest)
	if authorized.messages[len(authorized.messages)-1].Rcode != dns.RcodeNotAuth {
		t.Fatalf("unknown-zone NOTIFY response = %+v", authorized.messages[len(authorized.messages)-1])
	}
	malformed := new(dns.Msg)
	malformed.SetNotify("secondary.test.")
	malformed.Question[0].Qtype = dns.TypeA
	handler.ServeDNS(authorized, malformed)
	if authorized.messages[len(authorized.messages)-1].Rcode != dns.RcodeFormatError {
		t.Fatalf("malformed NOTIFY response = %+v", authorized.messages[len(authorized.messages)-1])
	}
}

func TestHandlerAuthenticatesSignedNotifyWithTSIG(t *testing.T) {
	secret := "c3VwZXItc2VjcmV0LXRoaXJ0eS10d28="
	configuration := testRuntimeConfig()
	configuration.TSIGKeys = []TSIGKey{{Name: "transfer-key.", Algorithm: dns.HmacSHA256, Secret: secret}}
	configuration.Zones = []AuthoritativeZone{{
		Name: "secondary.test", Type: "secondary", PrimaryServers: []string{"127.0.0.1:53"}, PrimaryProtocol: "tcp",
		TSIGKey: "transfer-key.",
		Records: []ZoneRecord{
			{Name: "@", Type: "SOA", TTL: 300, Value: "ns1.secondary.test. hostmaster.secondary.test. 1 10 3 20 300"},
			{Name: "@", Type: "NS", TTL: 300, Value: "ns1.secondary.test."},
		},
	}}
	runtime, err := Compile(configuration)
	if err != nil {
		t.Fatalf("Compile() error = %v", err)
	}
	handler := NewHandler(runtime)
	packet, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenPacket() error = %v", err)
	}
	started := make(chan struct{})
	server := &dns.Server{
		PacketConn: packet, Handler: handler, TsigProvider: handler,
		NotifyStartedFunc: func() { close(started) },
	}
	serveErrors := make(chan error, 1)
	go func() { serveErrors <- server.ActivateAndServe() }()
	<-started
	defer func() {
		_ = server.Shutdown()
		<-serveErrors
	}()

	request := new(dns.Msg)
	request.SetNotify("secondary.test.")
	request.SetTsig("transfer-key.", dns.HmacSHA256, 300, time.Now().Unix())
	client := &dns.Client{TsigSecret: map[string]string{"transfer-key.": secret}}
	response, _, err := client.Exchange(request, packet.LocalAddr().String())
	if err != nil || response.Rcode != dns.RcodeSuccess || response.IsTsig() == nil {
		t.Fatalf("signed NOTIFY response = %+v, %v", response, err)
	}
	select {
	case notification := <-handler.Notifications():
		if notification.Zone != "secondary.test" {
			t.Fatalf("notification = %+v", notification)
		}
	case <-time.After(time.Second):
		t.Fatal("signed NOTIFY did not enqueue a refresh")
	}

	unsigned := new(dns.Msg)
	unsigned.SetNotify("secondary.test.")
	response, _, err = new(dns.Client).Exchange(unsigned, packet.LocalAddr().String())
	if err != nil || response.Rcode != dns.RcodeRefused {
		t.Fatalf("unsigned NOTIFY response = %+v, %v", response, err)
	}
}

func TestHandlerAcceptsSignedDynamicUpdateAndRefusesUnsignedRequest(t *testing.T) {
	secret := "MDEyMzQ1Njc4OWFiY2RlZg=="
	configuration := testRuntimeConfig()
	configuration.TSIGKeys = []TSIGKey{{Name: "update-key.", Algorithm: dns.HmacSHA256, Secret: secret}}
	configuration.Zones = []AuthoritativeZone{{
		Name: "example.test", Type: "primary", TSIGKey: "update-key.", DynamicUpdates: true,
		Records: []ZoneRecord{
			{Name: "@", Type: "SOA", TTL: 300, Value: "ns1.example.test. hostmaster.example.test. 1 3600 600 1209600 300"},
			{Name: "@", Type: "NS", TTL: 300, Value: "ns1.example.test."},
		},
	}}
	runtime, err := Compile(configuration)
	if err != nil {
		t.Fatal(err)
	}
	handler := NewHandler(runtime)
	updates := make(chan ZoneUpdateRequest, 1)
	audits := make(chan ZoneUpdateResult, 2)
	collector := &eventCollector{events: make(chan querylog.Event, 2)}
	handler.SetQueryObserver(collector)
	handler.SetZoneUpdateAuditor(func(_ context.Context, _ ZoneUpdateRequest, result ZoneUpdateResult) {
		audits <- result
	})
	handler.SetZoneUpdater(func(_ context.Context, request ZoneUpdateRequest) ZoneUpdateResult {
		updates <- request
		return ZoneUpdateResult{Rcode: dns.RcodeSuccess, Changed: true}
	})

	packet, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server := &dns.Server{
		PacketConn: packet, Handler: handler, TsigProvider: handler, MsgAcceptFunc: dynamicUpdateAcceptFunc,
	}
	started := make(chan struct{})
	server.NotifyStartedFunc = func() { close(started) }
	go func() { _ = server.ActivateAndServe() }()
	<-started
	t.Cleanup(func() { _ = server.Shutdown() })

	unsigned := new(dns.Msg)
	unsigned.SetUpdate("example.test.")
	unsigned.Insert([]dns.RR{mustRR(t, "api.example.test. 60 IN A 192.0.2.20")})
	response, _, err := new(dns.Client).Exchange(unsigned, packet.LocalAddr().String())
	if err != nil || response.Rcode != dns.RcodeRefused {
		t.Fatalf("unsigned update response = %v, error %v", response, err)
	}

	signed := new(dns.Msg)
	signed.SetUpdate("example.test.")
	signed.Insert([]dns.RR{mustRR(t, "api.example.test. 60 IN A 192.0.2.20")})
	signed.SetTsig("update-key.", dns.HmacSHA256, 300, time.Now().Unix())
	client := &dns.Client{TsigSecret: map[string]string{"update-key.": secret}}
	response, _, err = client.Exchange(signed, packet.LocalAddr().String())
	if err != nil || response.Rcode != dns.RcodeSuccess || response.IsTsig() == nil {
		t.Fatalf("signed update response = %v, error %v", response, err)
	}
	select {
	case request := <-updates:
		if request.Zone != "example.test" || request.KeyName != "update-key." || len(request.Updates) != 1 {
			t.Fatalf("update request = %+v", request)
		}
	case <-time.After(time.Second):
		t.Fatal("signed update was not delivered")
	}
	firstAudit, secondAudit := <-audits, <-audits
	if firstAudit.Rcode != dns.RcodeRefused || secondAudit.Rcode != dns.RcodeSuccess || !secondAudit.Changed {
		t.Fatalf("update audits = %+v, %+v", firstAudit, secondAudit)
	}
	firstQuery, secondQuery := <-collector.events, <-collector.events
	if firstQuery.ResponseCode != dns.RcodeRefused || secondQuery.ResponseCode != dns.RcodeSuccess || secondQuery.Source != querylog.SourceAuthoritative {
		t.Fatalf("update query events = %+v, %+v", firstQuery, secondQuery)
	}
}

func TestHandlerRequiresTSIGForZoneTransfer(t *testing.T) {
	secret := "c3VwZXItc2VjcmV0LXRoaXJ0eS10d28="
	configuration := testRuntimeConfig()
	configuration.TSIGKeys = []TSIGKey{{Name: "transfer-key.", Algorithm: dns.HmacSHA256, Secret: secret}}
	configuration.Zones = []AuthoritativeZone{{
		Name: "example.test", Type: "primary", ZoneTransfer: "allow", TSIGKey: "transfer-key.",
		Records: []ZoneRecord{
			{Name: "@", Type: "SOA", TTL: 300, Value: "ns1.example.test. hostmaster.example.test. 1 10 3 20 300"},
			{Name: "@", Type: "NS", TTL: 300, Value: "ns1.example.test."},
			{Name: "www", Type: "A", TTL: 60, Value: "192.0.2.10"},
		},
	}}
	runtime, err := Compile(configuration)
	if err != nil {
		t.Fatalf("Compile() error = %v", err)
	}
	handler := NewHandler(runtime)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen() error = %v", err)
	}
	started := make(chan struct{})
	server := &dns.Server{
		Listener: listener, Handler: handler, TsigProvider: handler,
		NotifyStartedFunc: func() { close(started) },
	}
	serveErrors := make(chan error, 1)
	go func() { serveErrors <- server.ActivateAndServe() }()
	<-started
	defer func() {
		_ = server.Shutdown()
		<-serveErrors
	}()

	request := new(dns.Msg)
	request.SetAxfr("example.test.")
	request.SetTsig("transfer-key.", dns.HmacSHA256, 300, time.Now().Unix())
	transfer := &dns.Transfer{TsigSecret: map[string]string{"transfer-key.": secret}}
	envelopes, err := transfer.In(request, listener.Addr().String())
	if err != nil {
		t.Fatalf("signed Transfer.In() error = %v", err)
	}
	var records []dns.RR
	for envelope := range envelopes {
		if envelope.Error != nil {
			t.Fatalf("signed transfer envelope error = %v", envelope.Error)
		}
		records = append(records, envelope.RR...)
	}
	if len(records) != 4 || records[0].Header().Rrtype != dns.TypeSOA || records[len(records)-1].Header().Rrtype != dns.TypeSOA {
		t.Fatalf("signed AXFR records = %v", records)
	}

	unsigned := new(dns.Msg)
	unsigned.SetAxfr("example.test.")
	unsignedTransfer := new(dns.Transfer)
	envelopes, err = unsignedTransfer.In(unsigned, listener.Addr().String())
	if err != nil {
		t.Fatalf("unsigned Transfer.In() start error = %v", err)
	}
	envelope := <-envelopes
	if envelope == nil || envelope.Error == nil {
		t.Fatalf("unsigned transfer envelope = %+v, want refusal", envelope)
	}
	for range envelopes {
	}
}

func TestForwarderAndStubZonesRouteTheirEntireNamespace(t *testing.T) {
	t.Parallel()

	configuration := testRuntimeConfig()
	configuration.Zones = []AuthoritativeZone{
		{
			Name: "forward.test", Type: "forwarder",
			Records: []ZoneRecord{
				{Name: "@", Type: "SOA", TTL: 300, Value: "ns1.forward.test. hostmaster.forward.test. 1 3600 600 1209600 300"},
				{Name: "@", Type: "FWD", TTL: 300, Value: "tls 5 dns.forwarder.test"},
			},
		},
		{
			Name: "stub.test", Type: "stub", PrimaryServers: []string{"192.0.2.54:53"}, PrimaryProtocol: "udp",
			Records: []ZoneRecord{
				{Name: "@", Type: "SOA", TTL: 300, Value: "ns1.stub.test. hostmaster.stub.test. 1 3600 600 1209600 300"},
				{Name: "@", Type: "NS", TTL: 300, Value: "ns1.stub.test."},
			},
		},
	}
	runtime, err := Compile(configuration)
	if err != nil {
		t.Fatalf("Compile() error = %v", err)
	}
	handler := NewHandler(runtime)
	var endpoints []string
	handler.upstreamExchange = func(_ context.Context, request *dns.Msg, endpoint string, _ time.Duration) (*dns.Msg, error) {
		endpoints = append(endpoints, endpoint)
		return positiveResponse(request, 60), nil
	}
	for _, name := range []string{"api.forward.test.", "deep.service.stub.test."} {
		request := new(dns.Msg)
		request.SetQuestion(name, dns.TypeA)
		result := handler.resolveForClient(request, runtime, "192.0.2.1")
		if result.source != querylog.SourceUpstream || result.response.Rcode != dns.RcodeSuccess {
			t.Fatalf("resolve %s = source %q response %+v", name, result.source, result.response)
		}
	}
	if !slices.Equal(endpoints, []string{"tls://dns.forwarder.test:853", "udp://192.0.2.54:53"}) {
		t.Fatalf("zone routing endpoints = %v", endpoints)
	}
	if runtime.zoneCount != 2 {
		t.Fatalf("zoneCount = %d, want 2", runtime.zoneCount)
	}
}

func TestFetchSecondaryAndStubZonesProducesPersistableRecords(t *testing.T) {
	t.Parallel()

	runtime, err := Compile(testRuntimeConfig())
	if err != nil {
		t.Fatalf("Compile() error = %v", err)
	}
	handler := NewHandler(runtime)
	handler.zoneTransfer = func(_ context.Context, zone, primary, protocol string, _ transferAuth, _ time.Duration) ([]dns.RR, error) {
		if zone != "secondary.test" || primary != "192.0.2.53:53" || protocol != "tcp" {
			t.Fatalf("zone transfer = %q %q %q", zone, primary, protocol)
		}
		return []dns.RR{
			mustRR(t, "secondary.test. 300 IN SOA ns1.secondary.test. hostmaster.secondary.test. 2 3600 600 1209600 300"),
			mustRR(t, "secondary.test. 300 IN NS ns1.secondary.test."),
			mustRR(t, "www.secondary.test. 60 IN A 192.0.2.10"),
		}, nil
	}
	secondary, err := handler.FetchZone(context.Background(), "secondary.test", "secondary", []string{"192.0.2.53:53"}, "tcp", "")
	if err != nil || len(secondary) != 3 || secondary[2].Name != "www" || secondary[2].Value != "192.0.2.10" {
		t.Fatalf("secondary FetchZone() = %#v, %v", secondary, err)
	}

	handler.upstreamExchange = func(_ context.Context, request *dns.Msg, endpoint string, _ time.Duration) (*dns.Msg, error) {
		if endpoint != "udp://192.0.2.54:53" {
			t.Fatalf("stub endpoint = %q", endpoint)
		}
		response := new(dns.Msg)
		response.SetReply(request)
		switch request.Question[0].Qtype {
		case dns.TypeSOA:
			response.Answer = []dns.RR{mustRR(t, "stub.test. 300 IN SOA ns1.stub.test. hostmaster.stub.test. 2 3600 600 1209600 300")}
		case dns.TypeNS:
			response.Answer = []dns.RR{mustRR(t, "stub.test. 300 IN NS ns1.stub.test.")}
			response.Extra = []dns.RR{mustRR(t, "ns1.stub.test. 300 IN A 192.0.2.54")}
		}
		return response, nil
	}
	stub, err := handler.FetchZone(context.Background(), "stub.test", "stub", []string{"192.0.2.54:53"}, "udp", "")
	if err != nil || len(stub) != 3 || !slices.ContainsFunc(stub, func(record ZoneRecord) bool { return record.Type == "A" && record.Name == "ns1" }) {
		t.Fatalf("stub FetchZone() = %#v, %v", stub, err)
	}
}

func TestRefreshSecondaryAppliesIXFRDelta(t *testing.T) {
	t.Parallel()

	runtime, err := Compile(testRuntimeConfig())
	if err != nil {
		t.Fatalf("Compile() error = %v", err)
	}
	handler := NewHandler(runtime)
	current := []ZoneRecord{
		{Name: "@", Type: "SOA", TTL: 300, Value: "ns1.secondary.test. hostmaster.secondary.test. 1 10 3 30 300"},
		{Name: "@", Type: "NS", TTL: 300, Value: "ns1.secondary.test."},
		{Name: "old", Type: "A", TTL: 60, Value: "192.0.2.1"},
	}
	handler.zoneRefresh = func(_ context.Context, zone, primary, protocol string, soa *dns.SOA, _ transferAuth, _ time.Duration) ([]dns.RR, error) {
		if zone != "secondary.test" || primary != "192.0.2.53:53" || protocol != "tcp" || soa.Serial != 1 {
			t.Fatalf("IXFR request = %q %q %q serial=%d", zone, primary, protocol, soa.Serial)
		}
		return []dns.RR{
			mustRR(t, "secondary.test. 300 IN SOA ns1.secondary.test. hostmaster.secondary.test. 2 10 3 30 300"),
			mustRR(t, "secondary.test. 300 IN SOA ns1.secondary.test. hostmaster.secondary.test. 1 10 3 30 300"),
			mustRR(t, "old.secondary.test. 60 IN A 192.0.2.1"),
			mustRR(t, "secondary.test. 300 IN SOA ns1.secondary.test. hostmaster.secondary.test. 2 10 3 30 300"),
			mustRR(t, "new.secondary.test. 60 IN AAAA 2001:db8::1"),
			mustRR(t, "secondary.test. 300 IN SOA ns1.secondary.test. hostmaster.secondary.test. 2 10 3 30 300"),
		}, nil
	}
	updated, changed, err := handler.RefreshZone(
		context.Background(), "secondary.test", "secondary", []string{"192.0.2.53:53"}, "tcp", "", current,
	)
	if err != nil || !changed {
		t.Fatalf("RefreshZone() changed=%v error=%v", changed, err)
	}
	if slices.ContainsFunc(updated, func(record ZoneRecord) bool { return record.Name == "old" }) ||
		!slices.ContainsFunc(updated, func(record ZoneRecord) bool { return record.Name == "new" && record.Type == "AAAA" }) {
		t.Fatalf("refreshed records = %#v", updated)
	}
}

func TestRefreshSecondarySelectsConfiguredTSIGKey(t *testing.T) {
	t.Parallel()

	configuration := testRuntimeConfig()
	configuration.TSIGKeys = []TSIGKey{{
		Name: "transfer-key.", Algorithm: dns.HmacSHA512,
		Secret: "c3VwZXItc2VjcmV0LXRoaXJ0eS10d28=",
	}}
	runtime, err := Compile(configuration)
	if err != nil {
		t.Fatalf("Compile() error = %v", err)
	}
	handler := NewHandler(runtime)
	current := []ZoneRecord{
		{Name: "@", Type: "SOA", TTL: 300, Value: "ns1.secondary.test. hostmaster.secondary.test. 1 10 3 30 300"},
		{Name: "@", Type: "NS", TTL: 300, Value: "ns1.secondary.test."},
	}
	handler.zoneRefresh = func(_ context.Context, _, _, _ string, soa *dns.SOA, auth transferAuth, _ time.Duration) ([]dns.RR, error) {
		if auth.keyName != "transfer-key." || auth.algorithm != dns.HmacSHA512 || auth.secret != configuration.TSIGKeys[0].Secret {
			t.Fatalf("transfer auth = %+v", auth)
		}
		return []dns.RR{dns.Copy(soa)}, nil
	}
	_, changed, err := handler.RefreshZone(
		context.Background(), "secondary.test", "secondary", []string{"192.0.2.53:53"}, "tcp", "transfer-key", current,
	)
	if err != nil || changed {
		t.Fatalf("RefreshZone() changed=%v error=%v", changed, err)
	}
}

func TestExpiredManagedZoneReturnsServerFailureUntilRecovered(t *testing.T) {
	t.Parallel()

	configuration := testRuntimeConfig()
	configuration.Zones = []AuthoritativeZone{{
		Name: "secondary.test", Type: "secondary", PrimaryServers: []string{"192.0.2.53:53"}, PrimaryProtocol: "tcp",
		Records: []ZoneRecord{
			{Name: "@", Type: "SOA", TTL: 300, Value: "ns1.secondary.test. hostmaster.secondary.test. 1 10 3 20 300"},
			{Name: "@", Type: "NS", TTL: 300, Value: "ns1.secondary.test."},
			{Name: "www", Type: "A", TTL: 60, Value: "192.0.2.10"},
		},
	}}
	runtime, err := Compile(configuration)
	if err != nil {
		t.Fatalf("Compile() error = %v", err)
	}
	handler := NewHandler(runtime)
	request := new(dns.Msg)
	request.SetQuestion("www.secondary.test.", dns.TypeA)
	handler.SetZoneExpired("secondary.test", true)
	expired := new(responseCapture)
	handler.ServeDNS(expired, request)
	if expired.message == nil || expired.message.Rcode != dns.RcodeServerFailure {
		t.Fatalf("expired response = %+v, want SERVFAIL", expired.message)
	}
	handler.SetZoneExpired("secondary.test", false)
	recovered := new(responseCapture)
	handler.ServeDNS(recovered, request)
	if recovered.message == nil || recovered.message.Rcode != dns.RcodeSuccess || len(recovered.message.Answer) != 1 {
		t.Fatalf("recovered response = %+v", recovered.message)
	}
}

func mustRR(t *testing.T, value string) dns.RR {
	t.Helper()
	record, err := dns.NewRR(value)
	if err != nil {
		t.Fatalf("dns.NewRR(%q): %v", value, err)
	}
	return record
}

func TestRuntimeMatchesBlockedDomainAndChildren(t *testing.T) {
	t.Parallel()

	configuration := testRuntimeConfig()
	configuration.Blocking = true
	configuration.BlockedDomains = []string{"ads.example"}
	runtime, err := Compile(configuration)
	if err != nil {
		t.Fatalf("Compile() error = %v", err)
	}
	for _, name := range []string{"ads.example.", "pixel.ads.example.", "ADS.EXAMPLE"} {
		if !runtime.matchesBlocked(name) {
			t.Errorf("matchesBlocked(%q) = false, want true", name)
		}
	}
	if runtime.matchesBlocked("notads.example.") {
		t.Error("matchesBlocked(notads.example.) = true, want false")
	}
}

func TestHandlerReportsBlockedQueryWithoutCallingUpstream(t *testing.T) {
	t.Parallel()

	configuration := testRuntimeConfig()
	configuration.Forwarders = []string{"127.0.0.1:1"}
	configuration.Blocking = true
	configuration.BlockedDomains = []string{"ads.example"}
	runtime, err := Compile(configuration)
	if err != nil {
		t.Fatalf("Compile() error = %v", err)
	}
	handler := NewHandler(runtime)
	collector := &eventCollector{events: make(chan querylog.Event, 1)}
	handler.SetQueryObserver(collector)
	request := new(dns.Msg)
	request.SetQuestion("pixel.ads.example.", dns.TypeAAAA)
	capture := new(responseCapture)

	handler.ServeDNS(capture, request)
	event := <-collector.events
	if capture.message.Rcode != dns.RcodeNameError {
		t.Fatalf("response Rcode = %d, want NXDOMAIN", capture.message.Rcode)
	}
	if event.Source != querylog.SourceBlocked || event.ClientIP != "192.0.2.44" {
		t.Fatalf("event = %+v, want blocked source and client IP", event)
	}
}

func TestBlockingPolicySupportsOverridesPauseBypassAndResponses(t *testing.T) {
	t.Parallel()

	configuration := testRuntimeConfig()
	configuration.Blocking = true
	configuration.BlockedDomains = []string{"ads.example"}
	configuration.AllowedDomains = []string{"safe.ads.example", "*.trusted.ads.example"}
	configuration.BlockingType = "custom"
	configuration.BlockingTTL = 42
	configuration.BlockingAddrs = []string{"192.0.2.9", "2001:db8::9"}
	configuration.BypassClients = []string{"198.51.100.0/24"}
	configuration.AllowTXTReport = true
	runtime, err := Compile(configuration)
	if err != nil {
		t.Fatalf("Compile() error = %v", err)
	}
	handler := NewHandler(runtime)
	handler.upstreamExchange = func(_ context.Context, request *dns.Msg, _ string, _ time.Duration) (*dns.Msg, error) {
		response := new(dns.Msg)
		response.SetReply(request)
		return response, nil
	}

	request := new(dns.Msg)
	request.SetQuestion("pixel.ads.example.", dns.TypeANY)
	result := handler.resolveForClient(request, runtime, "192.0.2.4")
	if result.source != querylog.SourceBlocked || result.response.Rcode != dns.RcodeSuccess || len(result.response.Answer) != 2 {
		t.Fatalf("custom blocked result = source %q response %+v", result.source, result.response)
	}
	for _, answer := range result.response.Answer {
		if answer.Header().Ttl != 42 {
			t.Fatalf("blocking answer TTL = %d, want 42", answer.Header().Ttl)
		}
	}

	request.SetQuestion("safe.ads.example.", dns.TypeA)
	if got := handler.resolveForClient(request, runtime, "192.0.2.4"); got.source != querylog.SourceUpstream {
		t.Fatalf("allowed override source = %q, want upstream", got.source)
	}
	request.SetQuestion("child.safe.ads.example.", dns.TypeA)
	if got := handler.resolveForClient(request, runtime, "192.0.2.4"); got.source != querylog.SourceBlocked {
		t.Fatalf("exact allowed subdomain source = %q, want blocked", got.source)
	}
	request.SetQuestion("trusted.ads.example.", dns.TypeA)
	if got := handler.resolveForClient(request, runtime, "192.0.2.4"); got.source != querylog.SourceBlocked {
		t.Fatalf("wildcard allowed apex source = %q, want blocked", got.source)
	}
	request.SetQuestion("cdn.trusted.ads.example.", dns.TypeA)
	if got := handler.resolveForClient(request, runtime, "192.0.2.4"); got.source != querylog.SourceUpstream {
		t.Fatalf("wildcard allowed subdomain source = %q, want upstream", got.source)
	}
	request.SetQuestion("deep.cdn.trusted.ads.example.", dns.TypeA)
	if got := handler.resolveForClient(request, runtime, "192.0.2.4"); got.source != querylog.SourceUpstream {
		t.Fatalf("wildcard allowed nested subdomain source = %q, want upstream", got.source)
	}
	request.SetQuestion("pixel.ads.example.", dns.TypeA)
	if got := handler.resolveForClient(request, runtime, "198.51.100.8"); got.source != querylog.SourceUpstream {
		t.Fatalf("bypass source = %q, want upstream", got.source)
	}

	handler.PauseBlocking(time.Minute)
	if !handler.BlockingPaused() {
		t.Fatal("BlockingPaused() = false after pause")
	}
	if got := handler.resolveForClient(request, runtime, "192.0.2.4"); got.source != querylog.SourceUpstream {
		t.Fatalf("paused source = %q, want upstream", got.source)
	}
	handler.ResumeBlocking()
	if handler.BlockingPaused() {
		t.Fatal("BlockingPaused() = true after resume")
	}

	request.SetQuestion("pixel.ads.example.", dns.TypeTXT)
	result = handler.resolveForClient(request, runtime, "192.0.2.4")
	if result.source != querylog.SourceBlocked || len(result.response.Answer) != 1 {
		t.Fatalf("TXT blocked result = source %q response %+v", result.source, result.response)
	}
	if txt, ok := result.response.Answer[0].(*dns.TXT); !ok || len(txt.Txt) != 1 || txt.Txt[0] != "blocked by Sable" {
		t.Fatalf("TXT blocking answer = %#v", result.response.Answer[0])
	}
}

func TestNXDomainBlockingCanReturnTXTReport(t *testing.T) {
	t.Parallel()

	configuration := testRuntimeConfig()
	configuration.Blocking = true
	configuration.BlockedDomains = []string{"ads.example"}
	configuration.BlockingType = "nxdomain"
	configuration.BlockingTTL = 30
	configuration.AllowTXTReport = true
	runtime, err := Compile(configuration)
	if err != nil {
		t.Fatalf("Compile() error = %v", err)
	}
	request := new(dns.Msg)
	request.SetQuestion("ads.example.", dns.TypeTXT)
	response := runtime.blockedResponse(request)
	if response.Rcode != dns.RcodeSuccess || len(response.Answer) != 1 {
		t.Fatalf("TXT response = %+v, want one report answer", response)
	}
}

func TestHandlerServesAndReportsCacheHit(t *testing.T) {
	t.Parallel()

	configuration := testRuntimeConfig()
	configuration.Forwarders = []string{"127.0.0.1:1"}
	runtime, err := Compile(configuration)
	if err != nil {
		t.Fatalf("Compile() error = %v", err)
	}
	request := cacheRequest("cached.example.", 10)
	if !runtime.cache.Set(request, positiveResponse(request, 60), true) {
		t.Fatal("cache Set() = false")
	}
	handler := NewHandler(runtime)
	collector := &eventCollector{events: make(chan querylog.Event, 1)}
	handler.SetQueryObserver(collector)
	lookup := cacheRequest("cached.example.", 20)
	capture := new(responseCapture)

	handler.ServeDNS(capture, lookup)
	event := <-collector.events
	if capture.message.Id != lookup.Id || len(capture.message.Answer) != 1 {
		t.Fatalf("cached response = %+v, want answer with request ID", capture.message)
	}
	if event.Source != querylog.SourceCache || event.Protocol != "UDP" || !strings.Contains(event.Answer, "A ") {
		t.Fatalf("event = %+v, want cached UDP answer", event)
	}
	if handler.Stats().CacheHits != 1 {
		t.Fatalf("CacheHits = %d, want 1", handler.Stats().CacheHits)
	}
}

func TestHandlerServesLocalHostOverridesBeforeBlocking(t *testing.T) {
	t.Parallel()

	configuration := testRuntimeConfig()
	configuration.Blocking = true
	configuration.BlockedDomains = []string{"router.home.arpa"}
	configuration.Hosts = []HostOverride{{
		Name: "router.home.arpa", Addresses: []string{"192.168.1.1", "fd00::1"}, TTL: 120,
	}}
	runtime, err := Compile(configuration)
	if err != nil {
		t.Fatalf("Compile() error = %v", err)
	}
	handler := NewHandler(runtime)
	handler.upstreamExchange = func(context.Context, *dns.Msg, string, time.Duration) (*dns.Msg, error) {
		t.Fatal("local query reached upstream")
		return nil, nil
	}
	collector := &eventCollector{events: make(chan querylog.Event, 1)}
	handler.SetQueryObserver(collector)
	request := new(dns.Msg)
	request.SetQuestion("Router.Home.Arpa.", dns.TypeANY)
	capture := new(responseCapture)

	handler.ServeDNS(capture, request)
	event := <-collector.events
	if capture.message.Rcode != dns.RcodeSuccess || len(capture.message.Answer) != 2 {
		t.Fatalf("local response = %+v, want A and AAAA answers", capture.message)
	}
	if capture.message.Answer[0].Header().Ttl != 120 || capture.message.Answer[1].Header().Ttl != 120 {
		t.Fatalf("local answer TTLs = %d, %d", capture.message.Answer[0].Header().Ttl, capture.message.Answer[1].Header().Ttl)
	}
	if event.Source != querylog.SourceLocal {
		t.Fatalf("event source = %q, want local", event.Source)
	}
	stats := handler.Stats()
	if stats.LocalAnswers != 1 || stats.LocalHosts != 1 || stats.Blocked != 0 || stats.NoError != 1 {
		t.Fatalf("stats = %+v", stats)
	}
}

func TestLocalHostOverrideReturnsNODATAForUnsupportedType(t *testing.T) {
	t.Parallel()

	configuration := testRuntimeConfig()
	configuration.Hosts = []HostOverride{{
		Name: "router.home.arpa", Addresses: []string{"192.168.1.1"}, TTL: 300,
	}}
	runtime, err := Compile(configuration)
	if err != nil {
		t.Fatalf("Compile() error = %v", err)
	}
	request := new(dns.Msg)
	request.SetQuestion("router.home.arpa.", dns.TypeTXT)
	response, found := runtime.localResponse(request)
	if !found || response.Rcode != dns.RcodeSuccess || len(response.Answer) != 0 {
		t.Fatalf("localResponse() = %+v, %v; want NODATA", response, found)
	}
}

func TestHandlerServesAuthoritativeZoneBeforeLocalPolicyAndUpstream(t *testing.T) {
	t.Parallel()

	configuration := testRuntimeConfig()
	configuration.Blocking = true
	configuration.BlockedDomains = []string{"example.test"}
	configuration.Hosts = []HostOverride{{Name: "www.example.test", Addresses: []string{"192.0.2.99"}, TTL: 60}}
	configuration.Zones = []AuthoritativeZone{{
		Name: "example.test",
		Records: []ZoneRecord{
			{Name: "@", Type: "SOA", TTL: 300, Value: "ns1.example.test. hostmaster.example.test. 2026080801 3600 600 1209600 300"},
			{Name: "@", Type: "NS", TTL: 300, Value: "ns1.example.test."},
			{Name: "www", Type: "A", TTL: 120, Value: "192.0.2.10"},
			{Name: "*", Type: "A", TTL: 60, Value: "192.0.2.20"},
			{Name: "_https._tcp", Type: "SRV", TTL: 300, Value: "1 2 443 service.example.test."},
		},
	}}
	runtime, err := Compile(configuration)
	if err != nil {
		t.Fatalf("Compile() error = %v", err)
	}
	handler := NewHandler(runtime)
	handler.upstreamExchange = func(context.Context, *dns.Msg, string, time.Duration) (*dns.Msg, error) {
		t.Fatal("authoritative query reached upstream")
		return nil, nil
	}
	collector := &eventCollector{events: make(chan querylog.Event, 1)}
	handler.SetQueryObserver(collector)
	request := new(dns.Msg)
	request.SetQuestion("www.example.test.", dns.TypeA)
	capture := new(responseCapture)

	handler.ServeDNS(capture, request)
	event := <-collector.events
	if !capture.message.Authoritative || capture.message.Rcode != dns.RcodeSuccess || len(capture.message.Answer) != 1 {
		t.Fatalf("authoritative response = %+v", capture.message)
	}
	if answer, ok := capture.message.Answer[0].(*dns.A); !ok || answer.A.String() != "192.0.2.10" || answer.Hdr.Ttl != 120 {
		t.Fatalf("answer = %#v", capture.message.Answer[0])
	}
	if event.Source != querylog.SourceAuthoritative {
		t.Fatalf("event source = %q, want authoritative", event.Source)
	}
	stats := handler.Stats()
	if stats.AuthoritativeAnswers != 1 || stats.Zones != 1 || stats.LocalAnswers != 0 || stats.Blocked != 0 {
		t.Fatalf("stats = %+v", stats)
	}

	request.SetQuestion("missing.example.test.", dns.TypeA)
	response, found := runtime.authoritativeResponse(request)
	if !found || !response.Authoritative || response.Rcode != dns.RcodeSuccess || len(response.Answer) != 1 {
		t.Fatalf("wildcard response = %+v, found=%v", response, found)
	}
	if response.Answer[0].Header().Name != "missing.example.test." {
		t.Fatalf("wildcard owner = %q", response.Answer[0].Header().Name)
	}

	request.SetQuestion("_https._tcp.example.test.", dns.TypeSRV)
	response, found = runtime.authoritativeResponse(request)
	if !found || len(response.Answer) != 1 {
		t.Fatalf("SRV response = %+v, found=%v", response, found)
	}
	if answer, ok := response.Answer[0].(*dns.SRV); !ok || answer.Port != 443 || answer.Target != "service.example.test." {
		t.Fatalf("SRV answer = %#v", response.Answer[0])
	}
}

func TestHandlerFlattensANAMEIntoAuthoritativeAddressAnswers(t *testing.T) {
	t.Parallel()

	configuration := testRuntimeConfig()
	configuration.Zones = []AuthoritativeZone{{
		Name: "example.test",
		Records: []ZoneRecord{
			{Name: "@", Type: "SOA", TTL: 300, Value: "ns1.example.test. hostmaster.example.test. 2026080801 3600 600 1209600 300"},
			{Name: "@", Type: "NS", TTL: 300, Value: "ns1.example.test."},
			{Name: "app", Type: "ANAME", TTL: 120, Value: "origin.example.net."},
		},
	}}
	runtime, err := Compile(configuration)
	if err != nil {
		t.Fatalf("Compile() error = %v", err)
	}
	handler := NewHandler(runtime)
	var upstreamCalls int
	handler.upstreamExchange = func(_ context.Context, request *dns.Msg, _ string, _ time.Duration) (*dns.Msg, error) {
		upstreamCalls++
		if request.Question[0].Name != "origin.example.net." {
			t.Fatalf("ANAME target query = %q", request.Question[0].Name)
		}
		response := new(dns.Msg)
		response.SetReply(request)
		response.Answer = append(response.Answer, &dns.A{
			Hdr: dns.RR_Header{Name: "origin.example.net.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 600},
			A:   net.ParseIP("192.0.2.80"),
		})
		return response, nil
	}
	request := new(dns.Msg)
	request.SetQuestion("app.example.test.", dns.TypeA)
	result := handler.resolve(request, runtime)
	if result.source != querylog.SourceAuthoritative || !result.response.Authoritative || len(result.response.Answer) != 1 {
		t.Fatalf("ANAME result = source %q response %+v", result.source, result.response)
	}
	answer, ok := result.response.Answer[0].(*dns.A)
	if !ok || answer.Hdr.Name != "app.example.test." || answer.Hdr.Ttl != 120 || answer.A.String() != "192.0.2.80" {
		t.Fatalf("flattened ANAME answer = %#v", result.response.Answer[0])
	}
	second := handler.resolve(request, runtime)
	if len(second.response.Answer) != 1 || upstreamCalls != 1 {
		t.Fatalf("cached ANAME response = %+v, upstream calls = %d", second.response, upstreamCalls)
	}

	request.SetQuestion("app.example.test.", dns.TypeTXT)
	noData, found := runtime.authoritativeResponse(request)
	if !found || noData.Rcode != dns.RcodeSuccess || len(noData.Answer) != 0 || len(noData.Ns) != 1 {
		t.Fatalf("ANAME NODATA response = %+v, found=%v", noData, found)
	}
}

func TestAuthoritativeFWDRecordRoutesSubtreeByPriority(t *testing.T) {
	t.Parallel()

	configuration := testRuntimeConfig()
	configuration.Zones = []AuthoritativeZone{{
		Name: "example.test",
		Records: []ZoneRecord{
			{Name: "@", Type: "SOA", TTL: 300, Value: "ns1.example.test. hostmaster.example.test. 2026080801 3600 600 1209600 300"},
			{Name: "@", Type: "NS", TTL: 300, Value: "ns1.example.test."},
			{Name: "corp", Type: "FWD", TTL: 300, Value: "tcp 20 192.0.2.53:53"},
			{Name: "corp", Type: "FWD", TTL: 300, Value: "udp 10 192.0.2.54:53"},
		},
	}}
	runtime, err := Compile(configuration)
	if err != nil {
		t.Fatalf("Compile() error = %v", err)
	}
	request := new(dns.Msg)
	request.SetQuestion("host.corp.example.test.", dns.TypeA)
	if response, found := runtime.authoritativeResponse(request); found || response != nil {
		t.Fatalf("forwarded subtree returned authoritative response %+v, found=%v", response, found)
	}
	forwarders, routed := runtime.forwardersFor(request.Question[0].Name)
	want := []string{"udp://192.0.2.54:53", "tcp://192.0.2.53:53"}
	if !routed || !slices.Equal(forwarders, want) {
		t.Fatalf("forwardersFor() = %v, %v; want %v", forwarders, routed, want)
	}
	handler := NewHandler(runtime)
	handler.upstreamExchange = func(_ context.Context, query *dns.Msg, forwarder string, _ time.Duration) (*dns.Msg, error) {
		if forwarder != want[0] {
			t.Fatalf("first FWD endpoint = %q", forwarder)
		}
		response := new(dns.Msg)
		response.SetReply(query)
		response.Answer = append(response.Answer, &dns.A{
			Hdr: dns.RR_Header{Name: query.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
			A:   net.ParseIP("192.0.2.90"),
		})
		return response, nil
	}
	result := handler.resolve(request, runtime)
	if result.source != querylog.SourceUpstream || len(result.response.Answer) != 1 || result.response.Authoritative {
		t.Fatalf("FWD result = source %q response %+v", result.source, result.response)
	}
}

func TestCompileSkipsDisabledAuthoritativeZones(t *testing.T) {
	t.Parallel()

	configuration := testRuntimeConfig()
	configuration.Zones = []AuthoritativeZone{{
		Name: "disabled.test", Disabled: true,
		Records: []ZoneRecord{
			{Name: "@", Type: "SOA", TTL: 300, Value: "ns1.disabled.test. hostmaster.disabled.test. 1 3600 600 1209600 300"},
			{Name: "@", Type: "NS", TTL: 300, Value: "ns1.disabled.test."},
		},
	}}
	runtime, err := Compile(configuration)
	if err != nil {
		t.Fatalf("Compile() error = %v", err)
	}
	request := new(dns.Msg)
	request.SetQuestion("disabled.test.", dns.TypeSOA)
	if response, found := runtime.authoritativeResponse(request); found || response != nil {
		t.Fatalf("disabled zone response = %+v, found=%v", response, found)
	}
	if len(runtime.zones) != 0 {
		t.Fatalf("disabled zone count = %d", len(runtime.zones))
	}
}

func TestAuthoritativeZoneReturnsSOAForNXDomainAndNODATA(t *testing.T) {
	t.Parallel()

	configuration := testRuntimeConfig()
	configuration.Zones = []AuthoritativeZone{{
		Name: "example.test",
		Records: []ZoneRecord{
			{Name: "@", Type: "SOA", TTL: 300, Value: "ns1.example.test. hostmaster.example.test. 2026080801 3600 600 1209600 300"},
			{Name: "@", Type: "NS", TTL: 300, Value: "ns1.example.test."},
			{Name: "www", Type: "A", TTL: 120, Value: "192.0.2.10"},
		},
	}}
	runtime, err := Compile(configuration)
	if err != nil {
		t.Fatalf("Compile() error = %v", err)
	}
	request := new(dns.Msg)
	request.SetQuestion("absent.example.test.", dns.TypeA)
	nxDomain, found := runtime.authoritativeResponse(request)
	if !found || nxDomain.Rcode != dns.RcodeNameError || len(nxDomain.Ns) != 1 {
		t.Fatalf("NXDOMAIN response = %+v, found=%v", nxDomain, found)
	}
	request.SetQuestion("www.example.test.", dns.TypeAAAA)
	noData, found := runtime.authoritativeResponse(request)
	if !found || noData.Rcode != dns.RcodeSuccess || len(noData.Answer) != 0 || len(noData.Ns) != 1 {
		t.Fatalf("NODATA response = %+v, found=%v", noData, found)
	}
}

func TestAuthoritativeZoneOmitsDisabledAndExpiredRecords(t *testing.T) {
	t.Parallel()

	configuration := testRuntimeConfig()
	configuration.Zones = []AuthoritativeZone{{
		Name: "example.test",
		Records: []ZoneRecord{
			{Name: "@", Type: "SOA", TTL: 300, Value: "ns1.example.test. hostmaster.example.test. 2026080801 3600 600 1209600 300"},
			{Name: "@", Type: "NS", TTL: 300, Value: "ns1.example.test."},
			{Name: "disabled", Type: "A", TTL: 60, Value: "192.0.2.10", Disabled: true},
			{Name: "expired", Type: "A", TTL: 60, Value: "192.0.2.11", ExpiresAt: time.Now().Add(-time.Minute)},
			{Name: "active", Type: "A", TTL: 60, Value: "192.0.2.12", ExpiresAt: time.Now().Add(time.Hour)},
		},
	}}
	runtime, err := Compile(configuration)
	if err != nil {
		t.Fatalf("Compile() error = %v", err)
	}
	for _, name := range []string{"disabled.example.test.", "expired.example.test."} {
		request := new(dns.Msg)
		request.SetQuestion(name, dns.TypeA)
		response, found := runtime.authoritativeResponse(request)
		if !found || response.Rcode != dns.RcodeNameError || len(response.Answer) != 0 {
			t.Fatalf("response for %s = %+v, found=%v; want NXDOMAIN", name, response, found)
		}
	}
	request := new(dns.Msg)
	request.SetQuestion("active.example.test.", dns.TypeA)
	response, found := runtime.authoritativeResponse(request)
	if !found || response.Rcode != dns.RcodeSuccess || len(response.Answer) != 1 {
		t.Fatalf("active response = %+v, found=%v", response, found)
	}
}

func TestHandlerActivationReplacesLocalOverridesAndKeepsCompatibleCache(t *testing.T) {
	t.Parallel()

	firstConfiguration := testRuntimeConfig()
	firstConfiguration.Hosts = []HostOverride{{
		Name: "old.home.arpa", Addresses: []string{"192.168.1.2"}, TTL: 300,
	}}
	first, err := Compile(firstConfiguration)
	if err != nil {
		t.Fatalf("Compile(first) error = %v", err)
	}
	secondConfiguration := testRuntimeConfig()
	secondConfiguration.Hosts = []HostOverride{{
		Name: "new.home.arpa", Addresses: []string{"192.168.1.3"}, TTL: 300,
	}}
	second, err := Compile(secondConfiguration)
	if err != nil {
		t.Fatalf("Compile(second) error = %v", err)
	}
	handler := NewHandler(first)
	handler.Activate(second)
	active := handler.runtime.Load()
	if _, found := active.localHostFor("old.home.arpa."); found {
		t.Fatal("old local override remained active")
	}
	if _, found := active.localHostFor("new.home.arpa."); !found {
		t.Fatal("new local override was not activated")
	}
	if active.cache != first.cache {
		t.Fatal("compatible local override reload discarded the warm cache")
	}
}

func TestRuntimeUsesLongestConditionalForwardingSuffix(t *testing.T) {
	t.Parallel()

	configuration := testRuntimeConfig()
	configuration.Routes = []ForwardingRoute{
		{Domain: "example", Forwarders: []string{"192.0.2.1:53"}},
		{Domain: "corp.example", Forwarders: []string{"192.0.2.2:53"}},
	}
	runtime, err := Compile(configuration)
	if err != nil {
		t.Fatalf("Compile() error = %v", err)
	}
	forwarders, routed := runtime.forwardersFor("service.dev.corp.example.")
	if !routed || len(forwarders) != 1 || forwarders[0] != "192.0.2.2:53" {
		t.Fatalf("forwardersFor() = %v, %v; want longest matching route", forwarders, routed)
	}
	forwarders, routed = runtime.forwardersFor("unrelated.test.")
	if routed || forwarders[0] != configuration.Forwarders[0] {
		t.Fatalf("forwardersFor(default) = %v, %v", forwarders, routed)
	}
}

func TestResolveCoalescesConcurrentCacheMisses(t *testing.T) {
	t.Parallel()

	configuration := testRuntimeConfig()
	configuration.Forwarders = []string{"192.0.2.1:53"}
	runtime, err := Compile(configuration)
	if err != nil {
		t.Fatalf("Compile() error = %v", err)
	}
	handler := NewHandler(runtime)

	var calls atomic.Int32
	entered := make(chan struct{}, 1)
	release := make(chan struct{})
	handler.upstreamExchange = func(_ context.Context, request *dns.Msg, _ string, _ time.Duration) (*dns.Msg, error) {
		calls.Add(1)
		select {
		case entered <- struct{}{}:
		default:
		}
		<-release
		return positiveResponse(request, 60), nil
	}

	// SetQuestion assigns a random id, so set the id afterwards to give each
	// caller a distinct, known id.
	makeRequest := func(id uint16) *dns.Msg {
		request := new(dns.Msg)
		request.SetQuestion("coalesce.example.", dns.TypeA)
		request.SetEdns0(dns.DefaultMsgSize, true)
		request.Id = id
		return request
	}

	const callers = 6
	responses := make([]resolution, callers)
	var wg sync.WaitGroup

	// The leader enters the upstream exchange first; the followers then coalesce
	// onto the in-flight resolution instead of each hitting the upstream.
	wg.Add(1)
	go func() {
		defer wg.Done()
		responses[0] = handler.resolveForClient(makeRequest(1), runtime, "")
	}()
	<-entered
	for index := 1; index < callers; index++ {
		wg.Add(1)
		go func(index int) {
			defer wg.Done()
			responses[index] = handler.resolveForClient(makeRequest(uint16(index+1)), runtime, "")
		}(index)
	}
	time.Sleep(30 * time.Millisecond)
	close(release)
	wg.Wait()

	if got := calls.Load(); got != 1 {
		t.Fatalf("upstream called %d times for %d concurrent identical misses, want 1", got, callers)
	}
	for index, result := range responses {
		if result.response == nil || len(result.response.Answer) != 1 {
			t.Fatalf("caller %d response = %+v, want one answer", index, result.response)
		}
		if want := uint16(index + 1); result.response.Id != want {
			t.Fatalf("caller %d response id = %d, want %d (its own request id)", index, result.response.Id, want)
		}
	}
}

func TestUpstreamHealthTrackerDeprioritizesFailedForwarder(t *testing.T) {
	t.Parallel()
	tracker := newUpstreamHealthTracker()
	now := time.Now()
	tracker.now = func() time.Time { return now }
	forwarders := []string{"a", "b", "c"}

	if got := tracker.order(forwarders, 1); !slices.Equal(got, []string{"b", "c", "a"}) {
		t.Fatalf("all-healthy order from start=1 = %v, want round-robin", got)
	}

	tracker.markUnhealthy("b")
	if got := tracker.order(forwarders, 0); !slices.Equal(got, []string{"a", "c", "b"}) {
		t.Fatalf("cooling order = %v, want the failed forwarder last", got)
	}

	now = now.Add(upstreamUnhealthyCooldown + time.Second)
	if got := tracker.order(forwarders, 0); !slices.Equal(got, []string{"a", "b", "c"}) {
		t.Fatalf("post-cooldown order = %v, want the recovered forwarder back in rotation", got)
	}

	tracker.markUnhealthy("a")
	tracker.markHealthy("a")
	if got := tracker.order(forwarders, 0); !slices.Equal(got, []string{"a", "b", "c"}) {
		t.Fatalf("after markHealthy = %v, want the cleared forwarder in rotation", got)
	}
}

func TestCompileNormalizesBlockedDomainsRegardlessOfCase(t *testing.T) {
	t.Parallel()
	configuration := testRuntimeConfig()
	configuration.Blocking = true
	// A canonical name takes the fast path; a mixed-case name still normalizes.
	configuration.BlockedDomains = []string{"blocked.example", "MixedCase.Example"}
	runtime, err := Compile(configuration)
	if err != nil {
		t.Fatalf("Compile() error = %v", err)
	}
	if !runtime.matchesBlocked("blocked.example") {
		t.Fatal("canonical blocked domain did not match")
	}
	if !runtime.matchesBlocked("mixedcase.example") {
		t.Fatal("mixed-case blocked domain was not normalized to match")
	}
}

func TestHandlerFailsOverToNextForwarder(t *testing.T) {
	t.Parallel()

	configuration := testRuntimeConfig()
	configuration.Forwarders = []string{"192.0.2.1:53", "192.0.2.2:53"}
	runtime, err := Compile(configuration)
	if err != nil {
		t.Fatalf("Compile() error = %v", err)
	}
	handler := NewHandler(runtime)
	var attempted []string
	handler.upstreamExchange = func(
		_ context.Context,
		request *dns.Msg,
		forwarder string,
		_ time.Duration,
	) (*dns.Msg, error) {
		attempted = append(attempted, forwarder)
		if forwarder == "192.0.2.1:53" {
			return nil, errors.New("unavailable")
		}
		return positiveResponse(request, 60), nil
	}
	request := cacheRequest("failover.example.", 1)
	result := handler.resolve(request, runtime)
	if result.response.Rcode != dns.RcodeSuccess || len(result.response.Answer) != 1 {
		t.Fatalf("resolve() response = %+v, want successful failover", result.response)
	}
	// The unreachable forwarder is retried once (a dropped packet is common on a
	// lossy path) before failover moves on to the next one.
	want := []string{"192.0.2.1:53", "192.0.2.1:53", "192.0.2.2:53"}
	if !slices.Equal(attempted, want) {
		t.Fatalf("attempted = %v, want %v", attempted, want)
	}
}

func TestHandlerFailsOverWhenTheFirstForwarderStalls(t *testing.T) {
	t.Parallel()

	// The failure this pins down only appears when the first forwarder fails by
	// going silent rather than by answering with an error: the pool used to share
	// one deadline, so a stalled upstream spent the whole query budget and every
	// later forwarder was dialed with no time left.
	configuration := testRuntimeConfig()
	configuration.Forwarders = []string{"192.0.2.1:53", "192.0.2.2:53"}
	configuration.Timeout = 300 * time.Millisecond
	runtime, err := Compile(configuration)
	if err != nil {
		t.Fatalf("Compile() error = %v", err)
	}
	handler := NewHandler(runtime)
	var mu sync.Mutex
	budgets := make(map[string]time.Duration)
	handler.upstreamExchange = func(
		ctx context.Context,
		request *dns.Msg,
		forwarder string,
		_ time.Duration,
	) (*dns.Msg, error) {
		deadline, bounded := ctx.Deadline()
		if !bounded {
			return nil, errors.New("attempt ran without a deadline")
		}
		mu.Lock()
		budgets[forwarder] = time.Until(deadline)
		mu.Unlock()
		if forwarder == "192.0.2.1:53" {
			<-ctx.Done()
			return nil, errors.New("read udp 192.0.2.1:53: i/o timeout")
		}
		return positiveResponse(request, 60), nil
	}
	request := cacheRequest("stalled.example.", 1)
	result := handler.resolve(request, runtime)
	if result.response.Rcode != dns.RcodeSuccess || len(result.response.Answer) != 1 {
		t.Fatalf("resolve() response = %+v, want the second forwarder to answer", result.response)
	}
	mu.Lock()
	defer mu.Unlock()
	if budgets["192.0.2.2:53"] < configuration.Timeout/4 {
		t.Fatalf("second forwarder had %v of the %v budget, want a usable share", budgets["192.0.2.2:53"], configuration.Timeout)
	}
}

func TestExchangeContextLeavesUntriedForwardersHealthy(t *testing.T) {
	t.Parallel()

	configuration := testRuntimeConfig()
	configuration.Forwarders = []string{"192.0.2.1:53", "192.0.2.2:53"}
	runtime, err := Compile(configuration)
	if err != nil {
		t.Fatalf("Compile() error = %v", err)
	}
	handler := NewHandler(runtime)
	handler.upstreamExchange = func(
		context.Context,
		*dns.Msg,
		string,
		time.Duration,
	) (*dns.Msg, error) {
		t.Error("a spent budget still sent a query upstream")
		return nil, errors.New("unexpected exchange")
	}
	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer cancel()
	_, err = handler.exchangeContext(ctx, cacheRequest("spent.example.", 1), runtime, configuration.Forwarders)
	if !errors.Is(err, errForwarderNotTried) {
		t.Fatalf("exchangeContext() error = %v, want it to report %v", err, errForwarderNotTried)
	}
	// Cooling down an endpoint that was never contacted would push a healthy
	// upstream to the back of the pool for the next ten seconds.
	if len(handler.upstreamHealth.retryAfter) != 0 {
		t.Fatalf("upstream cooldowns = %v, want none for forwarders that were never queried", handler.upstreamHealth.retryAfter)
	}
}

func BenchmarkBlockedLookup(b *testing.B) {
	configuration := testRuntimeConfig()
	configuration.Blocking = true
	configuration.BlockedDomains = []string{"ads.example"}
	runtime, err := Compile(configuration)
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	for b.Loop() {
		_ = runtime.matchesBlocked("pixel.telemetry.ads.example.")
	}
}

func BenchmarkConditionalForwardingLookup(b *testing.B) {
	configuration := testRuntimeConfig()
	configuration.Routes = []ForwardingRoute{
		{Domain: "example", Forwarders: []string{"192.0.2.1:53"}},
		{Domain: "corp.example", Forwarders: []string{"192.0.2.2:53"}},
	}
	runtime, err := Compile(configuration)
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	for b.Loop() {
		_, _ = runtime.forwardersFor("service.dev.corp.example.")
	}
}

func BenchmarkLocalHostLookup(b *testing.B) {
	configuration := testRuntimeConfig()
	configuration.Hosts = []HostOverride{{
		Name: "router.home.arpa", Addresses: []string{"192.168.1.1", "fd00::1"}, TTL: 300,
	}}
	runtime, err := Compile(configuration)
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	for b.Loop() {
		_, _ = runtime.localHostFor("router.home.arpa.")
	}
}

func BenchmarkAuthoritativeLookup(b *testing.B) {
	configuration := testRuntimeConfig()
	configuration.Zones = []AuthoritativeZone{{
		Name: "example.test",
		Records: []ZoneRecord{
			{Name: "@", Type: "SOA", TTL: 300, Value: "ns1.example.test. hostmaster.example.test. 2026080801 3600 600 1209600 300"},
			{Name: "@", Type: "NS", TTL: 300, Value: "ns1.example.test."},
			{Name: "api", Type: "A", TTL: 60, Value: "192.0.2.10"},
		},
	}}
	runtime, err := Compile(configuration)
	if err != nil {
		b.Fatal(err)
	}
	request := new(dns.Msg)
	request.SetQuestion("api.example.test.", dns.TypeA)
	b.ReportAllocs()
	for b.Loop() {
		_, _ = runtime.authoritativeResponse(request)
	}
}

func BenchmarkLocalHostResponse(b *testing.B) {
	configuration := testRuntimeConfig()
	configuration.Hosts = []HostOverride{{
		Name: "router.home.arpa", Addresses: []string{"192.168.1.1", "fd00::1"}, TTL: 300,
	}}
	runtime, err := Compile(configuration)
	if err != nil {
		b.Fatal(err)
	}
	request := new(dns.Msg)
	request.SetQuestion("router.home.arpa.", dns.TypeA)
	b.ReportAllocs()
	for b.Loop() {
		_, _ = runtime.localResponse(request)
	}
}

func BenchmarkBlockedLookupWithLargePolicy(b *testing.B) {
	const policySize = 100_000
	b.StopTimer()
	configuration := testRuntimeConfig()
	configuration.Blocking = true
	configuration.BlockedDomains = make([]string, 0, policySize)
	for index := range policySize {
		configuration.BlockedDomains = append(configuration.BlockedDomains, fmt.Sprintf("host-%d.example", index))
	}
	runtime, err := Compile(configuration)
	if err != nil {
		b.Fatal(err)
	}
	b.StartTimer()
	b.ReportAllocs()
	for b.Loop() {
		_ = runtime.matchesBlocked("pixel.host-99999.example.")
	}
}

func testRuntimeConfig() RuntimeConfig {
	return RuntimeConfig{
		Forwarders: []string{"127.0.0.1:53"},
		Timeout:    time.Second,
		CacheSize:  1_024,
	}
}

func TestCompileSelectsRFC5011OnlyForBundledAnchors(t *testing.T) {
	t.Parallel()
	configuration := testRuntimeConfig()
	configuration.DNSSECValidation = true
	configuration.DNSSECTrustAnchorUpdates = true
	runtime, err := Compile(configuration)
	if err != nil {
		t.Fatal(err)
	}
	if !runtime.managedTrustAnchors {
		t.Fatal("bundled anchors did not enable RFC 5011 management")
	}
	configuration.DNSSECTrustAnchors = []string{trustanchor.DefaultRootKSK2017}
	runtime, err = Compile(configuration)
	if err != nil {
		t.Fatal(err)
	}
	if runtime.managedTrustAnchors {
		t.Fatal("operator-provided anchor unexpectedly enabled RFC 5011 management")
	}
}

func TestApplyManagedTrustAnchorsKeepsCacheWhenAnchorsUnchanged(t *testing.T) {
	t.Parallel()
	configuration := testRuntimeConfig()
	configuration.DNSSECValidation = true
	configuration.DNSSECTrustAnchorUpdates = true
	runtime, err := Compile(configuration)
	if err != nil {
		t.Fatal(err)
	}
	handler := NewHandler(runtime)
	request := cacheRequest("example.com.", 1)
	if !runtime.cache.Set(request, positiveResponse(request, 300), true) {
		t.Fatal("failed to seed the response cache")
	}

	anchors := []string{trustanchor.DefaultRootKSK2017, trustanchor.DefaultRootKSK2024}
	handler.ApplyManagedTrustAnchors(anchors, false)
	if entries := handler.Stats().CacheEntries; entries != 1 {
		t.Fatalf("CacheEntries = %d after an unchanged refresh, want 1", entries)
	}

	handler.ApplyManagedTrustAnchors([]string{trustanchor.DefaultRootKSK2024}, false)
	if entries := handler.Stats().CacheEntries; entries != 0 {
		t.Fatalf("CacheEntries = %d after a changed anchor set, want 0", entries)
	}
}

func benchmarkCacheHitHandler(b *testing.B) (*Handler, *dns.Msg) {
	b.Helper()
	configuration := testRuntimeConfig()
	configuration.CacheSize = 10_000
	runtime, err := Compile(configuration)
	if err != nil {
		b.Fatal(err)
	}
	handler := NewHandler(runtime)
	request := cacheRequest("example.com.", 1)
	if !runtime.cache.Set(request, positiveResponse(request, 300), true) {
		b.Fatal("failed to seed the response cache")
	}
	return handler, request
}

// BenchmarkServeDNSCacheHit measures the whole per-query handler cost for a
// cache hit, which is the steady state the dnsperf comparison exercises.
func BenchmarkServeDNSCacheHit(b *testing.B) {
	handler, request := benchmarkCacheHitHandler(b)
	b.ReportAllocs()
	for b.Loop() {
		handler.ServeDNS(discardWriter{}, request)
	}
}

// BenchmarkServeDNSCacheHitParallel shows how the same path holds up once more
// than one reader is feeding it.
func BenchmarkServeDNSCacheHitParallel(b *testing.B) {
	handler, request := benchmarkCacheHitHandler(b)
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		local := request.Copy()
		for pb.Next() {
			handler.ServeDNS(discardWriter{}, local)
		}
	})
}

// BenchmarkWireRoundTrip measures what miekg/dns spends per query outside the
// handler: unpacking the request off the socket and packing the reply back.
// Read it against BenchmarkServeDNSCacheHit to see how much of a query never
// reaches Sable's own code.
func BenchmarkWireRoundTrip(b *testing.B) {
	request := cacheRequest("example.com.", 1)
	response := positiveResponse(request, 300)
	wire, err := request.Pack()
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	for b.Loop() {
		decoded := new(dns.Msg)
		if err := decoded.Unpack(wire); err != nil {
			b.Fatal(err)
		}
		if _, err := response.Pack(); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkSetReply(b *testing.B) {
	request := new(dns.Msg)
	request.SetQuestion("example.com.", dns.TypeA)
	b.ReportAllocs()
	for b.Loop() {
		response := new(dns.Msg)
		response.SetReply(request)
	}
}

func TestCompileAppliesZoneDNSSECValidationOptOut(t *testing.T) {
	t.Parallel()
	configuration := testRuntimeConfig()
	configuration.DNSSECValidation = true
	configuration.Zones = []AuthoritativeZone{
		{
			Name: "private.test", Type: "forwarder", DNSSECValidationDisabled: true,
			Records: []ZoneRecord{
				{Name: "@", Type: "SOA", TTL: 300, Value: "ns1.private.test. hostmaster.private.test. 1 3600 600 1209600 300"},
				{Name: "@", Type: "FWD", TTL: 300, Value: "udp 0 10.2.0.245"},
			},
		},
		{
			Name: "validated.test", Type: "forwarder",
			Records: []ZoneRecord{
				{Name: "@", Type: "SOA", TTL: 300, Value: "ns1.validated.test. hostmaster.validated.test. 1 3600 600 1209600 300"},
				{Name: "@", Type: "FWD", TTL: 300, Value: "udp 0 192.0.2.53"},
			},
		},
	}
	runtime, err := Compile(configuration)
	if err != nil {
		t.Fatal(err)
	}
	if !runtime.dnssec.hasNegativeTrustAnchor("host.private.test.") {
		t.Fatal("forwarder zone opt-out did not reach the validator")
	}
	if runtime.dnssec.hasNegativeTrustAnchor("host.validated.test.") {
		t.Fatal("validation was disabled for a zone that did not ask for it")
	}
}

func TestCompileRejectsDNSSECValidationOptOutOnPrimaryZone(t *testing.T) {
	t.Parallel()
	configuration := testRuntimeConfig()
	configuration.Zones = []AuthoritativeZone{
		{
			Name: "example.test", Type: "primary", DNSSECValidationDisabled: true,
			Records: []ZoneRecord{
				{Name: "@", Type: "SOA", TTL: 300, Value: "ns1.example.test. hostmaster.example.test. 1 3600 600 1209600 300"},
				{Name: "@", Type: "NS", TTL: 300, Value: "ns1.example.test."},
			},
		},
	}
	if _, err := Compile(configuration); err == nil {
		t.Fatal("Compile() accepted a DNSSEC validation opt-out on a primary zone")
	}
}

func TestActivateZonesUpdatesDNSSECValidationOptOut(t *testing.T) {
	t.Parallel()
	configuration := testRuntimeConfig()
	configuration.DNSSECValidation = true
	runtime, err := Compile(configuration)
	if err != nil {
		t.Fatal(err)
	}
	handler := NewHandler(runtime)
	zones := []AuthoritativeZone{{
		Name: "private.test", Type: "forwarder", DNSSECValidationDisabled: true,
		Records: []ZoneRecord{
			{Name: "@", Type: "SOA", TTL: 300, Value: "ns1.private.test. hostmaster.private.test. 1 3600 600 1209600 300"},
			{Name: "@", Type: "FWD", TTL: 300, Value: "udp 0 10.2.0.245"},
		},
	}}
	if err := handler.ActivateZones(zones, nil); err != nil {
		t.Fatal(err)
	}
	active := handler.runtime.Load()
	if !active.dnssec.hasNegativeTrustAnchor("host.private.test.") {
		t.Fatal("zone activation did not apply the DNSSEC validation opt-out")
	}
	zones[0].DNSSECValidationDisabled = false
	if err := handler.ActivateZones(zones, nil); err != nil {
		t.Fatal(err)
	}
	active = handler.runtime.Load()
	if active.dnssec.hasNegativeTrustAnchor("host.private.test.") {
		t.Fatal("re-enabling validation left the zone marked insecure")
	}
}

func TestHandlerTransfersCatalogZonesButRefusesQueries(t *testing.T) {
	t.Parallel()

	configuration := testRuntimeConfig()
	configuration.Zones = []AuthoritativeZone{{
		Name: "catalog.invalid", Type: "catalog",
		ZoneTransfer: "acl", TransferACL: []string{"192.0.2.0/24"},
		Records: []ZoneRecord{
			{Name: "@", Type: "SOA", TTL: 0, Value: "invalid. invalid. 2026081701 3600 600 1209600 0"},
			{Name: "@", Type: "NS", TTL: 0, Value: "invalid."},
			{Name: "version", Type: "TXT", TTL: 0, Value: `"2"`},
			{Name: "nj2xg5b.zones", Type: "PTR", TTL: 0, Value: "example.test."},
		},
	}}
	runtime, err := Compile(configuration)
	if err != nil {
		t.Fatalf("Compile() error = %v", err)
	}
	handler := NewHandler(runtime)

	transfer := new(dns.Msg)
	transfer.SetAxfr("catalog.invalid.")
	authorized := &transferCapture{remote: &net.TCPAddr{IP: net.ParseIP("192.0.2.44"), Port: 53000}}
	handler.ServeDNS(authorized, transfer)

	var transferred []dns.RR
	for _, message := range authorized.messages {
		transferred = append(transferred, message.Answer...)
	}
	if !slices.ContainsFunc(transferred, func(record dns.RR) bool {
		return record.Header().Rrtype == dns.TypePTR && record.Header().Name == "nj2xg5b.zones.catalog.invalid."
	}) {
		t.Fatalf("catalog AXFR records = %v, want the member PTR record", transferred)
	}

	// RFC 9432 catalogs are transferred, never resolved. Answering would hand
	// any client the list of every zone the fleet serves.
	for _, name := range []string{"catalog.invalid.", "version.catalog.invalid.", "nj2xg5b.zones.catalog.invalid."} {
		query := new(dns.Msg)
		query.SetQuestion(name, dns.TypeTXT)
		capture := new(responseCapture)
		handler.ServeDNS(capture, query)
		if capture.message == nil || capture.message.Rcode != dns.RcodeRefused {
			t.Fatalf("query for %s = %+v, want REFUSED", name, capture.message)
		}
	}
}

func TestHandlerSkipsCatalogMembersAwaitingTransfer(t *testing.T) {
	t.Parallel()

	configuration := testRuntimeConfig()
	configuration.Zones = []AuthoritativeZone{{
		Name: "member.test", Type: "secondary", AwaitingTransfer: true,
		PrimaryServers: []string{"192.0.2.53"}, PrimaryProtocol: "tcp",
	}}
	if _, err := Compile(configuration); err != nil {
		t.Fatalf("a member awaiting its first transfer must compile, got %v", err)
	}
}

func TestAuthoritativeZoneChasesCNAMEChainIntoAnswer(t *testing.T) {
	t.Parallel()

	configuration := testRuntimeConfig()
	configuration.Zones = []AuthoritativeZone{{
		Name: "example.test",
		Records: []ZoneRecord{
			{Name: "@", Type: "SOA", TTL: 300, Value: "ns1.example.test. hostmaster.example.test. 2026080801 3600 600 1209600 300"},
			{Name: "@", Type: "NS", TTL: 300, Value: "ns1.example.test."},
			{Name: "host", Type: "A", TTL: 120, Value: "192.0.2.10"},
			{Name: "host", Type: "AAAA", TTL: 120, Value: "2001:db8::10"},
			{Name: "id", Type: "CNAME", TTL: 900, Value: "host.example.test."},
			{Name: "hop", Type: "CNAME", TTL: 900, Value: "id.example.test."},
			{Name: "dangling", Type: "CNAME", TTL: 900, Value: "absent.example.test."},
			{Name: "elsewhere", Type: "CNAME", TTL: 900, Value: "target.offsite.invalid."},
			{Name: "loop-a", Type: "CNAME", TTL: 900, Value: "loop-b.example.test."},
			{Name: "loop-b", Type: "CNAME", TTL: 900, Value: "loop-a.example.test."},
		},
	}}
	runtime, err := Compile(configuration)
	if err != nil {
		t.Fatalf("Compile() error = %v", err)
	}

	ask := func(name string, recordType uint16) *dns.Msg {
		t.Helper()
		request := new(dns.Msg)
		request.SetQuestion(name, recordType)
		response, found := runtime.authoritativeResponse(request)
		if !found {
			t.Fatalf("authoritativeResponse(%s) not answered locally", name)
		}
		return response
	}

	// The reported bug: a lone CNAME answer makes glibc and Go report "no such
	// host", so the address has to arrive in the same reply.
	single := ask("id.example.test.", dns.TypeA)
	if single.Rcode != dns.RcodeSuccess || len(single.Answer) != 2 {
		t.Fatalf("id answer = %+v; want CNAME plus A", single.Answer)
	}
	if _, ok := single.Answer[0].(*dns.CNAME); !ok {
		t.Fatalf("id answer[0] = %T; want *dns.CNAME", single.Answer[0])
	}
	address, ok := single.Answer[1].(*dns.A)
	if !ok || address.A.String() != "192.0.2.10" {
		t.Fatalf("id answer[1] = %v; want A 192.0.2.10", single.Answer[1])
	}

	// Chasing must follow the requested type, not stop at the first address.
	sixSingle := ask("id.example.test.", dns.TypeAAAA)
	if len(sixSingle.Answer) != 2 {
		t.Fatalf("id AAAA answer = %+v; want CNAME plus AAAA", sixSingle.Answer)
	}
	if _, ok := sixSingle.Answer[1].(*dns.AAAA); !ok {
		t.Fatalf("id AAAA answer[1] = %T; want *dns.AAAA", sixSingle.Answer[1])
	}

	multi := ask("hop.example.test.", dns.TypeA)
	if multi.Rcode != dns.RcodeSuccess || len(multi.Answer) != 3 {
		t.Fatalf("hop answer = %+v; want two CNAMEs plus A", multi.Answer)
	}

	// A CNAME query still answers with just the alias, chain untouched.
	alias := ask("hop.example.test.", dns.TypeCNAME)
	if len(alias.Answer) != 1 {
		t.Fatalf("hop CNAME answer = %+v; want the alias alone", alias.Answer)
	}

	// RFC 6604: the rcode belongs to the last name in the chain.
	dangling := ask("dangling.example.test.", dns.TypeA)
	if dangling.Rcode != dns.RcodeNameError || len(dangling.Answer) != 1 || len(dangling.Ns) != 1 {
		t.Fatalf("dangling answer = %+v ns = %+v rcode = %d; want NXDOMAIN with the alias kept", dangling.Answer, dangling.Ns, dangling.Rcode)
	}

	// Off-zone targets stay the querying resolver's problem.
	offsite := ask("elsewhere.example.test.", dns.TypeA)
	if offsite.Rcode != dns.RcodeSuccess || len(offsite.Answer) != 1 {
		t.Fatalf("offsite answer = %+v; want the alias alone", offsite.Answer)
	}

	// A loop must terminate without repeating hops forever.
	loop := ask("loop-a.example.test.", dns.TypeA)
	if loop.Rcode != dns.RcodeSuccess || len(loop.Answer) != 2 {
		t.Fatalf("loop answer = %+v; want the two aliases and nothing more", loop.Answer)
	}
}

func TestAuthoritativeZoneChasesCNAMEIntoNoDataAndWildcards(t *testing.T) {
	t.Parallel()

	configuration := testRuntimeConfig()
	configuration.Zones = []AuthoritativeZone{{
		Name: "example.test",
		Records: []ZoneRecord{
			{Name: "@", Type: "SOA", TTL: 300, Value: "ns1.example.test. hostmaster.example.test. 2026080801 3600 600 1209600 300"},
			{Name: "@", Type: "NS", TTL: 300, Value: "ns1.example.test."},
			{Name: "sixonly", Type: "AAAA", TTL: 120, Value: "2001:db8::20"},
			{Name: "nodata", Type: "CNAME", TTL: 900, Value: "sixonly.example.test."},
			{Name: "*.wild", Type: "A", TTL: 120, Value: "192.0.2.30"},
			{Name: "star", Type: "CNAME", TTL: 900, Value: "anything.wild.example.test."},
		},
	}}
	runtime, err := Compile(configuration)
	if err != nil {
		t.Fatalf("Compile() error = %v", err)
	}

	request := new(dns.Msg)
	request.SetQuestion("nodata.example.test.", dns.TypeA)
	noData, found := runtime.authoritativeResponse(request)
	if !found || noData.Rcode != dns.RcodeSuccess || len(noData.Answer) != 1 {
		t.Fatalf("nodata answer = %+v found = %v; want NOERROR with the alias alone", noData, found)
	}

	request.SetQuestion("star.example.test.", dns.TypeA)
	wild, found := runtime.authoritativeResponse(request)
	if !found || wild.Rcode != dns.RcodeSuccess || len(wild.Answer) != 2 {
		t.Fatalf("wildcard answer = %+v found = %v; want CNAME plus the expanded A", wild, found)
	}
	expanded, ok := wild.Answer[1].(*dns.A)
	if !ok || expanded.Hdr.Name != "anything.wild.example.test." || expanded.A.String() != "192.0.2.30" {
		t.Fatalf("wildcard answer[1] = %v; want A 192.0.2.30 owned by the chased name", wild.Answer[1])
	}
}

func TestExchangeWithRetriesReportsExpiredContextInsteadOfEmptyResult(t *testing.T) {
	t.Parallel()
	runtime, err := Compile(testRuntimeConfig())
	if err != nil {
		t.Fatal(err)
	}
	handler := NewHandler(runtime)
	attempts := 0
	handler.upstreamExchange = func(context.Context, *dns.Msg, string, time.Duration) (*dns.Msg, error) {
		attempts++
		return nil, nil
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	request := new(dns.Msg)
	request.SetQuestion("example.com.", dns.TypeA)
	response, err := handler.exchangeWithRetries(ctx, request, "udp://127.0.0.1:53", time.Second, 2)
	if response != nil {
		t.Fatalf("expired context returned a response: %+v", response)
	}
	if err == nil {
		t.Fatal("expired context returned no error, which hands callers a nil response and a nil error")
	}
	if attempts != 0 {
		t.Fatalf("expired context still queried the upstream %d times", attempts)
	}
}

func TestExchangeWithRetriesRejectsEmptyUpstreamResult(t *testing.T) {
	t.Parallel()
	runtime, err := Compile(testRuntimeConfig())
	if err != nil {
		t.Fatal(err)
	}
	handler := NewHandler(runtime)
	handler.upstreamExchange = func(context.Context, *dns.Msg, string, time.Duration) (*dns.Msg, error) {
		return nil, nil
	}

	request := new(dns.Msg)
	request.SetQuestion("example.com.", dns.TypeA)
	response, err := handler.exchangeWithRetries(context.Background(), request, "udp://127.0.0.1:53", time.Second, 1)
	if response != nil || err == nil {
		t.Fatalf("empty upstream result = (%+v, %v), want (nil, error)", response, err)
	}
}

func TestResolveUpstreamWithValidationSurvivesEmptyUpstreamResult(t *testing.T) {
	t.Parallel()
	configuration := testRuntimeConfig()
	configuration.DNSSECValidation = true
	runtime, err := Compile(configuration)
	if err != nil {
		t.Fatal(err)
	}
	if runtime.dnssec == nil {
		t.Fatal("DNSSEC validation did not compile a validator")
	}
	handler := NewHandler(runtime)
	handler.upstreamExchange = func(context.Context, *dns.Msg, string, time.Duration) (*dns.Msg, error) {
		return nil, nil
	}

	request := new(dns.Msg)
	request.SetQuestion("example.com.", dns.TypeA)
	response, state, err := handler.resolveUpstream(request, runtime, []string{"udp://127.0.0.1:53"})
	if response != nil {
		t.Fatalf("empty upstream result returned a response: %+v", response)
	}
	if err == nil {
		t.Fatal("empty upstream result returned no error")
	}
	if state != validationIndeterminate {
		t.Fatalf("validation state = %v, want indeterminate", state)
	}
}
