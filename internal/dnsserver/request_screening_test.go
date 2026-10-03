package dnsserver

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/quic-go/quic-go"
)

// screenedReply is what a client sees for one request: no reply at all, or a
// reply with this header.
type screenedReply struct {
	replied bool
	id      uint16
	opcode  int
	rcode   int
}

func screeningCases() []struct {
	name    string
	request func() *dns.Msg
	reached bool
} {
	query := func() *dns.Msg {
		request := new(dns.Msg)
		request.SetQuestion("example.com.", dns.TypeA)
		request.Id = 0
		return request
	}
	return []struct {
		name    string
		request func() *dns.Msg
		reached bool
	}{
		{name: "query", request: query, reached: true},
		{name: "response", request: func() *dns.Msg {
			request := query()
			request.Response = true
			return request
		}},
		{name: "two questions", request: func() *dns.Msg {
			request := query()
			request.Question = append(request.Question, dns.Question{Name: "example.net.", Qtype: dns.TypeA, Qclass: dns.ClassINET})
			return request
		}},
		{name: "no question", request: func() *dns.Msg {
			request := query()
			request.Question = nil
			return request
		}},
		{name: "status opcode", request: func() *dns.Msg {
			request := query()
			request.Opcode = dns.OpcodeStatus
			return request
		}},
		{name: "authority records", request: func() *dns.Msg {
			request := query()
			for _, address := range []string{"192.0.2.1", "192.0.2.2"} {
				request.Ns = append(request.Ns, &dns.A{
					Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
					A:   net.ParseIP(address),
				})
			}
			return request
		}},
		{name: "dynamic update", request: func() *dns.Msg {
			request := new(dns.Msg)
			request.SetUpdate("example.com.")
			request.Id = 0
			request.Insert([]dns.RR{&dns.A{
				Hdr: dns.RR_Header{Name: "www.example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
				A:   net.ParseIP("192.0.2.1"),
			}})
			return request
		}, reached: true},
	}
}

func replyHeader(message *dns.Msg) screenedReply {
	return screenedReply{replied: true, id: message.Id, opcode: message.Opcode, rcode: message.Rcode}
}

// TestDoHAndDoQScreenHeadersLikeUDP sends the same requests to a UDP server
// configured as openUDP configures it, to the DoH handler, and to a DoQ
// listener, and expects the same outcome from all three.
func TestDoHAndDoQScreenHeadersLikeUDP(t *testing.T) {
	t.Parallel()

	var reached atomic.Int64
	handler := dns.HandlerFunc(func(writer dns.ResponseWriter, request *dns.Msg) {
		reached.Add(1)
		response := new(dns.Msg)
		response.SetReply(request)
		_ = writer.WriteMsg(response)
	})

	packets, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	started := make(chan struct{})
	udpServer := &dns.Server{
		PacketConn: packets, Handler: handler, UDPSize: udpReadBufferSize,
		MsgAcceptFunc: acceptRequestHeader, NotifyStartedFunc: func() { close(started) },
	}
	go func() { _ = udpServer.ActivateAndServe() }()
	t.Cleanup(func() { _ = udpServer.Shutdown() })
	<-started

	dohHandler := NewDoHHandler(handler)
	doqAddress, pool := startTestDoQListener(t, handler)
	doqConnection := dialTestDoQ(t, doqAddress, pool)

	for _, test := range screeningCases() {
		wire, err := test.request().Pack()
		if err != nil {
			t.Fatalf("%s: Pack() error = %v", test.name, err)
		}
		before := reached.Load()
		udp := exchangeUDPForScreening(t, packets.LocalAddr().String(), wire)
		doh := exchangeDoHForScreening(t, dohHandler, wire)
		doq := exchangeDoQForScreening(t, doqConnection, wire)
		if udp != doh || udp != doq {
			t.Errorf("%s: UDP %+v, DoH %+v, DoQ %+v; want all three equal", test.name, udp, doh, doq)
		}
		wantReached := int64(0)
		if test.reached {
			wantReached = 3
		}
		if got := reached.Load() - before; got != wantReached {
			t.Errorf("%s: handler ran %d times, want %d", test.name, got, wantReached)
		}
	}
}

func exchangeUDPForScreening(t *testing.T, address string, wire []byte) screenedReply {
	t.Helper()
	connection, err := net.Dial("udp", address)
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	if _, err := connection.Write(wire); err != nil {
		t.Fatal(err)
	}
	// An ignored request gets no reply, so only a deadline can show it.
	_ = connection.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	buffer := make([]byte, 4096)
	read, err := connection.Read(buffer)
	if isTimeout(err) {
		return screenedReply{}
	}
	if err != nil {
		t.Fatal(err)
	}
	response := new(dns.Msg)
	if err := response.Unpack(buffer[:read]); err != nil {
		t.Fatal(err)
	}
	return replyHeader(response)
}

func isTimeout(err error) bool {
	var netErr net.Error
	return errors.As(err, &netErr) && netErr.Timeout()
}

func exchangeDoHForScreening(t *testing.T, handler http.Handler, wire []byte) screenedReply {
	t.Helper()
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, dohPOSTRequest(wire))
	if recorder.Code == http.StatusBadRequest {
		return screenedReply{}
	}
	if recorder.Code != http.StatusOK {
		t.Fatalf("DoH status = %d", recorder.Code)
	}
	response := new(dns.Msg)
	if err := response.Unpack(recorder.Body.Bytes()); err != nil {
		t.Fatal(err)
	}
	return replyHeader(response)
}

func exchangeDoQForScreening(t *testing.T, connection *quic.Conn, wire []byte) screenedReply {
	t.Helper()
	stream, err := connection.OpenStreamSync(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	writeTestDoQMessage(t, stream, wire)
	_ = stream.SetReadDeadline(time.Now().Add(5 * time.Second))
	responseWire, err := readDoQMessage(stream)
	if errors.Is(err, io.EOF) {
		return screenedReply{}
	}
	if err != nil {
		t.Fatal(err)
	}
	response := new(dns.Msg)
	if err := response.Unpack(responseWire); err != nil {
		t.Fatal(err)
	}
	return replyHeader(response)
}

func TestDoHReportsSignedRequestsAsUnverified(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		signed bool
	}{{name: "unsigned"}, {name: "signed", signed: true}}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var status error
			handler := NewDoHHandler(dns.HandlerFunc(func(writer dns.ResponseWriter, request *dns.Msg) {
				status = writer.TsigStatus()
				answerExampleQuery(writer, request)
			}))
			request := new(dns.Msg)
			request.SetQuestion("example.com.", dns.TypeA)
			if test.signed {
				request.SetTsig("transfer.", dns.HmacSHA256, 300, time.Now().Unix())
			}
			wire, err := request.Pack()
			if err != nil {
				t.Fatal(err)
			}
			recorder := httptest.NewRecorder()
			handler.ServeHTTP(recorder, dohPOSTRequest(wire))
			if recorder.Code != http.StatusOK {
				t.Fatalf("status = %d, want 200", recorder.Code)
			}
			if test.signed && status == nil {
				t.Fatal("TsigStatus() = nil for a TSIG request nothing verified")
			}
			if !test.signed && status != nil {
				t.Fatalf("TsigStatus() = %v for an unsigned request", status)
			}
		})
	}
}
