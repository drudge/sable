package dnsserver

import (
	"bytes"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/miekg/dns"
)

func TestDoHHandlesWireFormatPOSTAndGET(t *testing.T) {
	t.Parallel()

	handler := NewDoHHandler(dns.HandlerFunc(answerExampleQuery))
	query := new(dns.Msg)
	query.SetQuestion("example.com.", dns.TypeA)
	wire, err := query.Pack()
	if err != nil {
		t.Fatalf("Pack() error = %v", err)
	}

	tests := []struct {
		name    string
		request *http.Request
	}{
		{
			name: "POST",
			request: func() *http.Request {
				request := httptest.NewRequest(http.MethodPost, dohPath, bytes.NewReader(wire))
				request.Header.Set("Content-Type", dohContentType)
				return request
			}(),
		},
		{
			name: "GET",
			request: httptest.NewRequest(
				http.MethodGet,
				dohPath+"?dns="+base64.RawURLEncoding.EncodeToString(wire),
				nil,
			),
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, test.request)
			if response.Code != http.StatusOK {
				t.Fatalf("status = %d, want 200: %s", response.Code, response.Body.String())
			}
			if response.Header().Get("Content-Type") != dohContentType {
				t.Fatalf("Content-Type = %q", response.Header().Get("Content-Type"))
			}
			if response.Header().Get("Cache-Control") != "public, max-age=60" {
				t.Fatalf("Cache-Control = %q", response.Header().Get("Cache-Control"))
			}
			message := new(dns.Msg)
			if err := message.Unpack(response.Body.Bytes()); err != nil {
				t.Fatalf("Unpack() error = %v", err)
			}
			if message.Id != query.Id || len(message.Answer) != 1 {
				t.Fatalf("response = %+v, want matching response with one answer", message)
			}
		})
	}
}

func TestDoHRejectsInvalidRequests(t *testing.T) {
	t.Parallel()

	handler := NewDoHHandler(dns.HandlerFunc(answerExampleQuery))
	tests := []struct {
		name        string
		request     *http.Request
		wantStatus  int
		wantAllowed string
	}{
		{
			name:        "method",
			request:     httptest.NewRequest(http.MethodPut, dohPath, nil),
			wantStatus:  http.StatusMethodNotAllowed,
			wantAllowed: "GET, POST",
		},
		{
			name:       "content type",
			request:    httptest.NewRequest(http.MethodPost, dohPath, bytes.NewReader([]byte("dns"))),
			wantStatus: http.StatusUnsupportedMediaType,
		},
		{
			name:       "malformed wire",
			request:    dohPOSTRequest([]byte("not a DNS message")),
			wantStatus: http.StatusBadRequest,
		},
		{
			name:       "malformed GET",
			request:    httptest.NewRequest(http.MethodGet, dohPath+"?dns=!", nil),
			wantStatus: http.StatusBadRequest,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, test.request)
			if response.Code != test.wantStatus {
				t.Fatalf("status = %d, want %d", response.Code, test.wantStatus)
			}
			if response.Header().Get("Allow") != test.wantAllowed {
				t.Fatalf("Allow = %q, want %q", response.Header().Get("Allow"), test.wantAllowed)
			}
		})
	}
}

func answerExampleQuery(writer dns.ResponseWriter, request *dns.Msg) {
	response := new(dns.Msg)
	response.SetReply(request)
	response.Answer = []dns.RR{&dns.A{
		Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
		A:   []byte{192, 0, 2, 1},
	}}
	_ = writer.WriteMsg(response)
}

func dohPOSTRequest(wire []byte) *http.Request {
	request := httptest.NewRequest(http.MethodPost, dohPath, bytes.NewReader(wire))
	request.Header.Set("Content-Type", dohContentType)
	return request
}
