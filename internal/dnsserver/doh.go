package dnsserver

import (
	"encoding/base64"
	"errors"
	"io"
	"mime"
	"net"
	"net/http"
	"strconv"

	"github.com/miekg/dns"
)

const (
	dohPath        = "/dns-query"
	dohContentType = "application/dns-message"
	dohMaximumSize = 65_535
)

func NewDoHHandler(handler dns.Handler) http.Handler {
	mux := http.NewServeMux()
	mux.Handle(dohPath, &dohHandler{dnsHandler: handler})
	return mux
}

type dohHandler struct {
	dnsHandler dns.Handler
}

func (handler *dohHandler) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	wire, err := readDoHRequest(writer, request)
	if err != nil {
		writeDoHError(writer, err)
		return
	}
	message := new(dns.Msg)
	if err := message.Unpack(wire); err != nil {
		http.Error(writer, "invalid DNS message", http.StatusBadRequest)
		return
	}

	response := newDoHResponseWriter(request)
	handler.dnsHandler.ServeDNS(response, message)
	packed, err := response.pack()
	if err != nil {
		http.Error(writer, "DNS handler did not produce a valid response", http.StatusInternalServerError)
		return
	}
	writer.Header().Set("Content-Type", dohContentType)
	writer.Header().Set("Cache-Control", response.httpCacheControl())
	writer.Header().Set("X-Content-Type-Options", "nosniff")
	writer.WriteHeader(http.StatusOK)
	_, _ = writer.Write(packed)
}

var (
	errDoHMethod      = errors.New("DNS-over-HTTPS requires GET or POST")
	errDoHContentType = errors.New("DNS-over-HTTPS POST requires application/dns-message")
	errDoHMissingData = errors.New("DNS-over-HTTPS GET requires the dns query parameter")
)

func readDoHRequest(writer http.ResponseWriter, request *http.Request) ([]byte, error) {
	switch request.Method {
	case http.MethodGet:
		encoded := request.URL.Query().Get("dns")
		if encoded == "" {
			return nil, errDoHMissingData
		}
		wire, err := base64.RawURLEncoding.DecodeString(encoded)
		if err != nil || len(wire) > dohMaximumSize {
			return nil, errors.New("invalid DNS-over-HTTPS query parameter")
		}
		return wire, nil
	case http.MethodPost:
		mediaType, _, err := mime.ParseMediaType(request.Header.Get("Content-Type"))
		if err != nil || mediaType != dohContentType {
			return nil, errDoHContentType
		}
		request.Body = http.MaxBytesReader(writer, request.Body, dohMaximumSize)
		wire, err := io.ReadAll(request.Body)
		if err != nil {
			return nil, errors.New("invalid DNS-over-HTTPS request body")
		}
		return wire, nil
	default:
		return nil, errDoHMethod
	}
}

func writeDoHError(writer http.ResponseWriter, err error) {
	status := http.StatusBadRequest
	if errors.Is(err, errDoHMethod) {
		writer.Header().Set("Allow", "GET, POST")
		status = http.StatusMethodNotAllowed
	} else if errors.Is(err, errDoHContentType) {
		status = http.StatusUnsupportedMediaType
	}
	http.Error(writer, err.Error(), status)
}

type dohResponseWriter struct {
	localAddress  net.Addr
	remoteAddress net.Addr
	message       *dns.Msg
	wire          []byte
}

func newDoHResponseWriter(request *http.Request) *dohResponseWriter {
	localAddress, _ := request.Context().Value(http.LocalAddrContextKey).(net.Addr)
	return &dohResponseWriter{
		localAddress:  localAddress,
		remoteAddress: parseRemoteAddress(request.RemoteAddr),
	}
}

func (writer *dohResponseWriter) LocalAddr() net.Addr  { return writer.localAddress }
func (writer *dohResponseWriter) RemoteAddr() net.Addr { return writer.remoteAddress }

func (writer *dohResponseWriter) WriteMsg(message *dns.Msg) error {
	writer.message = message.Copy()
	writer.wire = nil
	return nil
}

func (writer *dohResponseWriter) Write(wire []byte) (int, error) {
	writer.wire = append(writer.wire[:0], wire...)
	writer.message = nil
	return len(wire), nil
}

func (writer *dohResponseWriter) Close() error        { return nil }
func (writer *dohResponseWriter) TsigStatus() error   { return nil }
func (writer *dohResponseWriter) TsigTimersOnly(bool) {}
func (writer *dohResponseWriter) Hijack()             {}

func (writer *dohResponseWriter) pack() ([]byte, error) {
	if writer.message != nil {
		return writer.message.Pack()
	}
	if len(writer.wire) == 0 {
		return nil, errors.New("empty DNS response")
	}
	return writer.wire, nil
}

func (writer *dohResponseWriter) httpCacheControl() string {
	if writer.message != nil {
		if ttl, cacheable := responseTTL(writer.message); cacheable {
			return "public, max-age=" + strconv.FormatUint(uint64(ttl), 10)
		}
	}
	return "no-store"
}

func parseRemoteAddress(address string) net.Addr {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return &net.IPAddr{IP: net.ParseIP(address)}
	}
	portNumber, _ := strconv.Atoi(port)
	return &net.TCPAddr{IP: net.ParseIP(host), Port: portNumber}
}
