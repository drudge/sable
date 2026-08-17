package dnsserver

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"sync"
	"time"

	"github.com/miekg/dns"
	"github.com/quic-go/quic-go"
)

// doqALPN is the ALPN token RFC 9250 registers for DNS-over-QUIC. A QUIC
// handshake that does not offer it is rejected before any DNS data is read.
const doqALPN = "doq"

// RFC 9250 section 4.3 application error codes. Every abnormal connection
// close carries one so clients can distinguish a protocol violation from an
// overloaded or failing server.
const (
	doqNoError          quic.ApplicationErrorCode = 0x0
	doqInternalError    quic.ApplicationErrorCode = 0x1
	doqProtocolError    quic.ApplicationErrorCode = 0x2
	doqRequestCancelled quic.ApplicationErrorCode = 0x3
	doqExcessiveLoad    quic.ApplicationErrorCode = 0x4
	doqUnspecifiedError quic.ApplicationErrorCode = 0x5
)

const (
	doqHandshakeTimeout   = 5 * time.Second
	doqIdleTimeout        = 30 * time.Second
	doqStreamTimeout      = 10 * time.Second
	doqMaxIncomingStreams = 512
	doqMaxMessageBytes    = 65_535
)

// doqServer serves RFC 9250 DNS-over-QUIC. Each query arrives on its own
// bidirectional stream carrying a two-octet length prefix, exactly like DNS
// over TCP, and the response is written back on the same stream.
type doqServer struct {
	handler   dns.Handler
	logger    *slog.Logger
	transport *quic.Transport
	listener  *quic.Listener
	packets   net.PacketConn
	tsig      dns.TsigProvider

	connections sync.WaitGroup
	closeOnce   sync.Once

	// live tracks accepted connections so shutdown can close them. Closing the
	// QUIC listener stops new handshakes but leaves established connections
	// running until they idle out, which is far longer than a controlled
	// shutdown should wait.
	liveMu sync.Mutex
	live   map[*quic.Conn]struct{}
	closed bool
}

func newDoQServer(
	handler dns.Handler,
	logger *slog.Logger,
	transport *quic.Transport,
	listener *quic.Listener,
	packets net.PacketConn,
) *doqServer {
	return &doqServer{
		handler:   handler,
		logger:    logger,
		transport: transport,
		listener:  listener,
		packets:   packets,
		tsig:      tsigProvider(handler),
		live:      make(map[*quic.Conn]struct{}),
	}
}

// track registers an accepted connection. It reports false once the server is
// closing so a connection accepted during the race is torn down immediately.
func (server *doqServer) track(connection *quic.Conn) bool {
	server.liveMu.Lock()
	defer server.liveMu.Unlock()

	if server.closed {
		return false
	}
	server.live[connection] = struct{}{}
	return true
}

func (server *doqServer) untrack(connection *quic.Conn) {
	server.liveMu.Lock()
	defer server.liveMu.Unlock()

	delete(server.live, connection)
}

func (server *doqServer) closeLiveConnections() {
	server.liveMu.Lock()
	connections := make([]*quic.Conn, 0, len(server.live))
	for connection := range server.live {
		connections = append(connections, connection)
	}
	server.closed = true
	server.liveMu.Unlock()

	for _, connection := range connections {
		_ = connection.CloseWithError(doqNoError, "server shutting down")
	}
}

func doqQUICConfig() *quic.Config {
	return &quic.Config{
		HandshakeIdleTimeout: doqHandshakeTimeout,
		MaxIdleTimeout:       doqIdleTimeout,
		MaxIncomingStreams:   doqMaxIncomingStreams,
		// RFC 9250 section 5.2 forbids unidirectional streams for DNS
		// payloads, so none are granted to the peer.
		MaxIncomingUniStreams: -1,
		Allow0RTT:             false,
	}
}

// serve accepts connections until the listener is closed. It mirrors the
// blocking contract of dns.Server.ActivateAndServe and http.Server.ServeTLS.
func (server *doqServer) serve() error {
	for {
		connection, err := server.listener.Accept(context.Background())
		if err != nil {
			server.connections.Wait()
			return err
		}
		server.connections.Add(1)
		go func() {
			defer server.connections.Done()
			server.serveConnection(connection)
		}()
	}
}

func (server *doqServer) serveConnection(connection *quic.Conn) {
	if !server.track(connection) {
		_ = connection.CloseWithError(doqNoError, "server shutting down")
		return
	}
	var streams sync.WaitGroup
	defer func() {
		streams.Wait()
		server.untrack(connection)
		_ = connection.CloseWithError(doqNoError, "")
	}()
	for {
		stream, err := connection.AcceptStream(context.Background())
		if err != nil {
			return
		}
		streams.Add(1)
		go func() {
			defer streams.Done()
			server.serveStream(connection, stream)
		}()
	}
}

func (server *doqServer) serveStream(connection *quic.Conn, stream *quic.Stream) {
	defer stream.Close()
	_ = stream.SetDeadline(time.Now().Add(doqStreamTimeout))

	wire, err := readDoQMessage(stream)
	if err != nil {
		server.abort(connection, doqProtocolError, "read DoQ query", err)
		return
	}
	request := new(dns.Msg)
	if err := request.Unpack(wire); err != nil {
		server.abort(connection, doqProtocolError, "unpack DoQ query", err)
		return
	}
	if hasEDNSTCPKeepalive(request) {
		// RFC 9250 section 5.5.2 makes edns-tcp-keepalive a fatal error on
		// DoQ because the option is specific to TCP connection management.
		server.abort(connection, doqProtocolError, "reject DoQ query", errors.New("edns-tcp-keepalive is not allowed over DoQ"))
		return
	}

	writer := newDoQResponseWriter(connection, stream, server.tsig)
	if signature := request.IsTsig(); signature != nil {
		writer.requestMAC = signature.MAC
		writer.tsigStatus = errors.New("TSIG verification is unavailable")
		if server.tsig != nil {
			writer.tsigStatus = dns.TsigVerifyWithProvider(wire, server.tsig, "", false)
		}
	}
	server.handler.ServeDNS(writer, request)
	if writer.err != nil {
		server.logger.Warn(
			"DoQ response write failed",
			"client", connection.RemoteAddr().String(),
			"error", writer.err,
		)
	}
}

// abort tears the whole connection down. RFC 9250 treats a malformed length
// prefix, an unparsable message, or a forbidden EDNS option as fatal for the
// connection rather than for the individual stream.
func (server *doqServer) abort(connection *quic.Conn, code quic.ApplicationErrorCode, message string, cause error) {
	if errors.Is(cause, io.EOF) || errors.Is(cause, context.Canceled) {
		// The peer closed the stream without sending a query, or the
		// connection went away first. Neither is a protocol violation.
		return
	}
	description := message
	if cause != nil {
		description = fmt.Sprintf("%s: %s", message, cause)
	}
	server.logger.Debug("DoQ connection aborted", "client", connection.RemoteAddr().String(), "reason", description)
	_ = connection.CloseWithError(code, description)
}

func (server *doqServer) Close() error {
	var err error
	server.closeOnce.Do(func() {
		listenerErr := server.listener.Close()
		server.closeLiveConnections()
		err = errors.Join(listenerErr, server.transport.Close(), server.packets.Close())
	})
	return err
}

func (server *doqServer) shutdown(ctx context.Context) error {
	err := server.Close()
	done := make(chan struct{})
	go func() {
		server.connections.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-ctx.Done():
		return errors.Join(err, ctx.Err())
	}
	return err
}

func readDoQMessage(stream *quic.Stream) ([]byte, error) {
	var header [2]byte
	if _, err := io.ReadFull(stream, header[:]); err != nil {
		return nil, err
	}
	length := binary.BigEndian.Uint16(header[:])
	if length == 0 {
		return nil, errors.New("DoQ message length is zero")
	}
	wire := make([]byte, length)
	if _, err := io.ReadFull(stream, wire); err != nil {
		return nil, err
	}
	return wire, nil
}

func hasEDNSTCPKeepalive(message *dns.Msg) bool {
	opt := message.IsEdns0()
	if opt == nil {
		return false
	}
	for _, option := range opt.Option {
		if option.Option() == dns.EDNS0TCPKEEPALIVE {
			return true
		}
	}
	return false
}

type doqResponseWriter struct {
	connection     *quic.Conn
	stream         *quic.Stream
	tsig           dns.TsigProvider
	requestMAC     string
	tsigStatus     error
	tsigTimersOnly bool
	err            error
}

func newDoQResponseWriter(connection *quic.Conn, stream *quic.Stream, provider dns.TsigProvider) *doqResponseWriter {
	return &doqResponseWriter{connection: connection, stream: stream, tsig: provider}
}

func (writer *doqResponseWriter) LocalAddr() net.Addr   { return writer.connection.LocalAddr() }
func (writer *doqResponseWriter) RemoteAddr() net.Addr  { return writer.connection.RemoteAddr() }
func (writer *doqResponseWriter) QueryProtocol() string { return "QUIC" }

func (writer *doqResponseWriter) WriteMsg(message *dns.Msg) error {
	var (
		wire []byte
		err  error
	)
	if signature := message.IsTsig(); signature != nil && writer.tsig != nil {
		wire, _, err = dns.TsigGenerateWithProvider(message, writer.tsig, writer.requestMAC, writer.tsigTimersOnly)
	} else {
		wire, err = message.Pack()
	}
	if err != nil {
		writer.err = err
		return err
	}
	_, err = writer.Write(wire)
	return err
}

func (writer *doqResponseWriter) Write(wire []byte) (int, error) {
	if len(wire) > doqMaxMessageBytes {
		writer.err = errors.New("DNS response exceeds the DoQ message limit")
		return 0, writer.err
	}
	framed := make([]byte, 2+len(wire))
	binary.BigEndian.PutUint16(framed[:2], uint16(len(wire)))
	copy(framed[2:], wire)
	written, err := writer.stream.Write(framed)
	if err != nil {
		writer.err = err
	}
	return max(written-2, 0), err
}

func (writer *doqResponseWriter) Close() error             { return writer.stream.Close() }
func (writer *doqResponseWriter) TsigStatus() error        { return writer.tsigStatus }
func (writer *doqResponseWriter) TsigTimersOnly(only bool) { writer.tsigTimersOnly = only }
func (writer *doqResponseWriter) Hijack()                  {}
