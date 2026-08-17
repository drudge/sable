package dnsclient

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"time"

	"github.com/miekg/dns"
	"github.com/quic-go/quic-go"
)

const (
	// doqALPN is the ALPN token RFC 9250 registers for DNS-over-QUIC.
	doqALPN = "doq"
	// doqMaxMessageBytes matches the two-octet length prefix DoQ shares with
	// DNS over TCP.
	doqMaxMessageBytes = 65_535
)

// ExchangeQUIC sends one query over an RFC 9250 DNS-over-QUIC connection.
// Each exchange opens its own bidirectional stream, half-closes it so the
// server sees the query is complete, and reads the length-prefixed response
// back from the same stream.
func ExchangeQUIC(
	ctx context.Context,
	message *dns.Msg,
	server string,
	serverName string,
	timeout time.Duration,
) (*dns.Msg, time.Duration, error) {
	host, _, err := net.SplitHostPort(server)
	if err != nil {
		return nil, 0, fmt.Errorf("parse QUIC server: %w", err)
	}
	if strings.TrimSpace(serverName) == "" {
		serverName = host
	}
	wire, err := message.Pack()
	if err != nil {
		return nil, 0, fmt.Errorf("pack DNS request: %w", err)
	}
	if len(wire) > doqMaxMessageBytes {
		return nil, 0, errors.New("DNS request exceeds the DoQ message limit")
	}

	if timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
	}
	started := time.Now()
	tlsConfiguration := &tls.Config{
		MinVersion: tls.VersionTLS13,
		ServerName: strings.TrimSuffix(serverName, "."),
		NextProtos: []string{doqALPN},
	}
	connection, err := quic.DialAddr(ctx, server, tlsConfiguration, &quic.Config{
		HandshakeIdleTimeout: timeout,
		MaxIdleTimeout:       timeout,
	})
	if err != nil {
		return nil, time.Since(started), err
	}
	defer func() { _ = connection.CloseWithError(0, "") }()

	response, err := exchangeDoQStream(ctx, connection, wire)
	elapsed := time.Since(started)
	if err != nil {
		return nil, elapsed, err
	}
	if response.Id != message.Id {
		return nil, elapsed, errors.New("DoQ response ID does not match request")
	}
	return response, elapsed, nil
}

func exchangeDoQStream(ctx context.Context, connection *quic.Conn, wire []byte) (*dns.Msg, error) {
	stream, err := connection.OpenStreamSync(ctx)
	if err != nil {
		return nil, fmt.Errorf("open DoQ stream: %w", err)
	}
	defer stream.Close()
	if deadline, ok := ctx.Deadline(); ok {
		_ = stream.SetDeadline(deadline)
	}

	framed := make([]byte, 2+len(wire))
	binary.BigEndian.PutUint16(framed[:2], uint16(len(wire)))
	copy(framed[2:], wire)
	if _, err := stream.Write(framed); err != nil {
		return nil, fmt.Errorf("write DoQ query: %w", err)
	}
	// RFC 9250 section 4.2 requires the client to signal the end of the query
	// with a STREAM FIN before the server answers.
	if err := stream.Close(); err != nil {
		return nil, fmt.Errorf("finish DoQ query: %w", err)
	}

	var header [2]byte
	if _, err := io.ReadFull(stream, header[:]); err != nil {
		return nil, fmt.Errorf("read DoQ response: %w", err)
	}
	length := binary.BigEndian.Uint16(header[:])
	if length == 0 {
		return nil, errors.New("DoQ server returned an empty DNS response")
	}
	responseWire := make([]byte, length)
	if _, err := io.ReadFull(stream, responseWire); err != nil {
		return nil, fmt.Errorf("read DoQ response: %w", err)
	}
	response := new(dns.Msg)
	if err := response.Unpack(responseWire); err != nil {
		return nil, fmt.Errorf("unpack DNS response: %w", err)
	}
	return response, nil
}

func exchangeDoQ(
	ctx context.Context,
	message *dns.Msg,
	server string,
	serverName string,
	timeout time.Duration,
) (*dns.Msg, time.Duration, error) {
	return ExchangeQUIC(ctx, message, server, serverName, timeout)
}
