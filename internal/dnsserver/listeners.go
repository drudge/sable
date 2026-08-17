package dnsserver

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
	"github.com/quic-go/quic-go"
)

const (
	dnsReadTimeout       = 5 * time.Second
	dnsWriteTimeout      = 5 * time.Second
	dohHeaderTimeout     = 5 * time.Second
	dohRequestTimeout    = 10 * time.Second
	dohIdleTimeout       = 30 * time.Second
	dohMaxHeaderBytes    = 16 << 10
	listenerStartTimeout = 5 * time.Second
)

type ListenerConfig struct {
	PlainDNS    []string
	DoT         []string
	DoH         []string
	DoQ         []string
	Certificate string
	PrivateKey  string
	MinimumTLS  uint16
}

type certificateStore struct {
	current atomic.Pointer[tls.Certificate]
}

func (store *certificateStore) activate(certificate *tls.Certificate) {
	store.current.Store(certificate)
}

func (store *certificateStore) getCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	certificate := store.current.Load()
	if certificate == nil {
		return nil, errors.New("TLS certificate is not loaded")
	}
	return certificate, nil
}

type activeListener struct {
	target     listenerTarget
	dnsServer  *dns.Server
	httpServer *http.Server
	quicServer *doqServer
	socket     io.Closer
	started    chan struct{}
}

func (listener *activeListener) closeSocket() error {
	if listener.socket == nil {
		return nil
	}
	return listener.socket.Close()
}

func (listener *activeListener) shutdown(ctx context.Context) error {
	if listener.dnsServer != nil {
		return listener.dnsServer.ShutdownContext(ctx)
	}
	if listener.httpServer != nil {
		return listener.httpServer.Shutdown(ctx)
	}
	if listener.quicServer != nil {
		return listener.quicServer.shutdown(ctx)
	}
	return nil
}

type ListenerGroup struct {
	handler      dns.Handler
	logger       *slog.Logger
	certificates certificateStore
	openListener func(listenerTarget) (*activeListener, error)
	mu           sync.Mutex
	listeners    map[string]*activeListener
}

type protocolHandler struct {
	handler  dns.Handler
	protocol string
}

func (handler protocolHandler) ServeDNS(writer dns.ResponseWriter, request *dns.Msg) {
	handler.handler.ServeDNS(protocolResponseWriter{ResponseWriter: writer, protocol: handler.protocol}, request)
}

type protocolResponseWriter struct {
	dns.ResponseWriter
	protocol string
}

func (writer protocolResponseWriter) QueryProtocol() string { return writer.protocol }

func NewListenerGroup(handler dns.Handler, logger *slog.Logger) *ListenerGroup {
	group := &ListenerGroup{
		handler:   handler,
		logger:    logger,
		listeners: make(map[string]*activeListener),
	}
	group.openListener = group.open
	return group
}

func (group *ListenerGroup) Replace(ctx context.Context, configuration ListenerConfig) error {
	group.mu.Lock()
	defer group.mu.Unlock()

	certificate, err := loadCertificate(configuration)
	if err != nil {
		return err
	}
	desired := listenerKeys(configuration)
	candidate := make(map[string]*activeListener, len(desired))
	opened := make([]*activeListener, 0, len(desired))
	for key, target := range desired {
		if existing, ok := group.listeners[key]; ok {
			candidate[key] = existing
			continue
		}
		listener, openErr := group.openListener(target)
		if openErr != nil {
			closeSockets(opened)
			return openErr
		}
		candidate[key] = listener
		opened = append(opened, listener)
	}

	previousCertificate := group.certificates.current.Load()
	if certificate != nil {
		group.certificates.activate(certificate)
	}
	serveResults := make([]<-chan error, 0, len(opened))
	for _, listener := range opened {
		serveResults = append(serveResults, group.serve(listener))
	}
	if startErr := awaitListenerStarts(ctx, opened, serveResults); startErr != nil {
		closeSockets(opened)
		if certificate != nil {
			group.certificates.activate(previousCertificate)
		}
		return startErr
	}
	for key, listener := range group.listeners {
		if _, keep := candidate[key]; !keep {
			if shutdownErr := listener.shutdown(ctx); shutdownErr != nil {
				group.logger.Error("DNS listener shutdown failed", "listener", key, "error", shutdownErr)
			}
		}
	}
	group.listeners = candidate
	return nil
}

func (group *ListenerGroup) Close(ctx context.Context) error {
	group.mu.Lock()
	defer group.mu.Unlock()

	var closeErrors []error
	for key, listener := range group.listeners {
		if err := listener.shutdown(ctx); err != nil {
			closeErrors = append(closeErrors, fmt.Errorf("shutdown %s: %w", key, err))
		}
	}
	group.listeners = make(map[string]*activeListener)
	return errors.Join(closeErrors...)
}

func (group *ListenerGroup) open(target listenerTarget) (*activeListener, error) {
	switch target.kind {
	case listenerDNSUDP:
		return group.openUDP(target)
	case listenerDNSTCP:
		return group.openTCP(target)
	case listenerDoT:
		return group.openDoT(target)
	case listenerDoH:
		return group.openDoH(target)
	case listenerDoQ:
		return group.openDoQ(target)
	default:
		return nil, fmt.Errorf("unsupported DNS listener kind %q", target.kind)
	}
}

func (group *ListenerGroup) openUDP(target listenerTarget) (*activeListener, error) {
	connection, err := net.ListenPacket("udp", target.address)
	if err != nil {
		return nil, fmt.Errorf("listen udp %s: %w", target.address, err)
	}
	server := &dns.Server{
		Net:           "udp",
		Handler:       group.handler,
		PacketConn:    connection,
		ReadTimeout:   dnsReadTimeout,
		WriteTimeout:  dnsWriteTimeout,
		TsigProvider:  tsigProvider(group.handler),
		MsgAcceptFunc: dynamicUpdateAcceptFunc,
	}
	started := make(chan struct{})
	server.NotifyStartedFunc = func() { close(started) }
	return &activeListener{target: target, dnsServer: server, socket: connection, started: started}, nil
}

func (group *ListenerGroup) openTCP(target listenerTarget) (*activeListener, error) {
	listener, err := net.Listen("tcp", target.address)
	if err != nil {
		return nil, fmt.Errorf("listen tcp %s: %w", target.address, err)
	}
	server := &dns.Server{
		Net:           "tcp",
		Handler:       group.handler,
		Listener:      listener,
		ReadTimeout:   dnsReadTimeout,
		WriteTimeout:  dnsWriteTimeout,
		TsigProvider:  tsigProvider(group.handler),
		MsgAcceptFunc: dynamicUpdateAcceptFunc,
	}
	started := make(chan struct{})
	server.NotifyStartedFunc = func() { close(started) }
	return &activeListener{target: target, dnsServer: server, socket: listener, started: started}, nil
}

func (group *ListenerGroup) openDoT(target listenerTarget) (*activeListener, error) {
	listener, err := net.Listen("tcp", target.address)
	if err != nil {
		return nil, fmt.Errorf("listen dot %s: %w", target.address, err)
	}
	tlsListener := tls.NewListener(listener, group.tlsConfig(target.minimumTLS, []string{"dot"}))
	server := &dns.Server{
		Net:           "tcp-tls",
		Handler:       protocolHandler{handler: group.handler, protocol: "TLS"},
		Listener:      tlsListener,
		ReadTimeout:   dnsReadTimeout,
		WriteTimeout:  dnsWriteTimeout,
		TsigProvider:  tsigProvider(group.handler),
		MsgAcceptFunc: dynamicUpdateAcceptFunc,
	}
	started := make(chan struct{})
	server.NotifyStartedFunc = func() { close(started) }
	return &activeListener{target: target, dnsServer: server, socket: tlsListener, started: started}, nil
}

func tsigProvider(handler dns.Handler) dns.TsigProvider {
	provider, _ := handler.(dns.TsigProvider)
	return provider
}

func dynamicUpdateAcceptFunc(header dns.Header) dns.MsgAcceptAction {
	if header.Bits&0x8000 == 0 && int(header.Bits>>11)&0xf == dns.OpcodeUpdate {
		if header.Qdcount != 1 || header.Arcount > 2 {
			return dns.MsgReject
		}
		return dns.MsgAccept
	}
	return dns.DefaultMsgAcceptFunc(header)
}

func (group *ListenerGroup) openDoH(target listenerTarget) (*activeListener, error) {
	listener, err := net.Listen("tcp", target.address)
	if err != nil {
		return nil, fmt.Errorf("listen doh %s: %w", target.address, err)
	}
	server := &http.Server{
		Handler:           NewDoHHandler(group.handler),
		TLSConfig:         group.tlsConfig(target.minimumTLS, []string{"h2", "http/1.1"}),
		ReadHeaderTimeout: dohHeaderTimeout,
		ReadTimeout:       dohRequestTimeout,
		WriteTimeout:      dohRequestTimeout,
		IdleTimeout:       dohIdleTimeout,
		MaxHeaderBytes:    dohMaxHeaderBytes,
	}
	return &activeListener{target: target, httpServer: server, socket: listener, started: make(chan struct{})}, nil
}

func (group *ListenerGroup) openDoQ(target listenerTarget) (*activeListener, error) {
	packets, err := net.ListenPacket("udp", target.address)
	if err != nil {
		return nil, fmt.Errorf("listen doq %s: %w", target.address, err)
	}
	transport := &quic.Transport{Conn: packets}
	// QUIC is TLS 1.3 only, so a lower configured minimum cannot apply here.
	tlsConfiguration := group.tlsConfig(tls.VersionTLS13, []string{doqALPN})
	listener, err := transport.Listen(tlsConfiguration, doqQUICConfig())
	if err != nil {
		_ = transport.Close()
		_ = packets.Close()
		return nil, fmt.Errorf("listen doq %s: %w", target.address, err)
	}
	server := newDoQServer(group.handler, group.logger, transport, listener, packets)
	return &activeListener{target: target, quicServer: server, socket: server, started: make(chan struct{})}, nil
}

func (group *ListenerGroup) tlsConfig(minimumVersion uint16, protocols []string) *tls.Config {
	return &tls.Config{
		MinVersion:     minimumVersion,
		NextProtos:     protocols,
		GetCertificate: group.certificates.getCertificate,
	}
}

func (group *ListenerGroup) serve(listener *activeListener) <-chan error {
	result := make(chan error, 1)
	go func() {
		var err error
		switch {
		case listener.dnsServer != nil:
			err = listener.dnsServer.ActivateAndServe()
		case listener.quicServer != nil:
			close(listener.started)
			err = listener.quicServer.serve()
		default:
			close(listener.started)
			err = listener.httpServer.ServeTLS(listener.socket.(net.Listener), "", "")
		}
		result <- err
		if err != nil && !errors.Is(err, net.ErrClosed) && !errors.Is(err, http.ErrServerClosed) && !errors.Is(err, quic.ErrServerClosed) {
			group.logger.Error(
				"DNS listener stopped",
				"protocol", listener.target.kind,
				"address", listener.target.address,
				"error", err,
			)
		}
	}()
	return result
}

func awaitListenerStarts(
	ctx context.Context,
	listeners []*activeListener,
	serveResults []<-chan error,
) error {
	timer := time.NewTimer(listenerStartTimeout)
	defer timer.Stop()
	for index, listener := range listeners {
		select {
		case <-listener.started:
		case err := <-serveResults[index]:
			return fmt.Errorf("start %s listener %s: %w", listener.target.kind, listener.target.address, err)
		case <-ctx.Done():
			return fmt.Errorf("start %s listener %s: %w", listener.target.kind, listener.target.address, ctx.Err())
		case <-timer.C:
			return fmt.Errorf("start %s listener %s: timed out", listener.target.kind, listener.target.address)
		}
	}
	return nil
}

func loadCertificate(configuration ListenerConfig) (*tls.Certificate, error) {
	if len(configuration.DoT)+len(configuration.DoH)+len(configuration.DoQ) == 0 {
		return nil, nil
	}
	certificate, err := tls.LoadX509KeyPair(configuration.Certificate, configuration.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("load encrypted DNS certificate: %w", err)
	}
	return &certificate, nil
}

func ValidateListenerConfig(configuration ListenerConfig) error {
	_, err := loadCertificate(configuration)
	return err
}

type listenerKind string

const (
	listenerDNSUDP listenerKind = "dns-udp"
	listenerDNSTCP listenerKind = "dns-tcp"
	listenerDoT    listenerKind = "dot"
	listenerDoH    listenerKind = "doh"
	listenerDoQ    listenerKind = "doq"
)

type listenerTarget struct {
	kind       listenerKind
	address    string
	minimumTLS uint16
}

func listenerKeys(configuration ListenerConfig) map[string]listenerTarget {
	capacity := len(configuration.PlainDNS)*2 + len(configuration.DoT) + len(configuration.DoH) + len(configuration.DoQ)
	result := make(map[string]listenerTarget, capacity)
	for _, address := range configuration.PlainDNS {
		addListenerTarget(result, listenerTarget{kind: listenerDNSUDP, address: address})
		addListenerTarget(result, listenerTarget{kind: listenerDNSTCP, address: address})
	}
	for _, address := range configuration.DoT {
		addListenerTarget(result, listenerTarget{kind: listenerDoT, address: address, minimumTLS: configuration.MinimumTLS})
	}
	for _, address := range configuration.DoH {
		addListenerTarget(result, listenerTarget{kind: listenerDoH, address: address, minimumTLS: configuration.MinimumTLS})
	}
	for _, address := range configuration.DoQ {
		addListenerTarget(result, listenerTarget{kind: listenerDoQ, address: address})
	}
	return result
}

func addListenerTarget(targets map[string]listenerTarget, target listenerTarget) {
	key := string(target.kind) + ":" + target.address
	if target.minimumTLS != 0 {
		key += ":tls" + strconv.Itoa(int(target.minimumTLS))
	}
	targets[key] = target
}

func closeSockets(listeners []*activeListener) {
	for _, listener := range listeners {
		_ = listener.closeSocket()
	}
}
