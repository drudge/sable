package web

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"
)

// requestBodyDeadline gives every request, DNS over HTTPS included, a much
// shorter body window than the server-wide ceiling. Routes that take uploads
// extend it for themselves.
func requestBodyDeadline(next http.Handler) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		_ = http.NewResponseController(writer).SetReadDeadline(time.Now().Add(webRequestBodyTimeout))
		next.ServeHTTP(writer, request)
	})
}

func (server *Server) sharedDoHHandler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		// The HTTP listener is a loopback recovery/setup endpoint. DoH is
		// available only on the public TLS listener and only when that exact
		// address is configured as a DoH endpoint.
		if request.TLS == nil || !server.config.Current().Config.SharesHTTPSWithDoH() {
			http.NotFound(writer, request)
			return
		}
		next.ServeHTTP(writer, request)
	})
}

func (server *Server) Start(address string) error {
	server.runtimeLifecycleMu.Lock()
	if server.runtimeClosed || server.runtimeStarted {
		server.runtimeLifecycleMu.Unlock()
		return errors.New("web server lifecycle has already started or closed")
	}
	listener, err := net.Listen("tcp", address)
	if err != nil {
		server.runtimeLifecycleMu.Unlock()
		return fmt.Errorf("listen for web console on %s: %w", address, err)
	}
	server.listener = listener
	server.runtimeStarted = true
	server.runtimeWG.Add(2)
	server.runtimeLifecycleMu.Unlock()
	server.history.record(time.Now(), server.stats.Stats())
	go func() { defer server.runtimeWG.Done(); server.collectStatsHistory() }()
	go func() { defer server.runtimeWG.Done(); server.runBlockListScheduler() }()
	go func() {
		if err := server.httpServer.Serve(listener); err != nil && err != http.ErrServerClosed {
			server.logger.Error("web console stopped", "error", err)
		}
	}()
	return nil
}

func (server *Server) StartTLS(address, certificateFile, privateKeyFile string, minimumVersion uint16) error {
	if strings.TrimSpace(address) == "" {
		return nil
	}
	if err := server.ReplaceCertificate(certificateFile, privateKeyFile); err != nil {
		return err
	}
	listener, err := net.Listen("tcp", address)
	if err != nil {
		return fmt.Errorf("listen for HTTPS web console on %s: %w", address, err)
	}
	tlsListener := tls.NewListener(listener, &tls.Config{
		MinVersion: minimumVersion,
		GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
			certificate := server.certificate.Load()
			if certificate == nil {
				return nil, errors.New("public TLS certificate is unavailable")
			}
			return certificate, nil
		},
	})
	server.httpsListener = tlsListener
	go func() {
		if err := server.httpServer.Serve(tlsListener); err != nil && err != http.ErrServerClosed {
			server.logger.Error("HTTPS web console stopped", "error", err)
		}
	}()
	return nil
}

func (server *Server) ReplaceCertificate(certificateFile, privateKeyFile string) error {
	certificate, err := tls.LoadX509KeyPair(certificateFile, privateKeyFile)
	if err != nil {
		return fmt.Errorf("load public TLS certificate: %w", err)
	}
	server.certificate.Store(&certificate)
	return nil
}

func (server *Server) Close(ctx context.Context) error {
	server.runtimeLifecycleMu.Lock()
	server.runtimeClosed = true
	server.runtimeCancel()
	server.runtimeLifecycleMu.Unlock()
	server.closeUnusedConnections()
	shutdownError := server.httpServer.Shutdown(ctx)
	server.runtimeWaitOnce.Do(func() {
		go func() {
			server.runtimeWG.Wait()
			close(server.runtimeDone)
		}()
	})
	var runtimeError error
	select {
	case <-server.runtimeDone:
	case <-ctx.Done():
		runtimeError = ctx.Err()
	}
	if runtimeError != nil {
		return errors.Join(shutdownError, runtimeError)
	}
	// The collector also flushes on its way out, but Close can win the race, so
	// persist the trailing counters here too. A flush clears what it wrote, so
	// whichever call runs second only writes what the first one missed.
	server.history.record(time.Now(), server.stats.Stats())
	if err := server.history.flush(ctx); err != nil {
		server.logger.Warn("persist query statistics", "error", err)
	}
	return shutdownError
}

// trackConnection remembers the connections that have not sent a request yet.
// http.Server.Shutdown counts one of those as busy until it is five seconds
// old, so a client's spare connection (a browser's preconnect, a cluster
// peer's second dial) held every stop that long, and failed it under a
// shutdown_timeout that short. Close drops them instead: nothing was asked
// on them, and a client that had only begun to write a request retries it.
func (server *Server) trackConnection(connection net.Conn, state http.ConnState) {
	if state != http.StateNew {
		server.unusedConnections.Delete(connection)
		return
	}
	server.unusedConnections.Store(connection, struct{}{})
	// Close may have swept before this one was stored.
	if server.closing.Load() {
		_ = connection.Close()
	}
}

// closeUnusedConnections closes every connection that has asked nothing, and
// has trackConnection close any that arrive before the listeners shut.
func (server *Server) closeUnusedConnections() {
	server.closing.Store(true)
	server.unusedConnections.Range(func(connection, _ any) bool {
		_ = connection.(net.Conn).Close()
		return true
	})
}

// goBackground runs work the console starts on its own, such as the reads that
// warm the Insights caches, without holding up the request that started it.
// The work gets a context Close cancels, and Close waits for it to return, so
// no background read is still using the store once the server has closed.
// Work started after Close runs at once on the canceled context, untracked,
// so anything waiting on it still hears back.
func (server *Server) goBackground(work func(context.Context)) {
	server.runtimeLifecycleMu.Lock()
	tracked := !server.runtimeClosed
	if tracked {
		server.runtimeWG.Add(1)
	}
	server.runtimeLifecycleMu.Unlock()
	go func() {
		if tracked {
			defer server.runtimeWG.Done()
		}
		work(server.runtimeContext)
	}()
}
