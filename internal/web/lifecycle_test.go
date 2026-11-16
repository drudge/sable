package web

import (
	"context"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/drudge/sable/internal/blocking"
	"github.com/drudge/sable/internal/config"
)

func TestBlockListSchedulerCancelsHangingRefresh(t *testing.T) {
	started := make(chan struct{})
	serverTest := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		close(started)
		<-request.Context().Done()
	}))
	defer serverTest.Close()
	runtimeContext, cancel := context.WithCancel(context.Background())
	defer cancel()
	updater := blocking.NewUpdater(t.TempDir())
	updater.SetNext(time.Now())
	server := &Server{
		logger:         slog.New(slog.NewTextHandler(io.Discard, nil)),
		config:         testConfiguration{snapshot: config.Snapshot{Config: config.Config{Blocking: config.Blocking{Lists: []config.BlockList{{URL: serverTest.URL, Path: "list"}}, UpdateInterval: config.Duration{Duration: time.Hour}}}}},
		blockLists:     updater,
		runtimeContext: runtimeContext,
		runtimeCancel:  cancel,
		runtimeDone:    make(chan struct{}),
	}
	done := make(chan struct{})
	go func() {
		server.runBlockListScheduler()
		close(done)
	}()
	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("scheduled refresh did not start")
	}
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("scheduler did not stop after context cancellation")
	}
}

// A client's spare connection, one it opened and has asked nothing on yet,
// must not hold Close: http.Server.Shutdown counts it as busy until it is five
// seconds old, which outlasts a short shutdown_timeout.
func TestCloseDoesNotWaitForAConnectionThatSentNothing(t *testing.T) {
	server, _ := newMCPTestServer(t)
	if err := server.Start("127.0.0.1:0"); err != nil {
		t.Fatal(err)
	}
	address := server.listener.Addr().String()
	spare, err := net.Dial("tcp", address)
	if err != nil {
		t.Fatal(err)
	}
	defer spare.Close()
	// The listener hands connections over in order, so once this request is
	// answered the server has accepted the spare one too.
	client := &http.Client{Transport: &http.Transport{DisableKeepAlives: true}, Timeout: 5 * time.Second}
	response, err := client.Get("http://" + address + "/healthz")
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	started := time.Now()
	if err := server.Close(ctx); err != nil {
		t.Fatalf("Close with an unused connection open = %v after %s", err, time.Since(started).Round(time.Millisecond))
	}
	if took := time.Since(started); took > time.Second {
		t.Fatalf("Close took %s with an unused connection open", took.Round(time.Millisecond))
	}
	// The server dropped the connection rather than leaving it open.
	_ = spare.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := spare.Read(make([]byte, 1)); err != io.EOF {
		t.Fatalf("read on the unused connection after Close = %v, want EOF", err)
	}
}

// A request still running when Close begins gets half of the shutdown budget,
// then the console closes it, so the DNS listeners and the cache snapshot that
// shut down after the console keep the rest.
func TestCloseCutsOffARequestThatOutlastsHalfTheBudget(t *testing.T) {
	server, _ := newMCPTestServer(t)
	started := make(chan struct{})
	server.httpServer.Handler = http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		close(started)
		<-request.Context().Done()
	})
	if err := server.Start("127.0.0.1:0"); err != nil {
		t.Fatal(err)
	}
	requestDone := make(chan error, 1)
	go func() {
		response, err := http.Get("http://" + server.listener.Addr().String() + "/slow")
		if err == nil {
			response.Body.Close()
		}
		requestDone <- err
	}()
	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("slow request did not reach the handler")
	}

	const budget = 2 * time.Second
	ctx, cancel := context.WithTimeout(context.Background(), budget)
	defer cancel()
	began := time.Now()
	if err := server.Close(ctx); err != nil {
		t.Fatalf("Close with a slow request running = %v after %s", err, time.Since(began).Round(time.Millisecond))
	}
	if took := time.Since(began); took < budget/2-100*time.Millisecond || took > budget*3/4 {
		t.Fatalf("Close took %s, want about half of the %s budget", took.Round(time.Millisecond), budget)
	}
	select {
	case err := <-requestDone:
		if err == nil {
			t.Fatal("the slow request finished normally, want it cut off")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("the slow request was still open after Close")
	}
}
