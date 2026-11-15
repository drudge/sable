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
