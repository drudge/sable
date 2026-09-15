package web

import (
	"context"
	"io"
	"log/slog"
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
