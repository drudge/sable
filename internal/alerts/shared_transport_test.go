package alerts

import (
	"net/http"
	"testing"
)

// The tests run in parallel and each closes its own httptest servers, which
// calls CloseIdleConnections on http.DefaultTransport. A dispatcher that posts
// there can lose its request to another test's cleanup.
func TestTheTestDispatcherDoesNotPostOnTheDefaultTransport(t *testing.T) {
	t.Parallel()
	dispatcher, _, _ := newTestDispatcher(t, nil)
	client := dispatcher.Client
	if client == nil || client == http.DefaultClient || client.Transport == nil || client.Transport == http.DefaultTransport {
		t.Fatal("the test dispatcher posts on http.DefaultTransport")
	}
}
