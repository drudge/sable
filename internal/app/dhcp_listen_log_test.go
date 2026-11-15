package app

import (
	"context"
	"runtime"
	"testing"
)

// The tests take the socket to talk to with listens.last() as soon as
// waitDHCPEvents sees its "listen". The log has to show the socket by then:
// when it doesn't, last() hands back the socket before it (closed, after a
// rebind) and the test waits for a reply that never comes, or panics on an
// empty list.
func TestReview630ListenLogShowsTheSocketWithItsListenEvent(t *testing.T) {
	for round := range 200000 {
		log := &dhcpListenLog{}
		go func() { _, _ = log.listen(context.Background(), 67) }()
		for len(log.snapshot()) == 0 {
			runtime.Gosched()
		}
		log.mutex.Lock()
		sockets := len(log.conns)
		log.mutex.Unlock()
		if sockets == 0 {
			t.Fatalf("round %d: the log shows \"listen\" but no socket yet, so listens.last() returns the one before it", round)
		}
	}
}
