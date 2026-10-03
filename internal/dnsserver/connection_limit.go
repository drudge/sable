package dnsserver

import (
	"net"
	"sync"
)

const (
	// maximumStreamConnections caps the TCP, DoT, and DoH connections open at
	// once across every listener in a group. Each one holds a goroutine and
	// its buffers for as long as the client keeps it, so without a cap a
	// client that opens connections and never closes them exhausts memory.
	maximumStreamConnections = 1024
	// maximumDoQConnections caps open DNS-over-QUIC connections across every
	// listener in a group. It is lower than the stream cap because each QUIC
	// connection may carry up to doqMaxIncomingStreams queries at once.
	maximumDoQConnections = 256
)

// connectionSlots is a counting semaphore shared by the listeners of one
// protocol family. A listener that is full closes the new connection straight
// away instead of blocking in Accept, so shutdown never waits on a slot and a
// flood of connections cannot queue up behind the cap.
type connectionSlots chan struct{}

func newConnectionSlots(size int) connectionSlots {
	return make(connectionSlots, size)
}

func (slots connectionSlots) tryAcquire() bool {
	select {
	case slots <- struct{}{}:
		return true
	default:
		return false
	}
}

func (slots connectionSlots) release() {
	<-slots
}

// limitListener returns a listener whose accepted connections each hold one
// of slots until they are closed.
func limitListener(listener net.Listener, slots connectionSlots) net.Listener {
	return &limitedListener{Listener: listener, slots: slots}
}

type limitedListener struct {
	net.Listener
	slots connectionSlots
}

func (listener *limitedListener) Accept() (net.Conn, error) {
	for {
		connection, err := listener.Listener.Accept()
		if err != nil {
			return nil, err
		}
		if listener.slots.tryAcquire() {
			return &limitedConn{Conn: connection, release: listener.slots.release}, nil
		}
		_ = connection.Close()
	}
}

type limitedConn struct {
	net.Conn
	releaseOnce sync.Once
	release     func()
}

func (connection *limitedConn) Close() error {
	err := connection.Conn.Close()
	connection.releaseOnce.Do(connection.release)
	return err
}
