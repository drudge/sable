package store

import (
	"context"
	"errors"
	"slices"
	"sync"
	"time"
)

// writerWaitLimit caps how long a transaction waits for this process's SQLite
// writer, whatever its context allows. A batch holds the writer for tens of
// milliseconds, so a wait this long means a transaction is stuck, and the
// writers behind it fail instead of hanging with it.
const writerWaitLimit = 30 * time.Second

// errWriterWait is the error of a transaction that waited writerWaitLimit
// for the writer without getting it.
var errWriterWait = errors.New("timed out waiting for the database writer")

// writePriority orders the transactions that wait for the writer.
type writePriority int

const (
	// writeNormal transactions take the writer in the order they asked.
	writeNormal writePriority = iota
	// writeUrgent transactions go ahead of every writeNormal one. A DHCP
	// lease save is urgent: its client waits for the ACK, and a query log
	// flush that came first can wait one more turn.
	writeUrgent
)

// writerQueue hands this process's SQLite writer to one transaction at a
// time: urgent waiters first, then the rest, each in the order they asked.
// The writer passes straight from one transaction to the next, so a waiter
// never races a newcomer for it.
type writerQueue struct {
	mu     sync.Mutex
	held   bool
	urgent []chan struct{}
	normal []chan struct{}
}

// acquire waits for the writer until ctx ends or limit passes. A nil error
// means the caller holds the writer and must release it.
func (queue *writerQueue) acquire(ctx context.Context, priority writePriority, limit time.Duration) error {
	queue.mu.Lock()
	if !queue.held {
		queue.held = true
		queue.mu.Unlock()
		return nil
	}
	turn := make(chan struct{})
	if priority == writeUrgent {
		queue.urgent = append(queue.urgent, turn)
	} else {
		queue.normal = append(queue.normal, turn)
	}
	queue.mu.Unlock()

	timer := time.NewTimer(limit)
	defer timer.Stop()
	var err error
	select {
	case <-turn:
		return nil
	case <-ctx.Done():
		err = ctx.Err()
	case <-timer.C:
		err = errWriterWait
	}
	queue.mu.Lock()
	if queue.remove(turn) {
		queue.mu.Unlock()
		return err
	}
	queue.mu.Unlock()
	// The writer reached this waiter as it gave up: pass it on.
	queue.release()
	return err
}

// release hands the writer to the next waiter, or frees it.
func (queue *writerQueue) release() {
	queue.mu.Lock()
	defer queue.mu.Unlock()
	next := shiftTurn(&queue.urgent)
	if next == nil {
		next = shiftTurn(&queue.normal)
	}
	if next == nil {
		queue.held = false
		return
	}
	close(next)
}

// remove drops a waiter that gave up and reports whether it was still
// waiting. queue.mu must be held.
func (queue *writerQueue) remove(turn chan struct{}) bool {
	for _, waiting := range []*[]chan struct{}{&queue.urgent, &queue.normal} {
		if index := slices.Index(*waiting, turn); index >= 0 {
			*waiting = slices.Delete(*waiting, index, index+1)
			return true
		}
	}
	return false
}

func shiftTurn(waiting *[]chan struct{}) chan struct{} {
	if len(*waiting) == 0 {
		return nil
	}
	next := (*waiting)[0]
	(*waiting)[0] = nil
	*waiting = (*waiting)[1:]
	return next
}
