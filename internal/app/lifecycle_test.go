package app

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

func TestWaitRuntimeWorkersHonorsShutdownDeadline(t *testing.T) {
	var workers sync.WaitGroup
	workers.Add(1)
	ctx, cancel := context.WithTimeout(context.Background(), time.Millisecond)
	defer cancel()
	if err := waitRuntimeWorkers(ctx, &workers); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("waitRuntimeWorkers() error = %v, want deadline exceeded", err)
	}
	workers.Done()
	if err := waitRuntimeWorkers(context.Background(), &workers); err != nil {
		t.Fatalf("waitRuntimeWorkers() after worker exit = %v", err)
	}
}
