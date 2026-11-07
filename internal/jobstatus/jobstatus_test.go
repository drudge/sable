package jobstatus

import (
	"errors"
	"testing"
	"time"
)

func TestAttemptsTransitions(t *testing.T) {
	start := time.Date(2026, 11, 7, 12, 0, 0, 0, time.UTC)
	var attempts Attempts
	if !attempts.Due(start) {
		t.Fatal("a worker that never ran is due")
	}
	attempts.Queue()
	if !attempts.Running || attempts.Due(start) {
		t.Fatalf("queued attempts = %+v, want running and not due", attempts)
	}
	attempts.Begin(start)
	attempts.Finish(start, start.Add(2*time.Second), false)
	attempts.Fail(errors.New("timeout"), start.Add(time.Minute))
	if attempts.Running || attempts.ConsecutiveFailures != 1 || attempts.LastError != "timeout" || attempts.Duration != 2*time.Second {
		t.Fatalf("after a failure attempts = %+v", attempts)
	}
	if attempts.Due(start.Add(30*time.Second)) || !attempts.Due(start.Add(time.Minute)) {
		t.Fatal("a failed worker is due again only at its next attempt")
	}
	attempts.Begin(start.Add(time.Minute))
	attempts.Finish(start.Add(time.Minute), start.Add(61*time.Second), true)
	attempts.Succeed(start.Add(61*time.Second), start.Add(time.Hour))
	if !attempts.Running || attempts.ConsecutiveFailures != 0 || attempts.LastError != "" || !attempts.LastSuccess.Equal(start.Add(61*time.Second)) {
		t.Fatalf("after a success with a run queued attempts = %+v", attempts)
	}
}

func TestBackoff(t *testing.T) {
	for _, test := range []struct {
		failures int
		want     time.Duration
	}{
		{0, time.Minute}, {1, time.Minute}, {2, 2 * time.Minute}, {3, 4 * time.Minute},
		{5, 10 * time.Minute}, {50, 10 * time.Minute},
	} {
		if got := Backoff(test.failures, time.Minute, 10*time.Minute); got != test.want {
			t.Errorf("Backoff(%d) = %s, want %s", test.failures, got, test.want)
		}
	}
}
