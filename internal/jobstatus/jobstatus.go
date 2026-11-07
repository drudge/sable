// Package jobstatus holds the attempt history that Sable's background
// workers share: whether a run is under way, when the last one started and
// succeeded, why it failed, how many failed in a row, and when the next one
// is due. Each worker embeds Attempts in its status and moves it only through
// these methods, so the transitions are written once.
package jobstatus

import "time"

// Attempts is one worker's run history.
type Attempts struct {
	// Running is true while an attempt is under way or queued behind one, so
	// the console shows a click on Sync Now straight away.
	Running     bool
	LastAttempt time.Time
	LastSuccess time.Time
	NextAttempt time.Time
	Duration    time.Duration
	LastError   string
	// ConsecutiveFailures counts the attempts in a row that failed. It paces
	// retries and lets an alert wait out one failed request but not three. A
	// success resets it.
	ConsecutiveFailures int
}

// Queue records that a run was asked for and is waiting to start.
func (attempts *Attempts) Queue() { attempts.Running = true }

// Begin records that an attempt started.
func (attempts *Attempts) Begin(started time.Time) {
	attempts.Running = true
	attempts.LastAttempt = started
}

// Finish records how long the attempt took. queued says whether another run
// is waiting behind it, which keeps Running true across the gap.
func (attempts *Attempts) Finish(started, finished time.Time, queued bool) {
	attempts.Running = queued
	attempts.Duration = finished.Sub(started)
}

// Succeed records a successful attempt and schedules the next one.
func (attempts *Attempts) Succeed(at, next time.Time) {
	attempts.ConsecutiveFailures = 0
	attempts.LastSuccess = at
	attempts.LastError = ""
	attempts.NextAttempt = next
}

// Fail records a failed attempt and schedules the retry.
func (attempts *Attempts) Fail(cause error, next time.Time) {
	attempts.ConsecutiveFailures++
	attempts.LastError = cause.Error()
	attempts.NextAttempt = next
}

// Due reports whether no attempt is running and the next one's time has come.
func (attempts Attempts) Due(now time.Time) bool {
	return !attempts.Running && (attempts.NextAttempt.IsZero() || !now.Before(attempts.NextAttempt))
}

// Backoff is the retry delay after failures attempts in a row: base after the
// first failure, doubling after each one after that, and never more than
// maximum.
func Backoff(failures int, base, maximum time.Duration) time.Duration {
	delay := base
	for attempt := 1; attempt < failures && delay < maximum; attempt++ {
		delay *= 2
	}
	return min(delay, maximum)
}
