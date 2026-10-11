package iec60870

import (
	"errors"
	"sync"
	"time"
)

// Late confirmations. A controlled station mirrors a command in its
// confirmation and termination (IEC 60870-5-101 7.2.6, -104 the same
// ASDUs). When a command times out, its confirmation may still come,
// while the next command on the same object waits: the waiter is keyed by
// type and address only, so the late answer would be taken as the next
// command's. LateConfirmations remembers the timed-out commands for a
// while and drops answers that mirror one of them (same type, address,
// S/E, qualifier and value), once each for confirmation and termination.

// timeoutError is a request that got no confirmation, or no termination,
// in time: the station may still answer it.
type timeoutError struct {
	msg       string
	confirmed bool // the confirmation came; the termination did not
}

func (e *timeoutError) Error() string { return e.msg }

// TimedOut says whether err is a request's confirmation or termination
// timeout (the station may answer it late).
func TimedOut(err error) bool {
	var te *timeoutError
	return errors.As(err, &te)
}

// NotTerminated says whether err is a request that was confirmed but
// whose activation termination did not come in time.
func NotTerminated(err error) bool {
	var te *timeoutError
	return errors.As(err, &te) && te.confirmed
}

// DefaultTerminationWait is how long an execute waits for its activation
// termination when the station has no termination wait configured
// (TerminationWait): an activation confirmation only says the station
// accepted the command, not that it was carried out.
const DefaultTerminationWait = 5 * time.Second

// TerminationWait is the termination wait of a station's setting: unset
// waits DefaultTerminationWait and lets a missing termination pass as
// ok, not terminated (soft); set, it waits that long (0: not at all) and
// a missing termination fails the command.
func TerminationWait(set *time.Duration) (wait time.Duration, soft bool) {
	if set == nil {
		return DefaultTerminationWait, true
	}
	return *set, false
}

// LateConfirmations holds the commands that timed out; the zero value is
// ready to use.
type LateConfirmations struct {
	mu    sync.Mutex
	stale []staleCommand
}

type staleCommand struct {
	t         TypeID
	o         Object
	until     time.Time
	con, term bool // already dropped
}

// Add remembers a command of type t that timed out, for keep.
func (l *LateConfirmations) Add(t TypeID, o Object, keep time.Duration) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.prune(time.Now())
	l.stale = append(l.stale, staleCommand{t: t, o: o, until: time.Now().Add(keep)})
}

// Forget removes the timed-out commands equal to one about to be sent
// (a retry of the same operation): a late answer of the earlier one then
// stands for the same operation, and the retry's own answer is not
// dropped in its place.
func (l *LateConfirmations) Forget(t TypeID, o Object) {
	l.mu.Lock()
	defer l.mu.Unlock()
	kept := l.stale[:0]
	for _, s := range l.stale {
		if !(s.t == t && same(s.o, o)) {
			kept = append(kept, s)
		}
	}
	l.stale = kept
}

func same(a, b Object) bool {
	return a.IOA == b.IOA && a.Select == b.Select && a.Qualifier == b.Qualifier && a.Value == b.Value
}

// Drop reports whether a is the late confirmation or termination of a
// command that timed out (and consumes it).
func (l *LateConfirmations) Drop(a *ASDU) bool {
	if len(a.Objects) == 0 {
		return false
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	l.prune(time.Now())
	got := a.Objects[0]
	for i := range l.stale {
		s := &l.stale[i]
		if s.t != a.Type || !same(s.o, got) {
			continue
		}
		switch {
		case a.Cause == CauseActTerm && !s.term:
			s.term = true
			return true
		case a.Cause != CauseActTerm && !s.con:
			s.con = true
			return true
		}
	}
	return false
}

func (l *LateConfirmations) prune(now time.Time) {
	kept := l.stale[:0]
	for _, s := range l.stale {
		if now.Before(s.until) && !(s.con && s.term) {
			kept = append(kept, s)
		}
	}
	l.stale = kept
}

// lateKeep is how long a timed-out command's answers are watched for.
func lateKeep(timeout time.Duration) time.Duration {
	return max(10*timeout, time.Minute)
}

// LateKeep is how long LateConfirmations should watch for the answers of
// a request that timed out after timeout: ten timeouts, at least a minute.
func LateKeep(timeout time.Duration) time.Duration { return lateKeep(timeout) }
