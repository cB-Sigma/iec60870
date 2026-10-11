package iec60870

import (
	"context"
	"fmt"
	"sync"
	"time"
)

// Commands of a controlling station (IEC 60870-5-101 7.4.7 to 7.4.9, the
// same procedures over IEC 60870-5-104). A request is an activation or
// deactivation the station confirms (ACTCON, DEACTCON) and, for some
// commands, ends with an activation termination (ACTTERM). A Commander
// runs one request at a time per station, hands it the answers that
// mirror its type and address, and keeps the requests that timed out so
// their late answers are not taken for the next one (LateConfirmations).
// Operate adds select-before-operate (7.4.7: a select, S/E 1, confirmed
// before the execute, S/E 0).

// Sender is how a Commander's requests reach one station.
type Sender struct {
	// Send transmits one request as a one-object ASDU.
	Send func(ctx context.Context, t TypeID, cause Cause, o Object) error
	// Timeout bounds the wait for the confirmation.
	Timeout time.Duration
	// Done, when set, is closed when the connection ends; Err then says
	// why (nil Err: no reason given).
	Done <-chan struct{}
	Err  func() error
}

// Request is one activation or deactivation.
type Request struct {
	Type   TypeID
	Cause  Cause // CauseActivation or CauseDeactivation
	Object Object
	// Termination, when positive, waits that long after a positive
	// activation confirmation for the activation termination.
	Termination time.Duration
	// Check, when set, inspects a positive confirmation (a test command's
	// counter and time, say); its error fails the request.
	Check func(*ASDU) error
	// Untracked requests are not remembered when they time out (see
	// LateConfirmations); for requests whose confirmation is checked
	// anyway.
	Untracked bool
}

// Answer is what Commander.Take did with a received ASDU.
type Answer int

// Answers of Commander.Take.
const (
	// Unrelated: no running request waits for it.
	Unrelated Answer = iota
	// Taken: handed to the running request.
	Taken
	// Late: the late confirmation or termination of a request that timed
	// out, dropped.
	Late
)

// Commander runs the requests to one station; the zero value is ready to
// use.
type Commander struct {
	run    sync.Mutex // one request at a time
	mu     sync.Mutex
	waiter chan *ASDU
	key    [2]uint32 // type, IOA
	late   LateConfirmations
}

// Take routes a received ASDU of a command type (confirmation,
// termination or refusal) to the running request with the same type and
// first information object address.
func (c *Commander) Take(a *ASDU) Answer {
	c.mu.Lock()
	w, key := c.waiter, c.key
	c.mu.Unlock()
	if c.late.Drop(a) {
		return Late
	}
	if w != nil && len(a.Objects) > 0 && key == [2]uint32{uint32(a.Type), a.Objects[0].IOA} {
		select {
		case w <- a:
		default:
		}
		return Taken
	}
	return Unrelated
}

// Do sends r and waits for its confirmation (and, with r.Termination,
// its termination). A negative confirmation, a refusal (causes 44 to 47)
// or none within the timeout is an error; TimedOut and NotTerminated
// tell the timeouts apart.
func (c *Commander) Do(ctx context.Context, x Sender, r Request) error {
	c.run.Lock()
	defer c.run.Unlock()
	w := make(chan *ASDU, 8)
	c.mu.Lock()
	c.waiter, c.key = w, [2]uint32{uint32(r.Type), r.Object.IOA}
	c.mu.Unlock()
	defer func() {
		c.mu.Lock()
		c.waiter = nil
		c.mu.Unlock()
	}()
	if !r.Untracked {
		c.late.Forget(r.Type, r.Object)
	}
	if err := x.Send(ctx, r.Type, r.Cause, r.Object); err != nil {
		return err
	}
	why := x.Err
	if why == nil {
		why = func() error { return nil }
	}
	err := awaitConfirmation(ctx, x.Done, why, w, r.Type, r.Cause, x.Timeout, r.Termination, r.Check)
	if !r.Untracked && TimedOut(err) {
		c.late.Add(r.Type, r.Object, lateKeep(x.Timeout))
	}
	return err
}

// Operation is one command for Operate.
type Operation struct {
	Type   TypeID // a command type (45 to 51, 58 to 64)
	Object Object // address, value and qualifier; Select is set by Operate
	// SelectBeforeOperate sends a select first and the execute only once
	// the select is confirmed.
	SelectBeforeOperate bool
	// SelectOnly sends the select and stops: Operate returns it for a
	// later execute or Cancel.
	SelectOnly bool
	// TimeTag stamps Object.Time with the time each message is sent (the
	// CP56Time2a types): a slow select confirmation does not age the
	// execute towards the station's maximum command delay.
	TimeTag bool
	// Termination is the execute's wait for its activation termination
	// (0: done on the confirmation).
	Termination time.Duration
	// Now is the clock for TimeTag (nil: time.Now).
	Now func() time.Time
}

// PhaseError is an Operate failure, with the message that failed.
type PhaseError struct {
	Phase string // "select" or "execute"
	Err   error
}

// Error names the phase and the failure.
func (e *PhaseError) Error() string { return e.Phase + ": " + e.Err.Error() }

// Unwrap returns the failure.
func (e *PhaseError) Unwrap() error { return e.Err }

// Operate runs a command: with SelectBeforeOperate (or SelectOnly) a
// select, then, unless SelectOnly, the execute. It returns the confirmed
// select when SelectOnly. Errors are *PhaseError.
func (c *Commander) Operate(ctx context.Context, x Sender, op Operation) (Object, error) {
	now := op.Now
	if now == nil {
		now = time.Now
	}
	o := op.Object
	o.Select = false
	if op.SelectBeforeOperate || op.SelectOnly {
		sel := o
		sel.Select = true
		if op.TimeTag {
			sel.Time = now()
		}
		if err := c.Do(ctx, x, Request{Type: op.Type, Cause: CauseActivation, Object: sel}); err != nil {
			return Object{}, &PhaseError{"select", err}
		}
		if op.SelectOnly {
			return sel, nil
		}
	}
	if op.TimeTag {
		o.Time = now()
	}
	if err := c.Do(ctx, x, Request{Type: op.Type, Cause: CauseActivation, Object: o, Termination: op.Termination}); err != nil {
		return Object{}, &PhaseError{"execute", err}
	}
	return Object{}, nil
}

// Cancel deactivates a confirmed select (cause 8, answered with cause 9;
// 7.4.7). With timeTag the select is stamped again.
func (c *Commander) Cancel(ctx context.Context, x Sender, t TypeID, sel Object, timeTag bool) error {
	sel.Select = true
	if timeTag {
		sel.Time = time.Now()
	}
	return c.Do(ctx, x, Request{Type: t, Cause: CauseDeactivation, Object: sel})
}

// awaitConfirmation is the confirmation and termination wait of
// Commander.Do: done (nil: none) closes when the connection ends, why
// says why; check, when set, inspects a positive confirmation.
func awaitConfirmation(ctx context.Context, done <-chan struct{}, why func() error, w <-chan *ASDU, t TypeID, cause Cause, timeout, term time.Duration, check func(*ASDU) error) error {
	want, what := CauseActCon, "confirmation"
	if cause == CauseDeactivation {
		want, what = CauseDeactCon, "deactivation confirmation"
	}
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	confirmed := false
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-done:
			if confirmed {
				return fmt.Errorf("%s was confirmed, but the connection dropped before its termination (outcome unknown): %v", t, why())
			}
			return fmt.Errorf("the connection dropped before the %s: %v", what, why())
		case <-timer.C:
			if confirmed {
				return &timeoutError{msg: fmt.Sprintf("%s was confirmed, but no activation termination came within %s (outcome unknown)", t, term), confirmed: true}
			}
			if t >= CScTa1 && t <= CBoTa1 {
				// Clause 8 and Amendment 1: a controlled station answers
				// nothing to a time-tagged command older than its maximum
				// allowable delay.
				return &timeoutError{msg: fmt.Sprintf("no %s of %s within %s (the station may have discarded it as older than its maximum command delay)", what, t, timeout)}
			}
			return &timeoutError{msg: fmt.Sprintf("no %s of %s within %s", what, t, timeout)}
		case a := <-w:
			switch {
			case !confirmed && a.Cause == want:
				if a.Negative {
					return fmt.Errorf("the station refused %s (negative %s)", t, a.Cause)
				}
				if check != nil {
					if err := check(a); err != nil {
						return err
					}
				}
				if term <= 0 || cause != CauseActivation {
					return nil
				}
				confirmed = true
				timer.Reset(term)
			case confirmed && a.Cause == CauseActTerm:
				if a.Negative {
					return fmt.Errorf("the station ended %s with a negative termination", t)
				}
				return nil
			case a.Cause == CauseUnknownType || a.Cause == CauseUnknownCause || a.Cause == CauseUnknownCA || a.Cause == CauseUnknownObject:
				return fmt.Errorf("the station refused %s: %s", t, a.Cause)
			case !confirmed && a.Negative && a.Cause != CauseActTerm:
				return fmt.Errorf("the station refused %s (negative %s)", t, a.Cause)
			}
			// activation termination of an earlier request, or other
			// traffic for this object: keep waiting.
		}
	}
}
