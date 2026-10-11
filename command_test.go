// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package iec60870_test

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/cB-Sigma/iec60870"
)

// station is a scripted controlled station for a Commander: answer
// decides what each request gets back (nil: nothing), and every answer is
// routed through Take as a receive loop would.
type station struct {
	mu     sync.Mutex
	sent   []iec60870.Object
	causes []iec60870.Cause
	answer func(t iec60870.TypeID, c iec60870.Cause, o iec60870.Object) []*iec60870.ASDU
	cmd    *iec60870.Commander
	taken  []iec60870.Answer
}

func (s *station) sender(timeout time.Duration) iec60870.Sender {
	return iec60870.Sender{Timeout: timeout, Send: func(_ context.Context, t iec60870.TypeID, c iec60870.Cause, o iec60870.Object) error {
		s.mu.Lock()
		s.sent = append(s.sent, o)
		s.causes = append(s.causes, c)
		f := s.answer
		s.mu.Unlock()
		if f != nil {
			as := f(t, c, o)
			go func() { // after Send returns, in order, as a receive loop
				for _, a := range as {
					s.take(a)
				}
			}()
		}
		return nil
	}}
}

func (s *station) take(a *iec60870.ASDU) {
	r := s.cmd.Take(a)
	s.mu.Lock()
	s.taken = append(s.taken, r)
	s.mu.Unlock()
}

// mirror is a station's answer: the request's object with another cause.
func mirror(t iec60870.TypeID, c iec60870.Cause, o iec60870.Object, neg bool) *iec60870.ASDU {
	return &iec60870.ASDU{Type: t, Cause: c, Negative: neg, CA: 1, Objects: []iec60870.Object{o}}
}

// confirmAll confirms every request, and terminates executes.
func confirmAll(t iec60870.TypeID, c iec60870.Cause, o iec60870.Object) []*iec60870.ASDU {
	if c == iec60870.CauseDeactivation {
		return []*iec60870.ASDU{mirror(t, iec60870.CauseDeactCon, o, false)}
	}
	out := []*iec60870.ASDU{mirror(t, iec60870.CauseActCon, o, false)}
	if !o.Select {
		out = append(out, mirror(t, iec60870.CauseActTerm, o, false))
	}
	return out
}

// Select-before-operate: the select (S/E 1) is confirmed before the
// execute (S/E 0) goes out, and with time tags each message is stamped
// when it is sent, so a slow select does not age the execute.
func TestOperateSelectBeforeOperate(t *testing.T) {
	cmd := &iec60870.Commander{}
	st := &station{cmd: cmd, answer: confirmAll}
	base := time.Date(2026, 10, 6, 12, 0, 0, 0, time.UTC)
	var mu sync.Mutex
	n := 0
	now := func() time.Time { mu.Lock(); defer mu.Unlock(); n++; return base.Add(time.Duration(n) * time.Second) }
	op := iec60870.Operation{Type: iec60870.CScTa1, Object: iec60870.Object{IOA: 2001, Value: 1}, SelectBeforeOperate: true,
		TimeTag: true, Termination: time.Second, Now: now}
	if _, err := cmd.Operate(context.Background(), st.sender(time.Second), op); err != nil {
		t.Fatal(err)
	}
	if len(st.sent) != 2 || !st.sent[0].Select || st.sent[1].Select {
		t.Fatalf("sent %+v, want a select then an execute", st.sent)
	}
	if !st.sent[1].Time.After(st.sent[0].Time) {
		t.Errorf("execute stamped %s, select %s: the execute must be stamped when sent", st.sent[1].Time, st.sent[0].Time)
	}
	// Direct execute: one message.
	st.sent = nil
	op.SelectBeforeOperate, op.TimeTag = false, false
	if _, err := cmd.Operate(context.Background(), st.sender(time.Second), op); err != nil || len(st.sent) != 1 || st.sent[0].Select {
		t.Fatalf("direct execute: %v, sent %+v", err, st.sent)
	}
	// Select only, then cancel (deactivation, cause 8).
	st.sent = nil
	op.SelectOnly = true
	sel, err := cmd.Operate(context.Background(), st.sender(time.Second), op)
	if err != nil || !sel.Select || len(st.sent) != 1 {
		t.Fatalf("select only: %v %+v", err, st.sent)
	}
	if err := cmd.Cancel(context.Background(), st.sender(time.Second), iec60870.CScNa1, sel, false); err != nil {
		t.Fatal(err)
	}
	if st.causes[len(st.causes)-1] != iec60870.CauseDeactivation || !st.sent[len(st.sent)-1].Select {
		t.Errorf("cancel sent cause %s, %+v", st.causes[len(st.causes)-1], st.sent[len(st.sent)-1])
	}
}

// A refused select stops the command: no execute, and the error names the
// phase.
func TestOperateSelectRefused(t *testing.T) {
	cmd := &iec60870.Commander{}
	st := &station{cmd: cmd, answer: func(ty iec60870.TypeID, c iec60870.Cause, o iec60870.Object) []*iec60870.ASDU {
		return []*iec60870.ASDU{mirror(ty, iec60870.CauseActCon, o, o.Select)}
	}}
	_, err := cmd.Operate(context.Background(), st.sender(time.Second), iec60870.Operation{Type: iec60870.CScNa1,
		Object: iec60870.Object{IOA: 7, Value: 1}, SelectBeforeOperate: true})
	var pe *iec60870.PhaseError
	if !errors.As(err, &pe) || pe.Phase != "select" || len(st.sent) != 1 {
		t.Fatalf("err %v, sent %+v", err, st.sent)
	}
}

// A confirmation that comes after its command timed out is dropped, not
// taken for the next command on the same object; a retry of the same
// operation takes it.
func TestLateConfirmation(t *testing.T) {
	cmd := &iec60870.Commander{}
	st := &station{cmd: cmd}
	x := st.sender(50 * time.Millisecond)
	closeCmd := iec60870.Object{IOA: 3001, Value: 1}
	err := cmd.Do(context.Background(), x, iec60870.Request{Type: iec60870.CScNa1, Cause: iec60870.CauseActivation, Object: closeCmd})
	if !iec60870.TimedOut(err) {
		t.Fatalf("want a timeout, got %v", err)
	}
	// The next command on the object (open) waits; the late confirmation
	// of "close" arrives first and must not confirm it.
	openCmd := iec60870.Object{IOA: 3001, Value: 0}
	st.mu.Lock()
	st.answer = func(ty iec60870.TypeID, c iec60870.Cause, o iec60870.Object) []*iec60870.ASDU {
		if o.Value == 0 {
			st.take(mirror(ty, iec60870.CauseActCon, closeCmd, false)) // the late one, first
			return []*iec60870.ASDU{mirror(ty, iec60870.CauseActCon, o, true)}
		}
		return nil
	}
	st.mu.Unlock()
	err = cmd.Do(context.Background(), st.sender(time.Second), iec60870.Request{Type: iec60870.CScNa1, Cause: iec60870.CauseActivation, Object: openCmd})
	if err == nil {
		t.Fatal("the late confirmation of the earlier command was taken for this one")
	}
	st.mu.Lock()
	if len(st.taken) == 0 || st.taken[0] != iec60870.Late {
		t.Errorf("Take answers %v, want Late first", st.taken)
	}
	st.mu.Unlock()
	// A retry of the timed-out operation is no longer watched: its own
	// (or the late) confirmation confirms it.
	_ = cmd.Do(context.Background(), x, iec60870.Request{Type: iec60870.CScNa1, Cause: iec60870.CauseActivation, Object: closeCmd})
	st.mu.Lock()
	st.answer = func(ty iec60870.TypeID, c iec60870.Cause, o iec60870.Object) []*iec60870.ASDU {
		return []*iec60870.ASDU{mirror(ty, iec60870.CauseActCon, o, false)}
	}
	st.mu.Unlock()
	if err := cmd.Do(context.Background(), st.sender(time.Second), iec60870.Request{Type: iec60870.CScNa1, Cause: iec60870.CauseActivation, Object: closeCmd}); err != nil {
		t.Fatalf("retry: %v", err)
	}
}

// A confirmed command whose termination does not come is told apart
// from one that was never confirmed.
func TestTerminationTimeout(t *testing.T) {
	cmd := &iec60870.Commander{}
	st := &station{cmd: cmd, answer: func(ty iec60870.TypeID, c iec60870.Cause, o iec60870.Object) []*iec60870.ASDU {
		return []*iec60870.ASDU{mirror(ty, iec60870.CauseActCon, o, false)}
	}}
	wait, soft := iec60870.TerminationWait(nil)
	if wait != iec60870.DefaultTerminationWait || !soft {
		t.Errorf("unset termination wait: %s %v", wait, soft)
	}
	_, err := cmd.Operate(context.Background(), st.sender(time.Second), iec60870.Operation{Type: iec60870.CDcNa1,
		Object: iec60870.Object{IOA: 9, Value: 2}, Termination: 50 * time.Millisecond})
	if !iec60870.NotTerminated(err) {
		t.Fatalf("want confirmed but not terminated, got %v", err)
	}
	// A negative termination fails the command.
	st.answer = func(ty iec60870.TypeID, c iec60870.Cause, o iec60870.Object) []*iec60870.ASDU {
		return []*iec60870.ASDU{mirror(ty, iec60870.CauseActCon, o, false), mirror(ty, iec60870.CauseActTerm, o, true)}
	}
	_, err = cmd.Operate(context.Background(), st.sender(time.Second), iec60870.Operation{Type: iec60870.CDcNa1,
		Object: iec60870.Object{IOA: 9, Value: 1}, Termination: time.Second})
	if err == nil || iec60870.TimedOut(err) {
		t.Fatalf("negative termination: %v", err)
	}
}
