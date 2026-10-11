// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package cs101_test

import (
	"bytes"
	"context"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/cB-Sigma/iec60870"
	"github.com/cB-Sigma/iec60870/cs101"
)

var params101 = iec60870.Params{COTSize: 1, CASize: 1, IOASize: 2}

func asdu(t *testing.T, ty iec60870.TypeID, c iec60870.Cause, o iec60870.Object) []byte {
	t.Helper()
	b, err := (&iec60870.ASDU{Type: ty, Cause: c, CA: 7, Objects: []iec60870.Object{o}}).Encode(params101, time.UTC)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// pair runs a controlling station's Link against a Secondary on the two
// ends of an in-memory line.
func pair(t *testing.T, balanced bool) (*cs101.Link, *cs101.Secondary, *sync.Mutex, *[][]byte, chan struct{}) {
	t.Helper()
	a, b := net.Pipe()
	ctx, cancel := context.WithCancel(context.Background())
	var mu sync.Mutex
	var acked [][]byte
	reset := make(chan struct{}, 1)
	s := cs101.NewSecondary(cs101.NewPort(a), cs101.SecondaryConfig{LinkAddress: 3, AddrSize: 1, Balanced: balanced,
		LinkTimeout: 5 * time.Second, Timeout: 300 * time.Millisecond, Retries: 2, TestPeriod: time.Hour, Name: "line 1",
		OnReset: func(*cs101.Secondary) {
			select {
			case reset <- struct{}{}:
			default:
			}
		},
		OnAcked: func(_ context.Context, as [][]byte) { mu.Lock(); acked = append(acked, as...); mu.Unlock() }})
	done := make(chan struct{})
	go func() { defer close(done); _ = s.Run(ctx) }()
	l := cs101.NewLink(cs101.NewPort(b), 1, balanced, 300*time.Millisecond, 2)
	t.Cleanup(func() { cancel(); l.Close(); s.Close(); <-done })
	return l, s, &mu, &acked, reset
}

// Unbalanced (Figure 6): the controlling station starts the secondary's
// link, polls its class 1 and 2 data and sends it user data; data
// answered to a poll counts as delivered once the next request changes
// the frame count bit.
func TestSecondaryUnbalanced(t *testing.T) {
	l, s, mu, acked, reset := pair(t, false)
	ctx := context.Background()
	if err := l.Start(ctx, 3); err != nil {
		t.Fatal(err)
	}
	select {
	case <-reset:
	case <-time.After(time.Second):
		t.Fatal("the secondary did not report the reset of its link")
	}
	if got := s.RemoteAddr().String(); got != "line 1" {
		t.Errorf("RemoteAddr %q", got)
	}
	ev := asdu(t, iec60870.MSpNa1, iec60870.CauseSpontaneous, iec60870.Object{IOA: 100, Value: 1})
	if err := s.Send(ctx, ev); err != nil {
		t.Fatal(err)
	}
	var got [][]byte
	if err := l.Poll(ctx, 3, 8, func(b []byte) { got = append(got, b) }); err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || !bytes.Equal(got[0], ev) {
		t.Fatalf("polled %x, want %x", got, ev)
	}
	// The next poll confirms it.
	if err := l.Poll(ctx, 3, 8, func([]byte) {}); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	if len(*acked) != 1 || !bytes.Equal((*acked)[0], ev) {
		t.Errorf("acknowledged %x", *acked)
	}
	mu.Unlock()
	cmd := asdu(t, iec60870.CScNa1, iec60870.CauseActivation, iec60870.Object{IOA: 200, Value: 1})
	if err := l.Send(ctx, 3, cmd); err != nil {
		t.Fatal(err)
	}
	select {
	case b := <-s.ASDUs():
		if !bytes.Equal(b, cmd) {
			t.Errorf("received %x", b)
		}
	case <-time.After(time.Second):
		t.Fatal("the secondary did not deliver the user data")
	}
	// Another address on the party line is not answered.
	if _, err := l.Request(ctx, 4, cs101.FnRequestStatus, false, nil); err == nil {
		t.Error("a request for link address 4 was answered")
	}
}

// Balanced (Figures 8 and 9): station B starts the controlling station's
// link and sends its data as confirmed user data; the controlling station
// sends commands the same way.
func TestSecondaryBalanced(t *testing.T) {
	l, s, mu, acked, _ := pair(t, true)
	ctx := context.Background()
	if err := l.Start(ctx, 3); err != nil {
		t.Fatal(err)
	}
	ev := asdu(t, iec60870.MMeNc1, iec60870.CauseSpontaneous, iec60870.Object{IOA: 101, Value: 49.98})
	if err := s.Send(ctx, ev); err != nil {
		t.Fatal(err)
	}
	select {
	case b := <-l.ASDUs():
		if !bytes.Equal(b, ev) {
			t.Errorf("received %x", b)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("station B's data did not arrive")
	}
	deadline := time.Now().Add(2 * time.Second)
	for {
		mu.Lock()
		n := len(*acked)
		mu.Unlock()
		if n == 1 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("station B's data was not acknowledged")
		}
		time.Sleep(10 * time.Millisecond)
	}
	cmd := asdu(t, iec60870.CScNa1, iec60870.CauseActivation, iec60870.Object{IOA: 200, Value: 0})
	if err := l.Send(ctx, 3, cmd); err != nil {
		t.Fatal(err)
	}
	select {
	case b := <-s.ASDUs():
		if !bytes.Equal(b, cmd) {
			t.Errorf("received %x", b)
		}
	case <-time.After(time.Second):
		t.Fatal("station B did not deliver the user data")
	}
}
