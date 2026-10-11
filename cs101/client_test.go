// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package cs101_test

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/cB-Sigma/iec60870"
	"github.com/cB-Sigma/iec60870/cs101"
)

// answer makes s a small station: it confirms what it receives, answers
// an interrogation with one point and a read with the point read, and
// terminates executes.
func answer(t *testing.T, s *cs101.Secondary) {
	go func() {
		for b := range s.ASDUs() {
			a, err := iec60870.DecodeASDU(b, params101, time.UTC)
			if err != nil {
				continue
			}
			reply := func(r *iec60870.ASDU) {
				out, err := r.Encode(params101, time.UTC)
				if err == nil {
					_ = s.Send(context.Background(), out)
				}
			}
			mirror := func(c iec60870.Cause) {
				m := *a
				m.Cause = c
				reply(&m)
			}
			switch a.Type {
			case iec60870.CRdNa1:
				reply(&iec60870.ASDU{Type: iec60870.MSpNa1, Cause: iec60870.CauseRequest, CA: a.CA,
					Objects: []iec60870.Object{{IOA: a.Objects[0].IOA, Value: 1}}})
			case iec60870.CIcNa1:
				mirror(iec60870.CauseActCon)
				reply(&iec60870.ASDU{Type: iec60870.MMeNc1, Cause: iec60870.CauseInterrogated, CA: a.CA,
					Objects: []iec60870.Object{{IOA: 300, Value: 1.5}}})
				mirror(iec60870.CauseActTerm)
			default:
				mirror(iec60870.CauseActCon)
				if a.Type == iec60870.CScNa1 && !a.Objects[0].Select || a.Type == iec60870.CCiNa1 {
					mirror(iec60870.CauseActTerm)
				}
			}
		}
	}()
}

// A frame's length octet holds at most 255 (control, address and ASDU):
// longer user data is refused, not sent with a wrapped length.
//
// Covers: SIG-IPE-1334
func TestFrameLengthLimit(t *testing.T) {
	l, s, _, _, _ := pair(t, false)
	ctx := context.Background()
	if err := l.Start(ctx, 3); err != nil {
		t.Fatal(err)
	}
	if err := l.Send(ctx, 3, make([]byte, 254)); err == nil {
		t.Error("254 octets of user data with a one-octet address were sent")
	}
	if err := s.Send(ctx, make([]byte, 254)); err == nil {
		t.Error("the secondary queued 254 octets with a one-octet address")
	}
	if err := l.Send(ctx, 3, make([]byte, 253)); err != nil {
		t.Errorf("253 octets: %v", err)
	}
}

// Covers: SIG-IPE-302
func TestClient101(t *testing.T) {
	for _, balanced := range []bool{false, true} {
		t.Run(map[bool]string{false: "unbalanced", true: "balanced"}[balanced], func(t *testing.T) {
			l, s, _, _, _ := pair(t, balanced)
			ctx := context.Background()
			if err := l.Start(ctx, 3); err != nil {
				t.Fatal(err)
			}
			answer(t, s)
			var mu sync.Mutex
			data := map[uint32]float64{}
			c := cs101.NewClient(l, cs101.ClientConfig{Address: 3, CA: 7, Timeout: 2 * time.Second, PollInterval: 20 * time.Millisecond,
				OnData: func(a *iec60870.ASDU) {
					mu.Lock()
					defer mu.Unlock()
					for _, o := range a.Objects {
						data[o.IOA] = o.Value
					}
				}})
			defer c.Close()
			if err := c.Interrogate(ctx, iec60870.QOIStation, 2*time.Second); err != nil {
				t.Fatal(err)
			}
			mu.Lock()
			if data[300] != 1.5 {
				t.Errorf("interrogated %v", data)
			}
			mu.Unlock()
			if _, err := c.Operate(ctx, iec60870.Operation{Type: iec60870.CScNa1, Object: iec60870.Object{IOA: 200, Value: 1},
				SelectBeforeOperate: true, Termination: 2 * time.Second}); err != nil {
				t.Fatal(err)
			}
			if err := c.ClockSync(ctx, time.Now()); err != nil {
				t.Error(err)
			}
			if err := c.CounterInterrogate(ctx, iec60870.QCC(iec60870.RQTGeneral, iec60870.FRZRead), 2*time.Second); err != nil {
				t.Error(err)
			}
			if err := c.Test(ctx); err != nil {
				t.Error(err)
			}
			if err := c.ResetProcess(ctx, iec60870.QRPGeneral); err != nil {
				t.Error(err)
			}
			if a, err := iec60870.Read(ctx, c, 100, 2*time.Second); err != nil || a.Objects[0].Value != 1 {
				t.Errorf("read %v %v", a, err)
			}
			if c.MaxASDU() != 253 {
				t.Errorf("MaxASDU %d, want 253 with a one-octet address", c.MaxASDU())
			}
		})
	}
}
