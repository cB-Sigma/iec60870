// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package cs104_test

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/cB-Sigma/iec60870"
	"github.com/cB-Sigma/iec60870/cs104"
)

// serve runs s on a loopback listener and returns its address.
func serve(t *testing.T, s *cs104.Server) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go func() { _ = s.Serve(ctx, ln) }()
	return ln.Addr().String()
}

// spont is a spontaneous single point at ioa.
func spont(t *testing.T, ioa uint32) []byte {
	t.Helper()
	b, err := (&iec60870.ASDU{Type: iec60870.MSpNa1, Cause: iec60870.CauseSpontaneous, CA: 1,
		Objects: []iec60870.Object{{IOA: ioa, Value: 1}}}).Encode(iec60870.Params{}.WithDefaults(), time.UTC)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// ioas reads n ASDUs from l and returns their first object addresses.
func ioas(t *testing.T, l *cs104.Link, n int) []uint32 {
	t.Helper()
	var out []uint32
	for len(out) < n {
		select {
		case b, ok := <-l.ASDUs():
			if !ok {
				t.Fatalf("link closed after %v: %v", out, l.Err())
			}
			a, err := iec60870.DecodeASDU(b, iec60870.Params{}.WithDefaults(), time.UTC)
			if err != nil {
				t.Fatal(err)
			}
			out = append(out, a.Objects[0].IOA)
		case <-time.After(3 * time.Second):
			t.Fatalf("received %v, want %d ASDUs", out, n)
		}
	}
	return out
}

func equal(a, b []uint32) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// Covers: SIG-IPE-896
func TestGroupSwitchover(t *testing.T) {
	g := &cs104.Group{Name: "a"}
	addr := serve(t, &cs104.Server{Groups: []*cs104.Group{g}})
	ctx := context.Background()
	// w above what is sent and t2 near t1: this side acknowledges nothing
	// before the switchover.
	quiet := cs104.LinkConfig{W: 100, T1: 20 * time.Second, T2: 19 * time.Second}
	a, err := cs104.Dial(ctx, addr, quiet)
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	for i := uint32(1); i <= 3; i++ {
		if err := g.Enqueue(spont(t, i)); err != nil {
			t.Fatal(err)
		}
	}
	if got := ioas(t, a, 3); !equal(got, []uint32{1, 2, 3}) {
		t.Fatalf("first connection received %v", got)
	}
	b, err := cs104.DialStandby(ctx, addr, cs104.LinkConfig{})
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	eventually(t, 2*time.Second, "two connections", func() bool { return g.Links() == 2 })
	if err := b.StartDT(ctx); err != nil {
		t.Fatal(err)
	}
	select {
	case <-a.Done(): // Figure 36: the other started connection is closed
	case <-time.After(3 * time.Second):
		t.Fatal("the first connection stayed open")
	}
	_ = g.Enqueue(spont(t, 4))
	// 10.6: what the first connection sent without acknowledgement comes
	// again, first, on the new one.
	if got := ioas(t, b, 4); !equal(got, []uint32{1, 2, 3, 4}) {
		t.Fatalf("second connection received %v", got)
	}
	t.Run("queued while stopped, sent on the next start", func(t *testing.T) {
		if err := b.StopDT(ctx); err != nil {
			t.Fatal(err)
		}
		_ = g.Enqueue(spont(t, 5))
		_ = g.Enqueue(spont(t, 6))
		if g.Pending() != 2 {
			t.Errorf("pending %d, want 2", g.Pending())
		}
		if err := b.StartDT(ctx); err != nil {
			t.Fatal(err)
		}
		if got := ioas(t, b, 2); !equal(got, []uint32{5, 6}) {
			t.Fatalf("received %v", got)
		}
	})
	t.Run("queue limit", func(t *testing.T) {
		h := &cs104.Group{Limit: 1}
		_ = h.Enqueue(spont(t, 1))
		if err := h.Enqueue(spont(t, 2)); err != cs104.ErrQueueFull {
			t.Errorf("Enqueue beyond the limit = %v", err)
		}
	})
}

// Covers: SIG-IPE-896
func TestServerGroupsPolicy(t *testing.T) {
	ctx := context.Background()
	t.Run("each connection its own group", func(t *testing.T) {
		s := &cs104.Server{PerConnection: func() *cs104.Group { return &cs104.Group{} }}
		addr := serve(t, s)
		a, err := cs104.Dial(ctx, addr, cs104.LinkConfig{})
		if err != nil {
			t.Fatal(err)
		}
		defer a.Close()
		b, err := cs104.Dial(ctx, addr, cs104.LinkConfig{})
		if err != nil {
			t.Fatal(err)
		}
		defer b.Close()
		if err := s.Enqueue(spont(t, 9)); err != nil {
			t.Fatal(err)
		}
		for _, l := range []*cs104.Link{a, b} {
			if got := ioas(t, l, 1); got[0] != 9 {
				t.Errorf("received %v", got)
			}
		}
	})
	t.Run("an address no group admits is refused", func(t *testing.T) {
		refused := make(chan error, 1)
		s := &cs104.Server{Groups: []*cs104.Group{{Allow: func(net.Addr) bool { return false }}},
			OnRefused: func(_ net.Addr, err error) { refused <- err }}
		addr := serve(t, s)
		_, _ = cs104.Dial(ctx, addr, cs104.LinkConfig{T1: time.Second, T2: 500 * time.Millisecond})
		select {
		case err := <-refused:
			if err != cs104.ErrNoGroup {
				t.Errorf("refused with %v", err)
			}
		case <-time.After(3 * time.Second):
			t.Fatal("not refused")
		}
	})
	t.Run("the most connections of a group", func(t *testing.T) {
		g := &cs104.Group{MaxConnections: 1}
		refused := make(chan error, 1)
		addr := serve(t, &cs104.Server{Groups: []*cs104.Group{g}, OnRefused: func(_ net.Addr, err error) { refused <- err }})
		a, err := cs104.DialStandby(ctx, addr, cs104.LinkConfig{})
		if err != nil {
			t.Fatal(err)
		}
		defer a.Close()
		eventually(t, 2*time.Second, "one connection", func() bool { return g.Links() == 1 })
		_, _ = cs104.DialStandby(ctx, addr, cs104.LinkConfig{})
		select {
		case err := <-refused:
			if err != cs104.ErrGroupFull {
				t.Errorf("refused with %v", err)
			}
		case <-time.After(3 * time.Second):
			t.Fatal("not refused")
		}
	})
}

// station answers the system commands a Client sends, mirroring them.
func station(t *testing.T) *cs104.Client {
	t.Helper()
	prm := iec60870.Params{}.WithDefaults()
	g := &cs104.Group{}
	g.OnASDU = func(l *cs104.Link, b []byte) {
		a, err := iec60870.DecodeASDU(b, prm, time.UTC)
		if err != nil {
			return
		}
		reply := func(c iec60870.Cause, neg bool) {
			m := *a
			m.Cause, m.Negative = c, neg
			out, _ := m.Encode(prm, time.UTC)
			_ = l.Send(context.Background(), out)
		}
		switch a.Type {
		case iec60870.CTsTa1, iec60870.CRpNa1:
			reply(iec60870.CauseActCon, a.Type == iec60870.CRpNa1 && a.Objects[0].Value > 2)
		case iec60870.CCiNa1:
			reply(iec60870.CauseActCon, false)
			if _, frz := iec60870.SplitQCC(uint8(a.Objects[0].Value)); frz == iec60870.FRZRead {
				reply(iec60870.CauseActTerm, false)
			}
		}
	}
	addr := serve(t, &cs104.Server{Groups: []*cs104.Group{g}})
	l, err := cs104.Dial(context.Background(), addr, cs104.LinkConfig{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(l.Close)
	return cs104.NewClient(l, cs104.ClientConfig{CA: 1, Timeout: 2 * time.Second})
}

// Covers: SIG-IPE-1326
func TestClientSystemCommands(t *testing.T) {
	c := station(t)
	ctx := context.Background()
	if err := c.CounterInterrogate(ctx, iec60870.QCC(iec60870.RQTGeneral, iec60870.FRZRead), time.Second); err != nil {
		t.Errorf("counter read: %v", err)
	}
	if err := c.CounterInterrogate(ctx, iec60870.QCC(1, iec60870.FRZFreeze), time.Second); err != nil {
		t.Errorf("counter freeze (no termination): %v", err)
	}
	if err := c.ResetProcess(ctx, iec60870.QRPGeneral); err != nil {
		t.Errorf("reset: %v", err)
	}
	if err := c.ResetProcess(ctx, 7); err == nil {
		t.Error("a refused reset succeeded")
	}
	if err := c.Test(ctx, 0xbeef, time.Now()); err != nil {
		t.Errorf("test: %v", err)
	}
}
