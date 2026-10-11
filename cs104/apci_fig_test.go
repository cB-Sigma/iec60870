package cs104_test

import (
	"bufio"
	"context"
	"errors"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/cB-Sigma/iec60870"
	"github.com/cB-Sigma/iec60870/cs104"
)

// peer is a scripted controlled station (station B of Figures 9 to 18):
// the test writes and reads single APDUs on the TCP connection.
type peer struct {
	t *testing.T
	c net.Conn
	r *bufio.Reader
}

// connect opens a TCP connection to a fresh listener and returns both ends.
func connect(t *testing.T) (net.Conn, *peer) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	acc := make(chan net.Conn, 1)
	go func() {
		c, _ := ln.Accept()
		acc <- c
	}()
	c, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	s := <-acc
	t.Cleanup(func() { _ = c.Close(); _ = s.Close() })
	return c, &peer{t: t, c: s, r: bufio.NewReader(s)}
}

func (p *peer) write(a cs104.APDU) {
	p.t.Helper()
	b, err := a.Encode()
	if err != nil {
		p.t.Fatal(err)
	}
	if _, err := p.c.Write(b); err != nil {
		p.t.Fatalf("writing %s: %v", a, err)
	}
}

func (p *peer) read() cs104.APDU {
	p.t.Helper()
	_ = p.c.SetReadDeadline(time.Now().Add(3 * time.Second))
	a, err := cs104.ReadAPDU(p.r)
	if err != nil {
		p.t.Fatalf("station B expected a frame: %v", err)
	}
	return a
}

// expect reads one frame and checks it is want.
func (p *peer) expect(want cs104.APDU) {
	p.t.Helper()
	got := p.read()
	if got.Format != want.Format || got.U != want.U || got.RecvSeq != want.RecvSeq ||
		(want.Format == cs104.FormatI && got.SendSeq != want.SendSeq) {
		p.t.Fatalf("station B received %s, want %s", got, want)
	}
}

// expectClose reads until the connection ends and fails on any frame but
// the allowed ones.
func (p *peer) expectClose(within time.Duration) {
	p.t.Helper()
	_ = p.c.SetReadDeadline(time.Now().Add(within))
	for {
		a, err := cs104.ReadAPDU(p.r)
		if err != nil {
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				p.t.Fatal("the controlling station did not close the connection")
			}
			return
		}
		p.t.Fatalf("station B received %s where the connection should close", a)
	}
}

func u(f uint8) cs104.APDU   { return cs104.APDU{Format: cs104.FormatU, U: f} }
func sf(n uint16) cs104.APDU { return cs104.APDU{Format: cs104.FormatS, RecvSeq: n} }
func ifr(ns, nr uint16) cs104.APDU {
	return cs104.APDU{Format: cs104.FormatI, SendSeq: ns, RecvSeq: nr, ASDU: []byte{byte(iec60870.MSpNa1), 1, 3, 0, 1, 0, 1, 0, 0, 1}}
}

// started runs Start against the peer, which confirms STARTDT.
func started(t *testing.T, cfg cs104.LinkConfig) (*cs104.Link, *peer) {
	t.Helper()
	c, p := connect(t)
	type res struct {
		l   *cs104.Link
		err error
	}
	done := make(chan res, 1)
	go func() {
		l, err := cs104.Start(context.Background(), c, cfg)
		done <- res{l, err}
	}()
	p.expect(u(cs104.UStartDTAct))
	p.write(u(cs104.UStartDTCon))
	r := <-done
	if r.err != nil {
		t.Fatal(r.err)
	}
	t.Cleanup(r.l.Close)
	return r.l, p
}

func recvASDU(t *testing.T, l *cs104.Link) {
	t.Helper()
	select {
	case <-l.ASDUs():
	case <-time.After(2 * time.Second):
		t.Fatal("the ASDU was not delivered")
	}
}

func closedWith(t *testing.T, l *cs104.Link, within time.Duration, want string) {
	t.Helper()
	select {
	case <-l.Done():
		if !strings.Contains(l.Err().Error(), want) {
			t.Errorf("the link ended with %q, want it to mention %q", l.Err(), want)
		}
	case <-time.After(within):
		t.Fatalf("the link did not close (want %q)", want)
	}
}

func alive(t *testing.T, l *cs104.Link) {
	t.Helper()
	select {
	case <-l.Done():
		t.Fatalf("the link closed: %v", l.Err())
	default:
	}
}

// Covers: SIG-IPE-880
func TestAPCIFixedControlBits(t *testing.T) {
	for _, c := range []struct {
		name string
		b    []byte
		ok   bool
	}{
		{"I-frame", []byte{0x02, 0x00, 0x04, 0x00, 0x64}, true},
		{"I-frame with bit 1 of octet 3 set", []byte{0x02, 0x00, 0x05, 0x00, 0x64}, false},
		{"S-frame", []byte{0x01, 0x00, 0x06, 0x00}, true},
		{"S-frame with octet 2 set", []byte{0x01, 0x01, 0x06, 0x00}, false},
		{"S-frame with bit 1 of octet 3 set", []byte{0x01, 0x00, 0x07, 0x00}, false},
		{"S-frame with octet 1 bits 3 to 8 set", []byte{0x05, 0x00, 0x06, 0x00}, false},
		{"TESTFR act", []byte{0x43, 0x00, 0x00, 0x00}, true},
		{"U-frame with octet 2 set", []byte{0x43, 0x01, 0x00, 0x00}, false},
		{"U-frame with octet 3 set", []byte{0x07, 0x00, 0x01, 0x00}, false},
		{"U-frame with octet 4 set", []byte{0x0b, 0x00, 0x00, 0x80}, false},
		{"two U functions", []byte{0x0f, 0x00, 0x00, 0x00}, false},
	} {
		_, err := cs104.ParseAPDU(c.b)
		if c.ok != (err == nil) {
			t.Errorf("%s (% x): err = %v", c.name, c.b, err)
		}
		if err != nil && !errors.Is(err, cs104.ErrFrame) {
			t.Errorf("%s: error %v does not wrap ErrFrame", c.name, err)
		}
	}
}

// Covers: SIG-IPE-881
func TestAPCIAcknowledgeAndWrap(t *testing.T) {
	t.Run("N(R) acknowledges the frames numbered below it (Amd 1 5.1)", func(t *testing.T) {
		l, p := started(t, cs104.LinkConfig{T1: 5 * time.Second, T2: time.Second})
		for i := 0; i < 3; i++ {
			if err := l.Send(context.Background(), gi(t)); err != nil {
				t.Fatal(err)
			}
			p.expect(ifr(uint16(i), 0))
		}
		p.write(sf(2)) // frames 0 and 1
		eventually(t, time.Second, "one frame outstanding", func() bool { return l.Stats().Outstanding == 1 })
		p.write(sf(3))
		eventually(t, time.Second, "none outstanding", func() bool { return l.Stats().Outstanding == 0 })
		p.write(sf(3)) // repeating an acknowledgement is harmless
		time.Sleep(50 * time.Millisecond)
		alive(t, l)
		p.write(sf(5)) // beyond V(S) = 3
		closedWith(t, l, 2*time.Second, "acknowledged up to 5")
	})
	t.Run("an acknowledgement below the last one closes the link", func(t *testing.T) {
		l, p := started(t, cs104.LinkConfig{T1: 5 * time.Second, T2: time.Second})
		for i := 0; i < 2; i++ {
			_ = l.Send(context.Background(), gi(t))
			p.read()
		}
		p.write(sf(2))
		p.write(sf(1))
		closedWith(t, l, 2*time.Second, "acknowledged up to 1")
	})
	t.Run("receive sequence numbers wrap from 32767 to 0", func(t *testing.T) {
		l, p := started(t, cs104.LinkConfig{K: 12, W: 8, T1: 10 * time.Second, T2: 5 * time.Second, T3: 20 * time.Second})
		const n = 32768 + 16
		go func() {
			for range n {
				<-l.ASDUs()
			}
		}()
		lastS := make(chan uint16, 1)
		go func() {
			var last uint16
			wrapped := false
			for {
				_ = p.c.SetReadDeadline(time.Now().Add(10 * time.Second))
				a, err := cs104.ReadAPDU(p.r)
				if err != nil {
					lastS <- last
					return
				}
				if a.Format == cs104.FormatS {
					wrapped = wrapped || last > 32000 && a.RecvSeq < 100
					last = a.RecvSeq
					if wrapped && last == 16 {
						lastS <- last
						return
					}
				}
			}
		}()
		w := bufio.NewWriterSize(p.c, 1<<16)
		for i := range n {
			b, _ := ifr(uint16(i%32768), 0).Encode()
			_, _ = w.Write(b)
		}
		_ = w.Flush()
		if got := <-lastS; got != 16 {
			t.Fatalf("last acknowledgement N(R) = %d, want 16 (32784 mod 32768)", got)
		}
		alive(t, l)
		if st := l.Stats(); st.IReceived != n {
			t.Errorf("received %d I-frames, want %d", st.IReceived, n)
		}
	})
	t.Run("send sequence numbers wrap from 32767 to 0", func(t *testing.T) {
		l, p := started(t, cs104.LinkConfig{K: 12, W: 8, T1: 10 * time.Second, T2: 5 * time.Second, T3: 20 * time.Second})
		const n = 32768 + 4
		bad := make(chan string, 1)
		go func() {
			for i := range n {
				_ = p.c.SetReadDeadline(time.Now().Add(10 * time.Second))
				a, err := cs104.ReadAPDU(p.r)
				if err != nil || a.Format != cs104.FormatI || a.SendSeq != uint16(i%32768) {
					bad <- a.String()
					return
				}
				b, _ := sf(uint16((i + 1) % 32768)).Encode()
				_, _ = p.c.Write(b)
			}
			bad <- ""
		}()
		asdu := gi(t)
		for i := range n {
			if err := l.Send(context.Background(), asdu); err != nil {
				t.Fatalf("send %d: %v", i, err)
			}
		}
		if b := <-bad; b != "" {
			t.Fatalf("station B received %s out of order", b)
		}
		eventually(t, time.Second, "all acknowledged", func() bool { return l.Stats().Outstanding == 0 })
	})
}

// Covers: SIG-IPE-882
func TestAPCIFigures9To14(t *testing.T) {
	t.Run("Figure 9: undisturbed I-frames acknowledge each other", func(t *testing.T) {
		l, p := started(t, cs104.LinkConfig{T1: 600 * time.Millisecond, T2: 500 * time.Millisecond})
		for i := uint16(0); i < 3; i++ {
			p.write(ifr(i, 0))
			recvASDU(t, l)
		}
		for i := uint16(0); i < 2; i++ {
			if err := l.Send(context.Background(), gi(t)); err != nil {
				t.Fatal(err)
			}
			p.expect(ifr(i, 3)) // I(0,3), I(1,3): N(R) carries our V(R)
		}
		p.write(ifr(3, 2)) // acknowledges both of ours
		recvASDU(t, l)
		time.Sleep(800 * time.Millisecond) // longer than t1
		alive(t, l)
		if st := l.Stats(); st.Outstanding != 0 {
			t.Errorf("%d frames outstanding after I(3,2)", st.Outstanding)
		}
	})
	t.Run("Figure 10: I-frames acknowledged by an S-frame", func(t *testing.T) {
		l, p := started(t, cs104.LinkConfig{K: 3, W: 2, T1: 2 * time.Second, T2: time.Second})
		p.write(ifr(0, 0))
		p.write(ifr(1, 0))
		recvASDU(t, l)
		recvASDU(t, l)
		p.expect(sf(2))
	})
	t.Run("Figure 11: a sequence gap closes the connection", func(t *testing.T) {
		l, p := started(t, cs104.LinkConfig{T1: 2 * time.Second, T2: time.Second})
		p.write(ifr(0, 0))
		p.write(ifr(2, 0))
		closedWith(t, l, 2*time.Second, "expected I-frame 1, got 2")
		p.expectClose(2 * time.Second)
	})
	t.Run("Figure 12: t1 expires on an unacknowledged I-frame", func(t *testing.T) {
		l, p := started(t, cs104.LinkConfig{T1: 300 * time.Millisecond, T2: 100 * time.Millisecond})
		start := time.Now()
		_ = l.Send(context.Background(), gi(t))
		p.expect(ifr(0, 0))
		closedWith(t, l, 2*time.Second, "t1 expired: I-frame 0")
		if d := time.Since(start); d < 300*time.Millisecond {
			t.Errorf("closed after %s, before t1", d)
		}
	})
	t.Run("Figure 13: undisturbed test procedure", func(t *testing.T) {
		l, p := started(t, cs104.LinkConfig{T1: 400 * time.Millisecond, T2: 200 * time.Millisecond, T3: 200 * time.Millisecond})
		for range 3 {
			p.expect(u(cs104.UTestFRAct))
			p.write(u(cs104.UTestFRCon))
		}
		alive(t, l)
		// A test frame from station B is confirmed too.
		p.write(u(cs104.UTestFRAct))
		for {
			a := p.read()
			if a.U == cs104.UTestFRCon {
				break
			}
			if a.U != cs104.UTestFRAct {
				t.Fatalf("unexpected %s", a)
			}
			p.write(u(cs104.UTestFRCon))
		}
	})
	t.Run("Figure 14: unconfirmed test procedure closes after t1", func(t *testing.T) {
		l, p := started(t, cs104.LinkConfig{T1: 300 * time.Millisecond, T2: 100 * time.Millisecond, T3: 200 * time.Millisecond})
		p.expect(u(cs104.UTestFRAct))
		closedWith(t, l, 2*time.Second, "no TESTFR confirmation")
	})
	t.Run("5.2: any received frame retriggers t3", func(t *testing.T) {
		l, p := started(t, cs104.LinkConfig{T1: time.Second, T2: 500 * time.Millisecond, T3: 300 * time.Millisecond})
		got := make(chan cs104.APDU, 16)
		go func() {
			for {
				_ = p.c.SetReadDeadline(time.Now().Add(2 * time.Second))
				a, err := cs104.ReadAPDU(p.r)
				if err != nil {
					close(got)
					return
				}
				got <- a
			}
		}()
		// Station B tests every 150 ms: A has no idle period to test.
		for range 8 {
			p.write(u(cs104.UTestFRAct))
			time.Sleep(150 * time.Millisecond)
		}
		if n := l.Stats().TestFRSent; n != 0 {
			t.Errorf("A sent %d TESTFR act although frames kept arriving", n)
		}
		for len(got) > 0 {
			if a := <-got; a.U != cs104.UTestFRCon {
				t.Errorf("unexpected %s", a)
			}
		}
	})
}

// Covers: SIG-IPE-883
func TestAPCIStartProcedure(t *testing.T) {
	start := func(t *testing.T, cfg cs104.LinkConfig) (*peer, chan error) {
		c, p := connect(t)
		done := make(chan error, 1)
		go func() {
			l, err := cs104.Start(context.Background(), c, cfg)
			if l != nil {
				t.Cleanup(l.Close)
			}
			done <- err
		}()
		p.expect(u(cs104.UStartDTAct))
		return p, done
	}
	cfg := cs104.LinkConfig{T1: 400 * time.Millisecond, T2: 200 * time.Millisecond}
	t.Run("Figure 15: STARTDT con starts data transfer; other U-frames are ignored meanwhile", func(t *testing.T) {
		p, done := start(t, cfg)
		p.write(u(cs104.UTestFRCon))
		p.write(u(cs104.UStopDTCon))
		p.write(u(cs104.UTestFRAct))
		p.expect(u(cs104.UTestFRCon))
		p.write(u(cs104.UStartDTCon))
		if err := <-done; err != nil {
			t.Fatal(err)
		}
	})
	t.Run("Figure 15: no STARTDT con within t1 closes the connection", func(t *testing.T) {
		p, done := start(t, cfg)
		if err := <-done; err == nil || !strings.Contains(err.Error(), "no STARTDT confirmation") {
			t.Errorf("Start = %v", err)
		}
		p.expectClose(time.Second)
	})
	for _, f := range []cs104.APDU{sf(0), ifr(0, 0)} {
		t.Run("Figure 18: "+f.String()+" while pending started closes the connection", func(t *testing.T) {
			p, done := start(t, cfg)
			p.write(f)
			if err := <-done; err == nil || !strings.Contains(err.Error(), "pending start") {
				t.Errorf("Start = %v", err)
			}
			p.expectClose(time.Second)
		})
	}
}

// Covers: SIG-IPE-884
func TestAPCIStopProcedure(t *testing.T) {
	cfg := cs104.LinkConfig{K: 12, W: 8, T1: 500 * time.Millisecond, T2: 400 * time.Millisecond, T3: 10 * time.Second}
	t.Run("Figures 16 and 18: acknowledge, STOPDT act, immediate acknowledgement, STOPDT con", func(t *testing.T) {
		l, p := started(t, cfg)
		p.write(ifr(0, 0))
		p.write(ifr(1, 0))
		recvASDU(t, l)
		recvASDU(t, l)
		stopped := make(chan error, 1)
		go func() { stopped <- l.StopDT(context.Background()) }()
		p.expect(sf(2)) // received data confirmed before STOPDT act
		p.expect(u(cs104.UStopDTAct))
		if err := l.Send(context.Background(), gi(t)); !errors.Is(err, cs104.ErrStopped) {
			t.Errorf("Send while stopping = %v, want ErrStopped", err)
		}
		p.write(ifr(2, 0)) // pending data from B
		recvASDU(t, l)
		p.expect(sf(3)) // acknowledged at once, not after w or t2
		p.write(u(cs104.UStopDTCon))
		if err := <-stopped; err != nil || l.Started() {
			t.Fatalf("StopDT = %v, started %v", err, l.Started())
		}
		// Stopped: the idle connection stays open.
		time.Sleep(600 * time.Millisecond)
		alive(t, l)
	})
	t.Run("STOPDT act stops queued I-frames at once", func(t *testing.T) {
		l, p := started(t, cs104.LinkConfig{K: 1, W: 1, T1: 2 * time.Second, T2: time.Second})
		if err := l.Send(context.Background(), gi(t)); err != nil {
			t.Fatal(err)
		}
		p.expect(ifr(0, 0))
		queued := make(chan error, 1)
		go func() { queued <- l.Send(context.Background(), gi(t)) }() // waits for the k window
		time.Sleep(50 * time.Millisecond)
		stopped := make(chan error, 1)
		go func() { stopped <- l.StopDT(context.Background()) }()
		p.expect(u(cs104.UStopDTAct))
		if err := <-queued; !errors.Is(err, cs104.ErrStopped) {
			t.Errorf("queued Send = %v, want ErrStopped", err)
		}
		// Pending unconfirmed stopped: B acknowledges, then confirms.
		p.write(sf(1))
		p.write(u(cs104.UStopDTCon))
		if err := <-stopped; err != nil {
			t.Fatal(err)
		}
		if st := l.Stats(); st.ISent != 1 || st.Outstanding != 0 {
			t.Errorf("sent %d, outstanding %d; want 1, 0", st.ISent, st.Outstanding)
		}
	})
	t.Run("Figure 16: no STOPDT con within t1 closes the connection", func(t *testing.T) {
		l, p := started(t, cfg)
		go func() { _ = l.StopDT(context.Background()) }()
		p.expect(u(cs104.UStopDTAct))
		closedWith(t, l, 2*time.Second, "no STOPDT confirmation")
	})
	t.Run("Figure 18: an unsolicited STOPDT con is ignored", func(t *testing.T) {
		l, p := started(t, cfg)
		p.write(u(cs104.UStopDTCon))
		p.write(u(cs104.UStartDTCon))
		p.write(ifr(0, 0))
		recvASDU(t, l)
		alive(t, l)
		if !l.Started() {
			t.Error("the link left the started state")
		}
	})
}

// Covers: SIG-IPE-885
func TestAPCIStoppedConnection(t *testing.T) {
	cfg := cs104.LinkConfig{K: 12, W: 1, T1: 500 * time.Millisecond, T2: 400 * time.Millisecond, T3: 10 * time.Second}
	for _, f := range []cs104.APDU{ifr(0, 0), sf(0)} {
		t.Run("Figure 18 and 10.6: "+f.String()+" on a stopped connection closes it unacknowledged", func(t *testing.T) {
			c, p := connect(t)
			l := cs104.Open(context.Background(), c, cfg)
			t.Cleanup(l.Close)
			p.write(u(cs104.UTestFRAct)) // U-frames are valid while stopped
			p.expect(u(cs104.UTestFRCon))
			p.write(f)
			closedWith(t, l, 2*time.Second, "while the connection is stopped")
			p.expectClose(time.Second) // no S-frame: nothing is acknowledged
			if st := l.Stats(); st.IReceived != 0 || st.SSent != 0 {
				t.Errorf("stats %+v", st)
			}
		})
	}
	t.Run("user data cannot be sent on a stopped connection", func(t *testing.T) {
		c, _ := connect(t)
		l := cs104.Open(context.Background(), c, cfg)
		t.Cleanup(l.Close)
		if err := l.Send(context.Background(), gi(t)); !errors.Is(err, cs104.ErrStopped) {
			t.Errorf("Send = %v", err)
		}
		if err := l.StopDT(context.Background()); err == nil || !strings.Contains(err.Error(), "stopped") {
			t.Errorf("StopDT on a stopped link = %v", err)
		}
	})
}

// Covers: SIG-IPE-894
func TestLinkParameterRanges(t *testing.T) {
	ok := cs104.LinkConfig{}.WithDefaults()
	if ok.K != 12 || ok.W != 8 || ok.T0 != 30*time.Second || ok.T1 != 15*time.Second || ok.T2 != 10*time.Second || ok.T3 != 20*time.Second {
		t.Errorf("defaults %+v differ from clause 9.6", ok)
	}
	if err := ok.Validate(); err != nil {
		t.Fatal(err)
	}
	for name, c := range map[string]cs104.LinkConfig{
		"k above 32767":   {K: 32768, W: 8},
		"t0 above 255 s":  {T0: 256 * time.Second},
		"t1 above 255 s":  {T1: 256 * time.Second, T2: 10 * time.Second},
		"t2 above 255 s":  {T1: 255 * time.Second, T2: 256 * time.Second},
		"t3 above 48 h":   {T3: 49 * time.Hour},
		"t2 not below t1": {T1: 10 * time.Second, T2: 10 * time.Second},
	} {
		if err := c.WithDefaults().Validate(); err == nil {
			t.Errorf("%s was accepted", name)
		}
	}
	// w above 2/3 k is a recommendation: CheckWindow reports it, Validate
	// accepts it.
	if c := (cs104.LinkConfig{K: 12, W: 9}).WithDefaults(); c.CheckWindow() == nil || c.Validate() != nil {
		t.Error("w above 2/3 k: not reported by CheckWindow, or refused by Validate")
	}
	if err := (cs104.LinkConfig{K: 32767, W: 8, T0: 255 * time.Second, T1: 255 * time.Second, T2: 254 * time.Second, T3: 48 * time.Hour}).Validate(); err != nil {
		t.Errorf("the largest values were refused: %v", err)
	}
}
