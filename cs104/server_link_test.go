package cs104_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/cB-Sigma/iec60870/cs104"
)

// accepted runs the controlled station's side on one end of a TCP
// connection; the peer scripts the controlling station.
func accepted(t *testing.T, cfg cs104.LinkConfig, onStart func(*cs104.Link)) (*cs104.Link, *peer) {
	t.Helper()
	c, p := connect(t)
	l := cs104.Accept(context.Background(), c, cfg, onStart, nil)
	t.Cleanup(l.Close)
	return l, p
}

// Covers: SIG-IPE-896
func TestServerLinkFigure17(t *testing.T) {
	cfg := cs104.LinkConfig{T1: time.Second, T2: 500 * time.Millisecond, T3: 10 * time.Second}
	for _, f := range []cs104.APDU{ifr(0, 0), sf(0)} {
		t.Run("STOPPED: "+f.String()+" closes", func(t *testing.T) {
			l, p := accepted(t, cfg, nil)
			p.write(u(cs104.UTestFRAct))
			p.expect(u(cs104.UTestFRCon))
			if err := l.Send(context.Background(), gi(t)); !errors.Is(err, cs104.ErrStopped) {
				t.Errorf("Send while stopped = %v", err)
			}
			p.write(f)
			closedWith(t, l, 2*time.Second, "stopped")
			p.expectClose(time.Second)
		})
	}
	t.Run("STARTDT act is confirmed after onStart; STOPDT act without unconfirmed frames at once", func(t *testing.T) {
		called := make(chan bool, 1)
		l, p := accepted(t, cfg, func(*cs104.Link) { called <- true })
		p.write(u(cs104.UStartDTAct))
		p.expect(u(cs104.UStartDTCon))
		if !<-called || !l.Started() {
			t.Fatal("not started")
		}
		if err := l.StartDT(context.Background()); err == nil {
			t.Error("a controlled station sent STARTDT")
		}
		p.write(ifr(0, 0))
		recvASDU(t, l)
		p.write(u(cs104.UStopDTAct))
		p.expect(u(cs104.UStopDTCon))
		if !l.Stopped() {
			t.Error("not stopped")
		}
	})
	t.Run("pending unconfirmed stopped: STOPDT con after the S-frame", func(t *testing.T) {
		l, p := accepted(t, cfg, nil)
		p.write(u(cs104.UStartDTAct))
		p.expect(u(cs104.UStartDTCon))
		if err := l.Send(context.Background(), gi(t)); err != nil {
			t.Fatal(err)
		}
		p.expect(ifr(0, 0))
		p.write(u(cs104.UStopDTAct))
		p.write(u(cs104.UTestFRAct))
		p.expect(u(cs104.UTestFRCon)) // no STOPDT con yet
		if err := l.Send(context.Background(), gi(t)); !errors.Is(err, cs104.ErrStopped) {
			t.Errorf("Send while stopping = %v", err)
		}
		p.write(sf(1))
		p.expect(u(cs104.UStopDTCon))
	})
	t.Run("pending unconfirmed stopped: an I-frame closes", func(t *testing.T) {
		l, p := accepted(t, cfg, nil)
		p.write(u(cs104.UStartDTAct))
		p.expect(u(cs104.UStartDTCon))
		_ = l.Send(context.Background(), gi(t))
		p.expect(ifr(0, 0))
		p.write(u(cs104.UStopDTAct))
		p.write(ifr(0, 1))
		closedWith(t, l, 2*time.Second, "pending stop")
	})
	t.Run("10.6: unacknowledged ASDUs are kept when the link ends", func(t *testing.T) {
		l, p := accepted(t, cs104.LinkConfig{T1: 5 * time.Second, T2: time.Second, T3: 10 * time.Second}, nil)
		p.write(u(cs104.UStartDTAct))
		p.expect(u(cs104.UStartDTCon))
		a, b := gi(t), append(gi(t)[:0:0], gi(t)...)
		b[len(b)-1] = 21
		_ = l.Send(context.Background(), a)
		_ = l.Send(context.Background(), b)
		p.read()
		p.read()
		p.write(sf(1))
		time.Sleep(50 * time.Millisecond)
		_ = p.c.Close()
		un := l.Unacked()
		if len(un) != 1 || un[0][len(un[0])-1] != 21 {
			t.Errorf("unacknowledged = %v, want the second ASDU", un)
		}
	})
}
