package cs104

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/cB-Sigma/iec60870/sec"

	"github.com/cB-Sigma/iotsec"
)

// LinkConfig holds the protocol parameters of one connection (IEC
// 60870-5-104 clauses 5.5 and 9.6 give the defaults used here).
type LinkConfig struct {
	K  int           // most unacknowledged I-frames we send (default 12)
	W  int           // we acknowledge at the latest after W received I-frames (default 8)
	T0 time.Duration // connection establishment (default 30s)
	T1 time.Duration // acknowledgement of a sent I- or U-frame (default 15s)
	T2 time.Duration // we acknowledge received I-frames within T2 (default 10s)
	T3 time.Duration // idle time before a TESTFR (default 20s)
	// TLS, when set, secures the connections Dial and DialStandby open
	// (IEC 62351-3: TLS 1.2 or later, mutual authentication with
	// certificates). iotsec.StdTLS uses crypto/tls; an IEC 62351-3 profile
	// may also renew keys and recheck certificates on the connection, end
	// a connection whose peer does not take part (the caller reconnects),
	// and send a TESTFR act before a timed key update on an idle link
	// (iotsec.KeepaliveConn). The certificate is checked against
	// iotsec.ServerNameFor(TLS, addr).
	TLS iotsec.TLSClient
	// Dialer opens the TCP connections of Dial and DialStandby; nil uses a
	// net.Dialer.
	Dialer iotsec.Dialer
	// Security, when set, applies the IEC TS 60870-5-7 A-Profile to the
	// ASDUs of the link (shared by the links of one association).
	Security *sec.SecureLink
}

// WithDefaults fills zero values with the standard defaults.
func (c LinkConfig) WithDefaults() LinkConfig {
	if c.K <= 0 {
		c.K = 12
	}
	if c.W <= 0 {
		c.W = 8
	}
	if c.T0 <= 0 {
		c.T0 = 30 * time.Second
	}
	if c.T1 <= 0 {
		c.T1 = 15 * time.Second
	}
	if c.T2 <= 0 {
		c.T2 = 10 * time.Second
	}
	if c.T3 <= 0 {
		c.T3 = 20 * time.Second
	}
	return c
}

// Validate checks the parameter ranges of clause 9.6 (k and w 1 to
// 32767, t0 to t2 at most 255 s, t3 at most 48 h) and that t2 is shorter
// than t1. Timeouts below the standard's 1 s minimum are accepted
// (sub-second values serve tests and labs). The recommended ratio of w to
// k is CheckWindow's.
func (c LinkConfig) Validate() error {
	if c.K < 1 || c.K > 32767 || c.W < 1 || c.W > 32767 {
		return fmt.Errorf("k (%d) and w (%d) must be 1 to 32767", c.K, c.W)
	}
	for _, t := range []struct {
		name string
		d    time.Duration
	}{{"t0", c.T0}, {"t1", c.T1}, {"t2", c.T2}} {
		if t.d > 255*time.Second {
			return fmt.Errorf("%s (%s) exceeds 255 s", t.name, t.d)
		}
	}
	if c.T3 > 48*time.Hour {
		return fmt.Errorf("t3 (%s) exceeds 48 h", c.T3)
	}
	if c.T2 >= c.T1 {
		return fmt.Errorf("t2 (%s) must be shorter than t1 (%s)", c.T2, c.T1)
	}
	return nil
}

// CheckWindow reports a w above two thirds of k, which clause 9.6
// recommends against (acknowledgements come late and the sender stalls at
// k); such links still work.
func (c LinkConfig) CheckWindow() error {
	if c.W > c.K*2/3 {
		return fmt.Errorf("w (%d) should not exceed two thirds of k (%d)", c.W, c.K)
	}
	return nil
}

// Link is a controlling station's connection to a controlled station. It
// numbers and acknowledges I-frames, enforces the k and w windows and runs
// the t1, t2 and t3 timers. A link from Dial or Start is in data transfer
// (STARTDT); one from DialStandby or Open is a standby connection of a
// redundancy group (IEC 60870-5-104 edition 2): stopped (STOPDT), tested
// with TESTFR after t3 of silence, and started with StartDT on failover.
// Link errors close it; the caller reconnects.
type Link struct {
	conn    net.Conn
	cfg     LinkConfig
	in      chan []byte // received ASDUs
	out     chan outFrame
	ctl     chan ctlReq
	ka      chan chan error // keepalive requests from the TLS profile (keepalive)
	done    chan struct{}
	ended   chan struct{} // closed when the loop has exited
	started atomic.Bool
	state   atomic.Int32 // dtState

	errOnce sync.Once
	err     error

	stats   LinkStats
	unacked [][]byte // sent and never acknowledged, kept when the link ends
	smu     sync.Mutex

	// server is set for the controlled station's side (Accept): STARTDT
	// and STOPDT acts are received and confirmed (Figures 17 and 36).
	server bool
	// onStart runs when a STARTDT act is accepted, once the connection is
	// started (with its A-Profile attached) and before the confirmation
	// goes out (a redundancy group closes its other started connections
	// there). It must not call Send.
	onStart func(*Link)
	// onAck receives the ASDUs an N(R) acknowledged, in order (from the
	// link's loop: it must not block or call Send).
	onAck func([][]byte)
	// secOut carries the A-Profile's own messages to send (Security set).
	secOut chan []sec.Frame
}

// LinkStats counts frames, for tests and diagnostics.
type LinkStats struct {
	ISent, IReceived, SSent, TestFRSent int
	MaxOutstanding                      int // most unacknowledged I-frames at once
	Outstanding                         int // I-frames sent and not yet acknowledged
}

type outFrame struct {
	asdu []byte
	ack  []byte // what onAck and Unacked report: the application ASDU (nil for a segment or a security message)
	sent chan error
}

// ctlReq asks the loop to send a STARTDT or STOPDT act and to report its
// confirmation.
type ctlReq struct {
	u    uint8
	done chan error
}

// ErrClosed is returned by Send on a closed link.
var ErrClosed = errors.New("the connection is closed")

// ErrStopped is returned by Send while data transfer is stopped.
var ErrStopped = errors.New("data transfer is stopped (STOPDT)")

// Dial connects to addr, starts data transfer (STARTDT) and returns the
// running link.
func Dial(ctx context.Context, addr string, cfg LinkConfig) (*Link, error) {
	cfg = cfg.WithDefaults()
	conn, err := dial(ctx, addr, cfg)
	if err != nil {
		return nil, err
	}
	return Start(ctx, conn, cfg)
}

// DialStandby connects to addr and returns the link in the stopped state
// (STOPDT), as a standby connection.
func DialStandby(ctx context.Context, addr string, cfg LinkConfig) (*Link, error) {
	cfg = cfg.WithDefaults()
	conn, err := dial(ctx, addr, cfg)
	if err != nil {
		return nil, err
	}
	return Open(ctx, conn, cfg), nil
}

// Open runs the protocol over an open connection without starting data
// transfer; StartDT starts it.
func Open(ctx context.Context, conn net.Conn, cfg LinkConfig) *Link {
	cfg = cfg.WithDefaults()
	l := newLink(conn, cfg)
	frames := make(chan APDU, 64)
	r := bufio.NewReader(conn)
	go l.read(r, frames)
	go l.loop(ctx, frames)
	return l
}

// Accept runs the controlled station's side of the protocol over an
// accepted connection (clause 5.3, Figures 17 and 36): the connection
// starts stopped; a STARTDT act calls onStart (when set) and is confirmed;
// a STOPDT act is confirmed at once, or once every I-frame sent is
// acknowledged. An I- or S-frame while stopped, or an I-frame while a
// STOPDT waits for acknowledgements, closes the connection.
//
// onAck, when set, receives the ASDUs each received N(R) acknowledges.
func Accept(ctx context.Context, conn net.Conn, cfg LinkConfig, onStart func(*Link), onAck func([][]byte)) *Link {
	cfg = cfg.WithDefaults()
	l := newLink(conn, cfg)
	l.server, l.onStart, l.onAck = true, onStart, onAck
	frames := make(chan APDU, 64)
	r := bufio.NewReader(conn)
	go l.read(r, frames)
	go l.loop(ctx, frames)
	return l
}

// Unacked returns, once the link has ended, the ASDUs it sent that were
// never acknowledged, oldest first (clause 10.6: they are sent again on
// the connection that takes over).
func (l *Link) Unacked() [][]byte {
	<-l.ended
	l.smu.Lock()
	defer l.smu.Unlock()
	return l.unacked
}

// Stopped reports whether the connection is in the STOPPED state (not
// started, and no start or stop pending).
func (l *Link) Stopped() bool { return dtState(l.state.Load()) == dtStopped }

// RemoteAddr is the peer's address.
func (l *Link) RemoteAddr() net.Addr { return l.conn.RemoteAddr() }

func newLink(conn net.Conn, cfg LinkConfig) *Link {
	l := &Link{conn: conn, cfg: cfg, in: make(chan []byte, 256), out: make(chan outFrame), ctl: make(chan ctlReq),
		ka: make(chan chan error), done: make(chan struct{}), ended: make(chan struct{})}
	// Under an IEC 62351-3 profile a timed key update on an idle link is
	// preceded by a TESTFR act.
	iotsec.SetKeepalive(conn, l.keepalive)
	if cfg.Security != nil {
		l.secOut = make(chan []sec.Frame, 64)
		go l.secSender()
	}
	return l
}

// secSender sends the A-Profile's messages and the Secure Data it released
// from its queue.
func (l *Link) secSender() {
	for {
		select {
		case <-l.done:
			return
		case frames := <-l.secOut:
			for _, f := range frames {
				if l.sendFrame(context.Background(), f.Data, f.Orig) != nil {
					break
				}
			}
		}
	}
}

func dial(ctx context.Context, addr string, cfg LinkConfig) (net.Conn, error) {
	dctx, cancel := context.WithTimeout(ctx, cfg.T0)
	defer cancel()
	var d iotsec.Dialer = cfg.Dialer
	if d == nil {
		d = &net.Dialer{}
	}
	raw, err := d.DialContext(dctx, "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("connecting to %s: %w", addr, err)
	}
	if cfg.TLS == nil {
		return raw, nil
	}
	tc, err := cfg.TLS.Client(dctx, raw, iotsec.ServerNameFor(cfg.TLS, addr))
	if err != nil {
		_ = raw.Close()
		return nil, fmt.Errorf("connecting to %s: TLS handshake: %w", addr, err)
	}
	return tc, nil
}

// Start runs the protocol over an open connection: it sends STARTDT act
// and waits up to t1 for the confirmation (clause 5.3, Figure 15). While
// it waits, U-frames are answered or ignored and an I- or S-frame closes
// the connection (Figure 18, Pending STARTED).
func Start(ctx context.Context, conn net.Conn, cfg LinkConfig) (*Link, error) {
	l := Open(ctx, conn, cfg)
	if err := l.StartDT(ctx); err != nil {
		l.Close()
		return nil, fmt.Errorf("starting data transfer (STARTDT): %w", err)
	}
	return l, nil
}

// ASDUs delivers received ASDUs in order; it is closed with the link.
func (l *Link) ASDUs() <-chan []byte { return l.in }

// Done is closed when the link ends.
func (l *Link) Done() <-chan struct{} { return l.done }

// Err is why the link ended.
func (l *Link) Err() error {
	<-l.done
	return l.err
}

// Started reports whether data transfer is started (STARTDT confirmed and
// no STOPDT since).
func (l *Link) Started() bool { return l.started.Load() }

// StartDT starts data transfer on a stopped link: it sends STARTDT act and
// waits for the confirmation (t1 closes the link if none comes).
func (l *Link) StartDT(ctx context.Context) error { return l.control(ctx, UStartDTAct) }

// StopDT stops data transfer: the link stays open as a standby.
func (l *Link) StopDT(ctx context.Context) error { return l.control(ctx, UStopDTAct) }

func (l *Link) control(ctx context.Context, u uint8) error {
	r := ctlReq{u: u, done: make(chan error, 1)}
	select {
	case l.ctl <- r:
	case <-l.done:
		return fmt.Errorf("%w: %v", ErrClosed, l.err)
	case <-ctx.Done():
		return ctx.Err()
	}
	select {
	case err := <-r.done:
		return err
	case <-l.done:
		return fmt.Errorf("%w: %v", ErrClosed, l.err)
	case <-ctx.Done():
		return ctx.Err()
	}
}

// Stats returns the frame counters.
func (l *Link) Stats() LinkStats {
	l.smu.Lock()
	defer l.smu.Unlock()
	return l.stats
}

// Close ends the link.
func (l *Link) Close() { l.fail(ErrClosed) }

// keepalive sends a TESTFR act unless one is outstanding: the IEC 62351-3
// profile's keepalive before a timed key update on an idle link. Valid in
// every state of the connection, started or stopped.
func (l *Link) keepalive() error {
	r := make(chan error, 1)
	select {
	case l.ka <- r:
	case <-l.done:
		return ErrClosed
	case <-time.After(l.cfg.T1):
		return errors.New("the link is busy")
	}
	select {
	case err := <-r:
		return err
	case <-l.done:
		return ErrClosed
	}
}

func (l *Link) fail(err error) {
	l.errOnce.Do(func() {
		l.err = err
		_ = l.conn.Close()
		close(l.done)
	})
}

// Send queues an ASDU and returns once it is transmitted. While k frames
// are unacknowledged it waits for the window to open. With the A-Profile
// the ASDU goes out as Secure Data segments, or is queued by the security
// layer until a session is established (then Send returns nil at once and
// the ASDU is sent and acknowledged later).
func (l *Link) Send(ctx context.Context, asdu []byte) error {
	if l.cfg.Security == nil {
		return l.sendFrame(ctx, asdu, asdu)
	}
	frames, err := l.cfg.Security.Endpoint().Wrap(asdu)
	if err != nil {
		return err
	}
	for i, f := range frames {
		var ack []byte
		if i == len(frames)-1 {
			ack = asdu
		}
		if err := l.sendFrame(ctx, f, ack); err != nil {
			return err
		}
	}
	return nil
}

func (l *Link) sendFrame(ctx context.Context, asdu, ack []byte) error {
	f := outFrame{asdu: asdu, ack: ack, sent: make(chan error, 1)}
	select {
	case l.out <- f:
	case <-l.done:
		return fmt.Errorf("%w: %v", ErrClosed, l.err)
	case <-ctx.Done():
		return ctx.Err()
	}
	select {
	case err := <-f.sent:
		return err
	case <-l.done:
		return fmt.Errorf("%w: %v", ErrClosed, l.err)
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (l *Link) read(r *bufio.Reader, frames chan<- APDU) {
	for {
		a, err := ReadAPDU(r)
		if err != nil {
			l.fail(fmt.Errorf("reading: %w", err))
			return
		}
		select {
		case frames <- a:
		case <-l.done:
			return
		}
	}
}

// dtState is the controlling station's start/stop state of a connection
// (clause 5.3, Figure 18; Figure 37 for redundancy groups). The two
// pending-stop states of the figures (with and without unconfirmed
// I-frames) behave alike on our side and are one state here.
type dtState uint8

const (
	dtStopped      dtState = iota // STOPPED: only U-frames are valid
	dtPendingStart                // STARTDT act sent, confirmation awaited
	dtStarted                     // STARTED: user data both ways
	dtPendingStop                 // STOPDT act sent, confirmation awaited
)

func (s dtState) String() string {
	return [...]string{"stopped", "pending start", "started", "pending stop"}[s]
}

// loop owns the sequence and start/stop state; every frame is written
// from here.
func (l *Link) loop(ctx context.Context, frames <-chan APDU) {
	defer close(l.in)
	var (
		vs, vr, ack uint16      // next send, next receive, oldest unacknowledged send
		sentAt      []time.Time // send times of unacknowledged I-frames, oldest first
		sentData    [][]byte    // their ASDUs
		unacked     int         // received I-frames not yet acknowledged
		firstRecv   time.Time   // when the oldest of those arrived
		lastRx      = time.Now()
		testSent    time.Time // outstanding TESTFR act
		queue       []outFrame
		state       dtState
		pendAt      time.Time  // when the STARTDT or STOPDT act went out
		pendDone    chan error // its requester
	)
	tick := time.NewTicker(min(l.cfg.T1, l.cfg.T2, l.cfg.T3) / 10)
	defer tick.Stop()
	write := func(a APDU) bool {
		b, err := a.Encode()
		if err == nil {
			_ = l.conn.SetWriteDeadline(time.Now().Add(l.cfg.T1))
			_, err = l.conn.Write(b)
		}
		if err != nil {
			l.fail(fmt.Errorf("writing %s: %w", a, err))
			return false
		}
		return true
	}
	setState := func(s dtState) {
		was := state
		state = s
		l.started.Store(s == dtStarted)
		l.state.Store(int32(s))
		if sec := l.cfg.Security; sec != nil && (s == dtStarted) != (was == dtStarted) {
			if s == dtStarted {
				secStarted(sec, l)
			} else {
				sec.Detach(l)
			}
		}
	}
	sendS := func() bool {
		if !write(APDU{Format: FormatS, RecvSeq: vr}) {
			return false
		}
		unacked = 0
		l.smu.Lock()
		l.stats.SSent++
		l.smu.Unlock()
		return true
	}
	// acknowledge applies a received N(R). As amended in 2016, N(R)
	// acknowledges every I-frame numbered below it (modulo 32768); a
	// number outside the outstanding frames ends the connection.
	acknowledge := func(nr uint16) bool {
		n := seqDiff(ack, nr)
		if n > len(sentAt) {
			l.fail(fmt.Errorf("%w: the controlled station acknowledged up to %d, but the frames outstanding are %d to %d", ErrFrame,
				nr, ack, vs))
			return false
		}
		if n > 0 && l.onAck != nil {
			var acked [][]byte
			for _, a := range sentData[:n] {
				if a != nil {
					acked = append(acked, a)
				}
			}
			if len(acked) > 0 {
				l.onAck(acked)
			}
		}
		sentAt, sentData = sentAt[n:], sentData[n:]
		ack = nr
		l.smu.Lock()
		l.stats.Outstanding = len(sentAt)
		l.smu.Unlock()
		return true
	}
	flush := func() bool {
		for len(queue) > 0 && len(sentAt) < l.cfg.K {
			f := queue[0]
			queue = queue[1:]
			if !write(APDU{Format: FormatI, SendSeq: vs, RecvSeq: vr, ASDU: f.asdu}) {
				f.sent <- l.err
				return false
			}
			// An I-frame acknowledges what we received.
			unacked = 0
			vs = (vs + 1) % seqMod
			sentAt = append(sentAt, time.Now())
			sentData = append(sentData, f.ack)
			l.smu.Lock()
			l.stats.ISent++
			l.stats.MaxOutstanding = max(l.stats.MaxOutstanding, len(sentAt))
			l.stats.Outstanding = len(sentAt)
			l.smu.Unlock()
			f.sent <- nil
		}
		return true
	}
	// dropQueue fails the frames waiting for the k window: STOPDT act
	// stops the transmission of I-frames at once (clause 5.3).
	dropQueue := func() {
		for _, f := range queue {
			f.sent <- ErrStopped
		}
		queue = nil
	}
	finish := func(err error) {
		if pendDone != nil {
			pendDone <- err
			pendDone = nil
		}
	}
	defer func() {
		for _, f := range queue {
			f.sent <- ErrClosed
		}
		finish(ErrClosed)
		var un [][]byte
		for _, a := range sentData {
			if a != nil {
				un = append(un, a)
			}
		}
		l.smu.Lock()
		l.unacked = un
		l.smu.Unlock()
		if l.cfg.Security != nil {
			l.cfg.Security.Detach(l)
		}
		close(l.ended)
	}()
	for {
		select {
		case <-ctx.Done():
			l.fail(ctx.Err())
			return
		case <-l.done:
			return
		case f := <-l.out:
			if state != dtStarted {
				f.sent <- ErrStopped
				continue
			}
			queue = append(queue, f)
			if !flush() {
				return
			}
		case r := <-l.ctl:
			switch {
			case l.server:
				r.done <- errors.New("a controlled station does not send STARTDT or STOPDT")
				continue
			case r.u == UStartDTAct && state != dtStopped, r.u == UStopDTAct && state != dtStarted:
				r.done <- fmt.Errorf("cannot send %s: the connection is %s", APDU{Format: FormatU, U: r.u}, state)
				continue
			}
			if r.u == UStopDTAct {
				// Confirm what we received before stopping (clause 5.3).
				if unacked > 0 && !sendS() {
					r.done <- l.err
					return
				}
				dropQueue()
			}
			if !write(APDU{Format: FormatU, U: r.u}) {
				r.done <- l.err
				return
			}
			pendAt, pendDone = time.Now(), r.done
			if r.u == UStartDTAct {
				setState(dtPendingStart)
			} else {
				setState(dtPendingStop)
			}
		case r := <-l.ka:
			// TESTFR act as the TLS profile's keepalive: at most one is
			// outstanding, and its confirmation is awaited for t1 as for
			// the t3 test (clause 5.2).
			if testSent.IsZero() {
				if !write(APDU{Format: FormatU, U: UTestFRAct}) {
					r <- l.err
					return
				}
				testSent = time.Now()
				lastRx = testSent
				l.smu.Lock()
				l.stats.TestFRSent++
				l.smu.Unlock()
			}
			r <- nil
		case a := <-frames:
			lastRx = time.Now()
			switch a.Format {
			case FormatI:
				// Figure 18: an I-frame on a stopped (or not yet started)
				// connection closes it, unacknowledged (clause 10.6).
				// Figure 17: the controlled station also closes on an I-frame
				// while its STOPDT waits for acknowledgements.
				if state == dtStopped || state == dtPendingStart || l.server && state == dtPendingStop {
					l.fail(fmt.Errorf("%w: I-frame %d received while the connection is %s", ErrFrame, a.SendSeq, state))
					return
				}
				if a.SendSeq != vr {
					l.fail(fmt.Errorf("%w: expected I-frame %d, got %d", ErrFrame, vr, a.SendSeq))
					return
				}
				vr = (vr + 1) % seqMod
				if !acknowledge(a.RecvSeq) {
					return
				}
				if unacked == 0 {
					firstRecv = time.Now()
				}
				unacked++
				l.smu.Lock()
				l.stats.IReceived++
				l.smu.Unlock()
				deliver, ok := a.ASDU, true
				if l.cfg.Security != nil {
					deliver, ok = l.cfg.Security.Unwrap(a.ASDU)
				}
				if ok {
					select {
					case l.in <- deliver:
					case <-l.done:
						return
					}
				}
				// While a STOPDT waits, acknowledge at once so the
				// controlled station can confirm sooner (clause 5.3).
				if (unacked >= l.cfg.W || state == dtPendingStop) && !sendS() {
					return
				}
			case FormatS:
				if state == dtStopped || state == dtPendingStart {
					l.fail(fmt.Errorf("%w: S-frame received while the connection is %s", ErrFrame, state))
					return
				}
				if !acknowledge(a.RecvSeq) {
					return
				}
				if l.server && state == dtPendingStop && len(sentAt) == 0 {
					setState(dtStopped)
					if !write(APDU{Format: FormatU, U: UStopDTCon}) {
						return
					}
				}
			case FormatU:
				// Any other U-frame is ignored in every state (Figure 18).
				switch a.U {
				case UTestFRAct:
					if !write(APDU{Format: FormatU, U: UTestFRCon}) {
						return
					}
				case UTestFRCon:
					testSent = time.Time{}
				case UStartDTAct:
					if l.server && state == dtStopped {
						// Started (and the A-Profile attached) before
						// onStart: the group's sender may Send as soon as
						// onStart makes this its started connection.
						setState(dtStarted)
						if l.onStart != nil {
							l.onStart(l)
						}
						if !write(APDU{Format: FormatU, U: UStartDTCon}) {
							return
						}
					}
				case UStopDTAct:
					if l.server && state == dtStarted {
						dropQueue()
						if len(sentAt) > 0 {
							setState(dtPendingStop) // Pending UNCONFIRMED STOPPED
						} else {
							setState(dtStopped)
							if !write(APDU{Format: FormatU, U: UStopDTCon}) {
								return
							}
						}
					}
				case UStartDTCon:
					if state == dtPendingStart {
						setState(dtStarted)
						finish(nil)
					}
				case UStopDTCon:
					if state == dtPendingStop {
						setState(dtStopped)
						finish(nil)
					}
				}
			}
			if state == dtStarted && !flush() {
				return
			}
		case now := <-tick.C:
			if len(sentAt) > 0 && now.Sub(sentAt[0]) > l.cfg.T1 {
				l.fail(fmt.Errorf("t1 expired: I-frame %d not acknowledged within %s", ack, l.cfg.T1))
				return
			}
			if !l.server && (state == dtPendingStart || state == dtPendingStop) && now.Sub(pendAt) > l.cfg.T1 {
				name := "STARTDT"
				if state == dtPendingStop {
					name = "STOPDT"
				}
				l.fail(fmt.Errorf("t1 expired: no %s confirmation within %s", name, l.cfg.T1))
				return
			}
			if !testSent.IsZero() && now.Sub(testSent) > l.cfg.T1 {
				l.fail(fmt.Errorf("t1 expired: no TESTFR confirmation within %s", l.cfg.T1))
				return
			}
			if unacked > 0 && now.Sub(firstRecv) >= l.cfg.T2 && !sendS() {
				return
			}
			if testSent.IsZero() && now.Sub(lastRx) >= l.cfg.T3 {
				if !write(APDU{Format: FormatU, U: UTestFRAct}) {
					return
				}
				testSent = now
				lastRx = now
				l.smu.Lock()
				l.stats.TestFRSent++
				l.smu.Unlock()
			}
		}
	}
}

// secStarted makes l the connection that carries the A-Profile's messages.
func secStarted(s *sec.SecureLink, l *Link) {
	s.Attach(l, func(f []sec.Frame) {
		select {
		case l.secOut <- f:
		default: // the link is ending; the procedure's timers retransmit
		}
	})
}
