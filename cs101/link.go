package cs101

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"
)

// Link is the controlling station's end of an FT1.2 line. In unbalanced
// mode we are the only primary station and poll the secondaries; in
// balanced mode the station may also send requests, which the reader
// answers (status, reset, test) or passes on (user data).
type Link struct {
	p        *Port
	asize    int
	balanced bool
	timeout  time.Duration
	retries  int
	Log      func(msg string, args ...any) // discarded frames, for debugging

	wmu   sync.Mutex // writes
	reqMu sync.Mutex // one outstanding request
	resp  chan Frame // secondary frames and single characters
	asdus chan []byte

	mu    sync.Mutex
	fcb   map[uint16]bool // next FCB to send, per link address
	busy  map[uint16]bool // the secondary's last answer had DFC set
	rxFCB int8            // balanced: last FCB from the station, -1 after a reset
	// rxReset: balanced, the station has reset our secondary link (Figure
	// 9: until then only status and reset are answered).
	rxReset bool
	done    chan struct{}
}

// NewLink runs the controlling station's link over p: asize is the link
// address field (0 balanced only, 1 or 2 octets), timeout the answer
// timeout of a request (at least the interval of 6.2.2, see T0) and
// retries how often a request is repeated. Log, when replaced, receives
// the frames the link discards.
func NewLink(p *Port, asize int, balanced bool, timeout time.Duration, retries int) *Link {
	l := &Link{p: p, asize: asize, balanced: balanced, timeout: timeout, retries: retries,
		resp: make(chan Frame, 4), asdus: make(chan []byte, 64), fcb: map[uint16]bool{}, busy: map[uint16]bool{}, rxFCB: -1,
		done: make(chan struct{}), Log: func(string, ...any) {}}
	go l.reader()
	return l
}

// Close closes the line.
func (l *Link) Close() { _ = l.p.Close() }

// Done is closed when the line fails.
func (l *Link) Done() <-chan struct{} { return l.done }

// Err is why the line stopped.
func (l *Link) Err() error { return l.p.Err() }

// ASDUs are user data the station sent as a primary (balanced mode).
func (l *Link) ASDUs() <-chan []byte { return l.asdus }

func (l *Link) reader() {
	defer close(l.done)
	for {
		f, err := ReadFrame(l.p, l.asize)
		if errors.Is(err, ErrFrame) {
			l.Log("IEC 101 frame discarded", "error", err)
			continue
		}
		if err != nil {
			return
		}
		if l.balanced && !f.Single && f.C&CtrlDIR != 0 {
			// Figure 7: frames from the other station carry DIR 0; DIR 1
			// is our own direction (an echo or a second station A).
			l.Log("IEC 101 frame with our direction bit discarded", "frame", f.String())
			continue
		}
		if !f.PRM() {
			select {
			case l.resp <- f:
			default:
			}
			continue
		}
		if l.balanced {
			l.serve(f)
		}
	}
}

func (l *Link) write(f Frame) error {
	if l.balanced && !f.Single {
		f.C |= CtrlDIR
	}
	l.wmu.Lock()
	defer l.wmu.Unlock()
	_, err := l.p.Write(f.Encode(l.asize))
	return err
}

// serve answers a request from a balanced station as its secondary
// (Figure 9): status and reset of remote link (and of user process) are
// answered in any state; the rest only once the station has reset our
// link, before which they get no reply. User data and test frames
// repeated with the same FCB are acknowledged again without a second
// indication; unknown function codes get FC15.
func (l *Link) serve(f Frame) {
	ack := Frame{C: FnAck, Addr: f.Addr}
	l.mu.Lock()
	reset := l.rxReset
	l.mu.Unlock()
	switch f.Fn() {
	case FnRequestStatus:
		_ = l.write(Frame{C: FnStatus, Addr: f.Addr})
		return
	case FnResetLink, FnResetProcess:
		l.mu.Lock()
		l.rxFCB, l.rxReset = -1, true
		l.mu.Unlock()
		_ = l.write(ack)
		return
	}
	if !reset {
		l.Log("IEC 101 request before the reset of our link: no reply (Figure 9)", "fn", f.Fn())
		return
	}
	switch f.Fn() {
	case FnTestLink:
		_ = l.write(ack)
	case FnUserDataConfirm, FnUserDataNoReply:
		dup := false
		if f.C&CtrlFCV != 0 {
			bit := int8(0)
			if f.C&CtrlFCB != 0 {
				bit = 1
			}
			l.mu.Lock()
			dup = l.rxFCB == bit
			l.rxFCB = bit
			l.mu.Unlock()
		}
		if f.Fn() == FnUserDataConfirm {
			_ = l.write(ack)
		}
		if !dup && f.ASDU != nil {
			select {
			case l.asdus <- f.ASDU:
			default:
				l.Log("IEC 101 ASDU dropped: the queue is full")
			}
		}
	default:
		_ = l.write(Frame{C: FnNotImplemented, Addr: f.Addr})
	}
}

// ErrNoAnswer is returned when a request is not answered after the
// retries.
var ErrNoAnswer = errors.New("the station did not answer")

// ErrBusy is returned when a secondary stays busy (DFC) through the
// retries.
var ErrBusy = errors.New("the station's link stays busy (DFC)")

// Request sends a primary frame and waits for the secondary answer,
// repeating it (with the same FCB) after a timeout. fcv requests carry
// the alternating frame count bit.
func (l *Link) Request(ctx context.Context, addr uint16, fn byte, fcv bool, asdu []byte) (Frame, error) {
	if err := checkLength(asdu, l.asize); err != nil {
		return Frame{}, err
	}
	l.reqMu.Lock()
	defer l.reqMu.Unlock()
	c := CtrlPRM | fn
	l.mu.Lock()
	if fcv {
		c |= CtrlFCV
		if l.fcb[addr] {
			c |= CtrlFCB
		}
	}
	l.mu.Unlock()
	f := Frame{C: c, Addr: addr, ASDU: asdu}
	for attempt := 0; attempt <= l.retries; attempt++ {
		for drained := false; !drained; {
			select {
			case <-l.resp:
			default:
				drained = true
			}
		}
		if err := l.write(f); err != nil {
			return Frame{}, err
		}
		t := time.NewTimer(l.timeout)
		select {
		case <-ctx.Done():
			t.Stop()
			return Frame{}, ctx.Err()
		case <-l.done:
			t.Stop()
			return Frame{}, fmt.Errorf("the line closed: %v", l.Err())
		case r := <-l.resp:
			t.Stop()
			if !r.Single && l.asize > 0 && r.Addr != addr {
				return Frame{}, fmt.Errorf("answer from link address %d to a request for %d", r.Addr, addr)
			}
			l.mu.Lock()
			switch {
			case fn == FnResetLink && isAck(r):
				// Figure 6: the reset sets the secondary's FCB to 0, so the
				// first FCV frame after it carries FCB 1.
				l.fcb[addr] = true
			case fcv:
				l.fcb[addr] = !l.fcb[addr]
			}
			// DFC: further messages may overflow the secondary.
			l.busy[addr] = !r.Single && r.C&CtrlDFC != 0
			l.mu.Unlock()
			return r, nil
		case <-t.C:
		}
	}
	return Frame{}, fmt.Errorf("%w (function %d, link address %d, %d tries)", ErrNoAnswer, fn, addr, l.retries+1)
}

func isAck(f Frame) bool { return f.Single || f.Fn() == FnAck }

// fnName describes a secondary function code.
func fnName(f Frame) string {
	switch {
	case f.Single:
		return "E5"
	case f.Fn() == FnNotFunctioning:
		return "link service not functioning (FC14)"
	case f.Fn() == FnNotImplemented:
		return "link service not implemented (FC15)"
	case f.Fn() == FnNack:
		return "NACK (FC1)"
	}
	return f.String()
}

// Start runs the link start-up for one secondary (Figures 5 and 8):
// request status of link until FC11 without DFC, then reset of remote
// link until ACK; FC14, FC15, NACK and a busy status are repeated within
// the retries.
func (l *Link) Start(ctx context.Context, addr uint16) error {
	var last Frame
	ok := false
	for try := 0; try <= l.retries && !ok; try++ {
		r, err := l.Request(ctx, addr, FnRequestStatus, false, nil)
		if err != nil {
			return fmt.Errorf("request status of link: %w", err)
		}
		last = r
		ok = !r.Single && r.Fn() == FnStatus && r.C&CtrlDFC == 0
	}
	if !ok {
		return fmt.Errorf("request status of link answered with %s", fnName(last))
	}
	for try := 0; try <= l.retries; try++ {
		r, err := l.Request(ctx, addr, FnResetLink, false, nil)
		if err != nil {
			return fmt.Errorf("reset of remote link: %w", err)
		}
		if isAck(r) {
			return nil
		}
		last = r
	}
	return fmt.Errorf("reset of remote link answered with %s", fnName(last))
}

// WaitReady polls the status of a busy secondary (DFC set) until it
// answers without DFC (Figure 8: busy state).
func (l *Link) WaitReady(ctx context.Context, addr uint16) error {
	for try := 0; ; try++ {
		l.mu.Lock()
		busy := l.busy[addr]
		l.mu.Unlock()
		if !busy {
			return nil
		}
		if try > l.retries {
			return ErrBusy
		}
		if try > 0 {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(l.timeout):
			}
		}
		if _, err := l.Request(ctx, addr, FnRequestStatus, false, nil); err != nil {
			return err
		}
	}
}

// Send transmits user data with confirmation. A busy secondary (DFC) is
// polled with request status until it can take the message; a NACK from
// a busy secondary is repeated once it is ready again.
func (l *Link) Send(ctx context.Context, addr uint16, asdu []byte) error {
	for try := 0; ; try++ {
		if err := l.WaitReady(ctx, addr); err != nil {
			return err
		}
		r, err := l.Request(ctx, addr, FnUserDataConfirm, true, asdu)
		if err != nil {
			return err
		}
		if isAck(r) {
			return nil
		}
		if r.Fn() == FnNack && r.C&CtrlDFC != 0 && try < l.retries {
			continue
		}
		if r.Fn() == FnNack {
			return errors.New("the station did not accept the message (NACK)")
		}
		return fmt.Errorf("user data answered with %s", fnName(r))
	}
}

// T0 is the time-out interval of IEC 60870-5-101 6.2.2 for a line of baud
// bit/s, frames from the secondary of at most lmax octets, a link address
// of asize octets and the secondary's reaction time tR: unbalanced,
// tDAB + tR + tDBA + 11·lmax/B; balanced, adding the primary's fixed
// frame 11·(asize+4)/B and 33 bits of idle line, with tDAB and tDBA half
// a bit time each.
func T0(baud, lmax, asize int, balanced bool, tR time.Duration) time.Duration {
	b := float64(baud)
	ms := 1000*(0.5/b+0.5/b+11*float64(lmax)/b) + float64(tR.Microseconds())/1000
	if balanced {
		ms += 1000 * (11*float64(asize+4)/b + 33/b)
	}
	return time.Duration(ms * float64(time.Millisecond))
}

// Poll asks a secondary for its data (unbalanced transmission, 7.4.2): a
// request for class 2 data, then for class 1 data as long as the answers
// set ACD, at most max requests. deliver receives each ASDU.
func (l *Link) Poll(ctx context.Context, addr uint16, max int, deliver func([]byte)) error {
	fn := byte(FnRequestClass2)
	for n := 0; n < max && ctx.Err() == nil; n++ {
		r, err := l.Request(ctx, addr, fn, true, nil)
		if err != nil {
			return err
		}
		if !r.Single && r.Fn() == FnUserData && r.ASDU != nil {
			deliver(r.ASDU)
		}
		if r.Single || r.C&CtrlACD == 0 {
			return nil
		}
		fn = FnRequestClass1
	}
	return nil
}

// MaxFrame is the longest FT1.2 frame: a variable frame of L = 255.
const MaxFrame = 255 + 6

// SendNoReply sends user data with send/no reply (FC4), as to the
// broadcast address (6.2.1.1: only this service is broadcast).
func (l *Link) SendNoReply(addr uint16, asdu []byte) error {
	if err := checkLength(asdu, l.asize); err != nil {
		return err
	}
	l.reqMu.Lock()
	defer l.reqMu.Unlock()
	return l.write(Frame{C: CtrlPRM | FnUserDataNoReply, Addr: addr, ASDU: asdu})
}

// ErrTooLong is returned for user data longer than a frame carries.
var ErrTooLong = errors.New("the ASDU does not fit an FT1.2 frame")

// MaxASDU is the most ASDU octets a frame carries with an asize-octet
// link address: MaxUserData less the control and address octets.
func MaxASDU(asize int) int { return MaxUserData - 1 - asize }

func checkLength(asdu []byte, asize int) error {
	if len(asdu) > MaxASDU(asize) {
		return fmt.Errorf("%w (%d octets, at most %d)", ErrTooLong, len(asdu), MaxASDU(asize))
	}
	return nil
}

// BroadcastAddr is the link broadcast address: all ones (6.2.1.1).
func BroadcastAddr(asize int) uint16 { return uint16(1)<<(8*asize) - 1 }
