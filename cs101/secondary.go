package cs101

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/cB-Sigma/iec60870/sec"
)

// Secondary is the controlled station's end of a line for one session
// (6.2.4): the secondary link of an unbalanced line (Figure 6), polled by
// the controlling station, or station B of a balanced line (Figures 8
// and 9), whose own primary sends the queued data. Send queues ASDUs in
// class 1 or 2 (7.4.2); received user data comes out of ASDUs.
type Secondary struct {
	cfg SecondaryConfig
	p   *Port
	bal bool

	mu      sync.Mutex
	class1  [][]byte
	class2  [][]byte
	pending []byte // data answered to a poll, confirmed by the next FCB change
	reset   bool   // our secondary link was reset by the controlling station
	lastFCB int8   // -1 after a reset
	last    []byte // the last answer, repeated when the FCB does not change
	space   chan struct{}
	kick    chan struct{} // balanced: data to send
	asdus   chan []byte
	done    chan struct{}
	once    sync.Once
	err     error
	resp    chan Frame // balanced: answers to our primary requests
	ourFCB  bool
	up      bool // balanced: our primary link is reset
	// sec is the line's A-Profile (IEC TS 60870-5-7): queued ASDUs are
	// Secure Data segments; orig maps a series' last segment to the ASDU
	// it carries, for acknowledgements.
	sec   *sec.SecureLink
	orig  map[*byte][]byte
	secCh chan []sec.Frame
}

// SecondaryConfig configures a Secondary.
type SecondaryConfig struct {
	LinkAddress uint16 // our link address
	AddrSize    int    // link address field: 0 (balanced only), 1 or 2 octets
	Balanced    bool
	// LinkTimeout (unbalanced) ends the session after so long without a
	// request.
	LinkTimeout time.Duration
	// Timeout (balanced) is the answer timeout of our primary's requests,
	// Retries how often they are repeated, TestPeriod how often the link
	// is tested when idle.
	Timeout    time.Duration
	Retries    int
	TestPeriod time.Duration
	// Name names the session in RemoteAddr ("line 1", say).
	Name string
	// Security, when set, applies the IEC TS 60870-5-7 A-Profile: queued
	// ASDUs are Secure Data and received ones are unwrapped.
	Security *sec.SecureLink
	// OnReset runs when the controlling station first resets our link:
	// data may flow from then on.
	OnReset func(*Secondary)
	// OnAcked receives the ASDUs the controlling station confirmed, in
	// order.
	OnAcked func(ctx context.Context, asdus [][]byte)
}

const classLimit = 64

// NewSecondary serves the line p; Run reads it.
func NewSecondary(p *Port, cfg SecondaryConfig) *Secondary {
	c := &Secondary{cfg: cfg, p: p, bal: cfg.Balanced, lastFCB: -1, space: make(chan struct{}, 1),
		kick: make(chan struct{}, 1), asdus: make(chan []byte, 64), done: make(chan struct{}), resp: make(chan Frame, 4),
		sec: cfg.Security, orig: map[*byte][]byte{}}
	if c.sec != nil {
		c.secCh = make(chan []sec.Frame, 64)
	}
	return c
}

// secSender queues the A-Profile's own messages and released Secure Data.
func (c *Secondary) secSender(ctx context.Context) {
	for {
		select {
		case <-c.done:
			return
		case frames := <-c.secCh:
			for _, f := range frames {
				if c.queue(ctx, f.Data, f.Orig) != nil {
					break
				}
			}
		}
	}
}

// origOf maps sent frames back to the application ASDUs they complete.
func (c *Secondary) origOf(frames [][]byte) [][]byte {
	if c.sec == nil {
		return frames
	}
	var out [][]byte
	c.mu.Lock()
	for _, f := range frames {
		if len(f) == 0 {
			continue
		}
		if o, ok := c.orig[&f[0]]; ok {
			delete(c.orig, &f[0])
			out = append(out, o)
		}
	}
	c.mu.Unlock()
	return out
}

type lineAddr string

func (a lineAddr) Network() string { return "iec101" }
func (a lineAddr) String() string  { return string(a) }

// RemoteAddr names the session (SecondaryConfig.Name).
func (c *Secondary) RemoteAddr() net.Addr { return lineAddr(c.cfg.Name) }

// ASDUs delivers the received application ASDUs; it is closed when Run
// returns.
func (c *Secondary) ASDUs() <-chan []byte { return c.asdus }

// Stopped: until the controlling station resets our link, nothing is
// sent.
func (c *Secondary) Stopped() bool { c.mu.Lock(); defer c.mu.Unlock(); return !c.reset }

// Err is why the session ended.
func (c *Secondary) Err() error { c.mu.Lock(); defer c.mu.Unlock(); return c.err }

// Close ends the session.
func (c *Secondary) Close() {
	c.once.Do(func() {
		close(c.done)
		_ = c.p.Close()
		if c.sec != nil {
			c.sec.Detach(c)
		}
	})
}

// Unacked returns what was queued or answered but not confirmed.
func (c *Secondary) Unacked() [][]byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	var out [][]byte
	if c.pending != nil {
		out = append(out, c.pending)
	}
	out = append(append(out, c.class1...), c.class2...)
	c.class1, c.class2, c.pending = nil, nil, nil
	if c.sec != nil {
		var orig [][]byte
		for _, f := range out {
			if o, ok := c.orig[&f[0]]; ok {
				orig = append(orig, o)
			}
		}
		c.orig = map[*byte][]byte{}
		return orig
	}
	return out
}

// Send queues an ASDU: cyclic (cause 1) and background (cause 2) data in
// class 2, the rest in class 1 (7.4.2). It blocks while the classes are
// full.
// With the A-Profile the ASDU is queued as Secure Data segments, or held
// by the security layer until a session is established.
func (c *Secondary) Send(ctx context.Context, b []byte) error {
	if c.sec == nil {
		return c.queue(ctx, b, nil)
	}
	frames, err := c.sec.Wrap(b)
	if err != nil {
		return err
	}
	for i, f := range frames {
		var o []byte
		if i == len(frames)-1 {
			o = b
		}
		if err := c.queue(ctx, f, o); err != nil {
			return err
		}
	}
	return nil
}

func (c *Secondary) queue(ctx context.Context, b, orig []byte) error {
	if err := checkLength(b, c.cfg.AddrSize); err != nil {
		return err
	}
	for {
		c.mu.Lock()
		if len(c.class1)+len(c.class2) < classLimit {
			if orig != nil && len(b) > 0 {
				c.orig[&b[0]] = orig
			}
			if len(b) > 2 && (b[2]&0x3f == 1 || b[2]&0x3f == 2) {
				c.class2 = append(c.class2, b)
			} else {
				c.class1 = append(c.class1, b)
			}
			c.mu.Unlock()
			select {
			case c.kick <- struct{}{}:
			default:
			}
			return nil
		}
		c.mu.Unlock()
		select {
		case <-c.space:
		case <-ctx.Done():
			return ctx.Err()
		case <-c.done:
			return errors.New("the line session ended")
		}
	}
}

func (c *Secondary) freed() {
	select {
	case c.space <- struct{}{}:
	default:
	}
}

func (c *Secondary) write(f Frame) {
	if !f.Single && c.bal {
		f.C &^= CtrlDIR // station B: DIR 0 (Figure 7)
	}
	_, _ = c.p.Write(f.Encode(c.cfg.AddrSize))
}

func (c *Secondary) fail(err error) {
	c.mu.Lock()
	if c.err == nil {
		c.err = err
	}
	c.mu.Unlock()
	c.Close()
}

func (c *Secondary) acked(ctx context.Context, a [][]byte) {
	if c.cfg.OnAcked != nil {
		c.cfg.OnAcked(ctx, a)
	}
}

// Run reads frames until the line fails or, unbalanced, stays silent for
// LinkTimeout, and returns why.
func (c *Secondary) Run(ctx context.Context) error {
	defer close(c.asdus)
	if c.bal {
		go c.primary(ctx)
	}
	if c.sec != nil {
		go c.secSender(ctx)
	}
	for {
		if !c.bal {
			c.p.SetDeadline(time.Now().Add(c.cfg.LinkTimeout))
		}
		f, err := ReadFrame(c.p, c.cfg.AddrSize)
		if errors.Is(err, ErrFrame) {
			continue
		}
		if err != nil {
			if errors.Is(err, ErrTimeout) {
				err = fmt.Errorf("no request for %s", c.cfg.LinkTimeout)
			}
			c.fail(err)
			return err
		}
		select {
		case <-c.done:
			return c.Err()
		default:
		}
		if c.bal && !f.Single && f.C&CtrlDIR == 0 {
			continue // our own direction (Figure 7)
		}
		if !f.PRM() {
			select {
			case c.resp <- f:
			default:
			}
			continue
		}
		bcast := c.cfg.AddrSize > 0 && f.Addr == uint16(1)<<(8*c.cfg.AddrSize)-1
		// Without an address field (balanced, 0 octets) every frame is ours.
		if c.cfg.AddrSize > 0 && f.Addr != c.cfg.LinkAddress && !bcast {
			continue // another station on a party line
		}
		if bcast {
			// 6.2.1.1: only send/no reply is broadcast.
			if f.Fn() == FnUserDataNoReply && f.ASDU != nil && c.isReset() {
				c.deliver(f.ASDU)
			}
			continue
		}
		c.answer(ctx, f)
	}
}

func (c *Secondary) isReset() bool { c.mu.Lock(); defer c.mu.Unlock(); return c.reset }

func (c *Secondary) deliver(b []byte) {
	if c.sec != nil {
		data, ok := c.sec.Unwrap(b)
		if !ok {
			return
		}
		b = data
	}
	select {
	case c.asdus <- b:
	case <-c.done:
	}
}

// answer serves a request of the controlling station (Figure 6
// unbalanced, Figure 9 balanced).
func (c *Secondary) answer(ctx context.Context, f Frame) {
	addr := c.cfg.LinkAddress
	c.mu.Lock()
	fcv := f.C&CtrlFCV != 0
	bit := int8(0)
	if f.C&CtrlFCB != 0 {
		bit = 1
	}
	fn := f.Fn()
	switch {
	case fn == FnRequestStatus:
		c.mu.Unlock()
		c.write(c.flags(Frame{C: FnStatus, Addr: addr}))
		return
	case fn == FnResetLink || fn == FnResetProcess:
		first := !c.reset
		c.reset, c.lastFCB, c.last = true, -1, nil
		if c.pending != nil {
			// A reset of the link: the answer was not confirmed; send it
			// again.
			c.class1 = append([][]byte{c.pending}, c.class1...)
			c.pending = nil
		}
		c.mu.Unlock()
		c.write(c.flags(Frame{C: FnAck, Addr: addr}))
		if first {
			if c.sec != nil {
				ch := c.secCh
				c.sec.Attach(c, func(f []sec.Frame) {
					select {
					case ch <- f:
					default:
					}
				})
			}
			if c.cfg.OnReset != nil {
				c.cfg.OnReset(c)
			}
		}
		return
	case !c.reset:
		c.mu.Unlock()
		return // not reset: no reply (Figures 6 and 9)
	}
	if fcv && c.lastFCB == bit && c.last != nil {
		last := c.last
		c.mu.Unlock()
		_, _ = c.p.Write(last) // a repeat: the answer was lost
		return
	}
	var acked [][]byte
	if fcv {
		c.lastFCB = bit
		if c.pending != nil {
			acked = [][]byte{c.pending} // the FCB changed: our answer arrived
			c.pending = nil
		}
	}
	var ans Frame
	var in []byte
	switch fn {
	case FnTestLink:
		ans = Frame{C: FnAck, Addr: addr}
	case FnUserDataConfirm:
		ans, in = Frame{C: FnAck, Addr: addr}, f.ASDU
	case FnUserDataNoReply:
		in = f.ASDU
	case FnRequestClass1, FnRequestClass2:
		if c.bal {
			ans = Frame{C: FnNotImplemented, Addr: addr}
			break
		}
		q := &c.class1
		if fn == FnRequestClass2 {
			q = &c.class2
		}
		if len(*q) > 0 {
			ans = Frame{C: FnUserData, Addr: addr, ASDU: (*q)[0]}
			c.pending = (*q)[0]
			*q = (*q)[1:]
		} else {
			ans = Frame{C: FnNoData, Addr: addr}
		}
	default:
		ans = Frame{C: FnNotImplemented, Addr: addr}
	}
	var out []byte
	if fn != FnUserDataNoReply {
		ans = c.flagsLocked(ans)
		if !c.bal && ans.C&CtrlACD == 0 && (ans.C&0x0f == FnAck || ans.C&0x0f == FnNoData) && fn != FnTestLink {
			out = []byte{SingleACK} // Figure 6 NOTE 3: E5 unless ACD or DFC
		} else {
			out = ans.Encode(c.cfg.AddrSize) // station B's frames carry DIR 0
		}
		if fcv {
			c.last = out
		}
	}
	c.mu.Unlock()
	if len(acked) > 0 {
		if a := c.origOf(acked); len(a) > 0 {
			c.acked(ctx, a)
		}
		c.freed()
	}
	if out != nil {
		_, _ = c.p.Write(out)
	}
	if in != nil {
		c.deliver(in)
	}
}

// flags sets ACD (class 1 waiting, unbalanced) and DFC (full) in a
// secondary frame.
func (c *Secondary) flags(f Frame) Frame {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.flagsLocked(f)
}

func (c *Secondary) flagsLocked(f Frame) Frame {
	if !c.bal && len(c.class1) > 0 {
		f.C |= CtrlACD
	}
	if len(c.class1)+len(c.class2) >= classLimit {
		f.C |= CtrlDFC
	}
	return f
}

// primary is station B's primary (balanced, Figure 8): request status and
// reset the controlling station's link, then send the queued ASDUs as
// confirmed user data and test the link when idle.
func (c *Secondary) primary(ctx context.Context) {
	addr := c.cfg.LinkAddress
	test := time.NewTicker(c.cfg.TestPeriod)
	defer test.Stop()
	req := func(fn byte, fcv bool, asdu []byte) (Frame, bool) {
		cf := CtrlPRM | fn
		c.mu.Lock()
		if fcv {
			cf |= CtrlFCV
			if c.ourFCB {
				cf |= CtrlFCB
			}
		}
		c.mu.Unlock()
		for try := 0; try <= c.cfg.Retries; try++ {
			for drained := false; !drained; {
				select {
				case <-c.resp:
				default:
					drained = true
				}
			}
			c.write(Frame{C: cf, Addr: addr, ASDU: asdu})
			t := time.NewTimer(c.cfg.Timeout)
			select {
			case r := <-c.resp:
				t.Stop()
				c.mu.Lock()
				if fn == FnResetLink && isAck(r) {
					c.ourFCB = true
				} else if fcv {
					c.ourFCB = !c.ourFCB
				}
				c.mu.Unlock()
				return r, true
			case <-t.C:
			case <-c.done:
				t.Stop()
				return Frame{}, false
			}
		}
		return Frame{}, false
	}
	for ctx.Err() == nil {
		select {
		case <-c.done:
			return
		default:
		}
		c.mu.Lock()
		up := c.up
		c.mu.Unlock()
		if !up {
			if r, ok := req(FnRequestStatus, false, nil); !ok || r.Single || r.Fn() != FnStatus {
				select {
				case <-c.done:
					return
				case <-time.After(c.cfg.Timeout):
				}
				continue
			}
			if r, ok := req(FnResetLink, false, nil); !ok || !isAck(r) {
				continue
			}
			c.mu.Lock()
			c.up = true
			c.mu.Unlock()
		}
		c.mu.Lock()
		var b []byte
		if c.reset && len(c.class1)+len(c.class2) > 0 {
			if len(c.class1) > 0 {
				b, c.class1 = c.class1[0], c.class1[1:]
			} else {
				b, c.class2 = c.class2[0], c.class2[1:]
			}
			c.pending = b
		}
		c.mu.Unlock()
		if b != nil {
			r, ok := req(FnUserDataConfirm, true, b)
			c.mu.Lock()
			c.pending = nil
			if !ok || !isAck(r) {
				c.class1 = append([][]byte{b}, c.class1...) // sent again
				if !ok {
					c.up = false // no answer: start the link again
				}
				c.mu.Unlock()
				select {
				case <-c.done:
					return
				case <-time.After(c.cfg.Timeout):
				}
				continue
			}
			c.mu.Unlock()
			if a := c.origOf([][]byte{b}); len(a) > 0 {
				c.acked(ctx, a)
			}
			c.freed()
			continue
		}
		select {
		case <-c.done:
			return
		case <-ctx.Done():
			return
		case <-c.kick:
		case <-test.C:
			if _, ok := req(FnTestLink, true, nil); !ok {
				c.mu.Lock()
				c.up = false
				c.mu.Unlock()
			}
		}
	}
}
