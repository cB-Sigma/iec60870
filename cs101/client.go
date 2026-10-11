// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package cs101

import (
	"context"
	"fmt"
	"time"

	"github.com/cB-Sigma/iec60870"
)

// ClientConfig configures a Client.
type ClientConfig struct {
	Address uint16          // the station's link address
	CA      uint16          // the station's common address
	Params  iec60870.Params // field sizes (zero: one-octet cause and common address, two-octet object address) and our originator address
	Loc     *time.Location  // time zone of the station's time tags (nil: UTC)
	// Timeout bounds the wait for a confirmation (zero: 10 s).
	Timeout time.Duration
	// PollInterval is the pause between polling cycles on an unbalanced
	// line (zero: 100 ms); a cycle asks for class 2 data, then class 1 data
	// while the station has some.
	PollInterval time.Duration
	// OnData receives the monitor-direction ASDUs (and anything no running
	// request or procedure took), from the Client's goroutine.
	OnData func(*iec60870.ASDU)
	// OnError receives ASDUs that could not be decoded and polling errors
	// (nil b).
	OnError func(b []byte, err error)
}

// Client is a controlling station's session with one station of an IEC
// 101 line, the counterpart of cs104.Client: on an unbalanced line it
// polls the station, on a balanced line it reads what the station sends;
// it routes the answers to commands to its Commander and those to
// procedures to its Taps, and hands the rest to OnData. It is an
// iec60870.Peer. Several Clients may share one Link (a party line); the
// link's own start-up (Link.Start) is the caller's.
type Client struct {
	link *Link
	cfg  ClientConfig
	cmds iec60870.Commander
	taps iec60870.Taps
	stop context.CancelFunc
	done chan struct{}
}

// NewClient starts a Client on l; it ends with Close or when the line
// fails.
func NewClient(l *Link, cfg ClientConfig) *Client {
	if cfg.Params.COTSize == 0 && cfg.Params.CASize == 0 && cfg.Params.IOASize == 0 {
		cfg.Params.COTSize, cfg.Params.CASize, cfg.Params.IOASize = 1, 1, 2
	}
	cfg.Params = cfg.Params.WithDefaults()
	if cfg.Loc == nil {
		cfg.Loc = time.UTC
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 10 * time.Second
	}
	if cfg.PollInterval <= 0 {
		cfg.PollInterval = 100 * time.Millisecond
	}
	ctx, cancel := context.WithCancel(context.Background())
	c := &Client{link: l, cfg: cfg, stop: cancel, done: make(chan struct{})}
	go c.run(ctx)
	return c
}

func (c *Client) run(ctx context.Context) {
	defer close(c.done)
	if c.link.balanced {
		for {
			select {
			case <-ctx.Done():
				return
			case <-c.link.Done():
				return
			case b := <-c.link.ASDUs():
				c.receive(b)
			}
		}
	}
	t := time.NewTicker(c.cfg.PollInterval)
	defer t.Stop()
	for {
		if err := c.link.Poll(ctx, c.cfg.Address, 16, c.receive); err != nil && ctx.Err() == nil && c.cfg.OnError != nil {
			c.cfg.OnError(nil, err)
		}
		select {
		case <-ctx.Done():
			return
		case <-c.link.Done():
			return
		case <-t.C:
		}
	}
}

func (c *Client) receive(b []byte) {
	a, err := iec60870.DecodeASDU(b, c.cfg.Params, c.cfg.Loc)
	if err != nil {
		if c.cfg.OnError != nil {
			c.cfg.OnError(b, err)
		}
		return
	}
	if c.taps.Offer(a) {
		return
	}
	if a.Type.Control() && c.cmds.Take(a) != iec60870.Unrelated {
		return
	}
	if c.cfg.OnData != nil {
		c.cfg.OnData(a)
	}
}

// Close stops the Client (not the Link).
func (c *Client) Close() {
	c.stop()
	<-c.done
}

// Done is closed once the Client stopped.
func (c *Client) Done() <-chan struct{} { return c.done }

// Link is the client's link.
func (c *Client) Link() *Link { return c.link }

// Send encodes a and sends it as confirmed user data, filling in the
// common address and our originator address when they are zero
// (iec60870.Peer).
func (c *Client) Send(ctx context.Context, a *iec60870.ASDU) error {
	if a.CA == 0 {
		a.CA = c.cfg.CA
	}
	if a.Orig == 0 {
		a.Orig = c.cfg.Params.Originator
	}
	b, err := a.EncodeMax(c.cfg.Params, c.cfg.Loc, c.MaxASDU())
	if err != nil {
		return err
	}
	return c.link.Send(ctx, c.cfg.Address, b)
}

// Taps are where procedures wait for their answers (iec60870.Peer).
func (c *Client) Taps() *iec60870.Taps { return &c.taps }

// MaxASDU is the largest ASDU a frame carries: L at most 255, less the
// control and address octets (iec60870.Peer).
func (c *Client) MaxASDU() int { return MaxASDU(c.link.asize) }

// Params are the field sizes (iec60870.Peer).
func (c *Client) Params() iec60870.Params { return c.cfg.Params }

// Sender is how the client's Commander reaches the station.
func (c *Client) Sender() iec60870.Sender {
	return iec60870.Sender{Timeout: c.cfg.Timeout, Done: c.link.Done(), Err: c.link.Err,
		Send: func(ctx context.Context, t iec60870.TypeID, cause iec60870.Cause, o iec60870.Object) error {
			return c.Send(ctx, &iec60870.ASDU{Type: t, Cause: cause, Objects: []iec60870.Object{o}})
		}}
}

// Request sends one activation or deactivation and waits for its answers
// (see iec60870.Commander.Do).
func (c *Client) Request(ctx context.Context, r iec60870.Request) error {
	return c.cmds.Do(ctx, c.Sender(), r)
}

// Operate runs a command, with select-before-operate when op asks for it
// (see iec60870.Commander.Operate).
func (c *Client) Operate(ctx context.Context, op iec60870.Operation) (iec60870.Object, error) {
	return c.cmds.Operate(ctx, c.Sender(), op)
}

// Cancel deactivates a confirmed select (see iec60870.Commander.Cancel).
func (c *Client) Cancel(ctx context.Context, t iec60870.TypeID, sel iec60870.Object, timeTag bool) error {
	return c.cmds.Cancel(ctx, c.Sender(), t, sel, timeTag)
}

// Interrogate runs a station (QOI 20) or group interrogation and waits up
// to wait for its activation termination.
func (c *Client) Interrogate(ctx context.Context, qoi uint8, wait time.Duration) error {
	return c.Request(ctx, iec60870.Request{Type: iec60870.CIcNa1, Cause: iec60870.CauseActivation,
		Object: iec60870.Object{Value: float64(qoi)}, Termination: wait})
}

// CounterInterrogate runs a counter interrogation (see
// cs104.Client.CounterInterrogate).
func (c *Client) CounterInterrogate(ctx context.Context, qcc uint8, wait time.Duration) error {
	if _, frz := iec60870.SplitQCC(qcc); frz != iec60870.FRZRead {
		wait = 0
	}
	return c.Request(ctx, iec60870.Request{Type: iec60870.CCiNa1, Cause: iec60870.CauseActivation,
		Object: iec60870.Object{Value: float64(qcc)}, Termination: wait})
}

// ClockSync sends a clock synchronisation with time now.
func (c *Client) ClockSync(ctx context.Context, now time.Time) error {
	return c.Request(ctx, iec60870.Request{Type: iec60870.CCsNa1, Cause: iec60870.CauseActivation,
		Object: iec60870.Object{Time: now}})
}

// ResetProcess sends a reset process command with qualifier qrp.
func (c *Client) ResetProcess(ctx context.Context, qrp uint8) error {
	return c.Request(ctx, iec60870.Request{Type: iec60870.CRpNa1, Cause: iec60870.CauseActivation,
		Object: iec60870.Object{Value: float64(qrp)}})
}

// Test sends the test command C_TS_NA_1 with its fixed pattern; the
// confirmation must repeat it.
func (c *Client) Test(ctx context.Context) error {
	return c.Request(ctx, iec60870.Request{Type: iec60870.CTsNa1, Cause: iec60870.CauseActivation,
		Object: iec60870.Object{Value: iec60870.FBP}, Untracked: true,
		Check: func(a *iec60870.ASDU) error {
			if len(a.Objects) != 1 || a.Objects[0].Value != iec60870.FBP {
				return fmt.Errorf("the test command was confirmed with another pattern (%v)", a.Objects)
			}
			return nil
		}})
}
