// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package cs104

import (
	"context"
	"time"

	"github.com/cB-Sigma/iec60870"
)

// ClientConfig configures a Client.
type ClientConfig struct {
	CA     uint16          // the station's common address
	Params iec60870.Params // field sizes (zero: the IEC 104 defaults) and our originator address
	Loc    *time.Location  // time zone of the station's time tags (nil: UTC)
	// Timeout bounds the wait for a confirmation (zero: 10 s).
	Timeout time.Duration
	// OnData receives the monitor-direction ASDUs (and anything no
	// running request or procedure took), from the Client's goroutine.
	OnData func(*iec60870.ASDU)
	// OnError receives ASDUs that could not be decoded.
	OnError func(b []byte, err error)
}

// Client is a controlling station's session with one controlled station
// over a started Link: it decodes the received ASDUs, routes the answers
// to commands to its Commander and those to procedures to its Taps, and
// hands the rest to OnData. It is an iec60870.Peer, so the procedures of
// package iec60870 (Read, CallDirectory, GetFile...) run on it.
type Client struct {
	link *Link
	cfg  ClientConfig
	cmds iec60870.Commander
	taps iec60870.Taps
	done chan struct{}
}

// NewClient starts a Client on l; it ends when l does.
func NewClient(l *Link, cfg ClientConfig) *Client {
	cfg.Params = cfg.Params.WithDefaults()
	if cfg.Loc == nil {
		cfg.Loc = time.UTC
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 10 * time.Second
	}
	c := &Client{link: l, cfg: cfg, done: make(chan struct{})}
	go c.receive()
	return c
}

func (c *Client) receive() {
	defer close(c.done)
	for b := range c.link.ASDUs() {
		a, err := iec60870.DecodeASDU(b, c.cfg.Params, c.cfg.Loc)
		if err != nil {
			if c.cfg.OnError != nil {
				c.cfg.OnError(b, err)
			}
			continue
		}
		if c.taps.Offer(a) {
			continue
		}
		if a.Type.Control() && c.cmds.Take(a) != iec60870.Unrelated {
			continue
		}
		if c.cfg.OnData != nil {
			c.cfg.OnData(a)
		}
	}
}

// Done is closed once the link ended and every received ASDU was handled.
func (c *Client) Done() <-chan struct{} { return c.done }

// Link is the client's link.
func (c *Client) Link() *Link { return c.link }

// Send encodes a and sends it, filling in the common address and our
// originator address when they are zero (iec60870.Peer).
func (c *Client) Send(ctx context.Context, a *iec60870.ASDU) error {
	if a.CA == 0 {
		a.CA = c.cfg.CA
	}
	if a.Orig == 0 {
		a.Orig = c.cfg.Params.Originator
	}
	b, err := a.Encode(c.cfg.Params, c.cfg.Loc)
	if err != nil {
		return err
	}
	return c.link.Send(ctx, b)
}

// Taps are where procedures wait for their answers (iec60870.Peer).
func (c *Client) Taps() *iec60870.Taps { return &c.taps }

// MaxASDU is the largest ASDU a link carries (iec60870.Peer).
func (c *Client) MaxASDU() int { return MaxASDU }

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
// to wait for its activation termination; the answers (cause 20 to 36)
// arrive through OnData before it returns.
func (c *Client) Interrogate(ctx context.Context, qoi uint8, wait time.Duration) error {
	return c.Request(ctx, iec60870.Request{Type: iec60870.CIcNa1, Cause: iec60870.CauseActivation,
		Object: iec60870.Object{Value: float64(qoi)}, Termination: wait})
}

// ClockSync sends a clock synchronisation with time now.
func (c *Client) ClockSync(ctx context.Context, now time.Time) error {
	return c.Request(ctx, iec60870.Request{Type: iec60870.CCsNa1, Cause: iec60870.CauseActivation,
		Object: iec60870.Object{Time: now}})
}
