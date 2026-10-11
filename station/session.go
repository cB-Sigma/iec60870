// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package station

import (
	"context"
	"sync"
	"time"

	"github.com/cB-Sigma/iec60870"
	"github.com/cB-Sigma/iec60870/cs101"
	"github.com/cB-Sigma/iec60870/cs104"
)

// SessionConfig describes how a session encodes what it sends.
type SessionConfig struct {
	Params iec60870.Params // field sizes (zero: the station's)
	Loc    *time.Location  // time zone of time tags (nil: the station's)
	// MaxASDU is the largest ASDU the link carries (zero:
	// iec60870.MaxASDU, the IEC 104 limit).
	MaxASDU int
	// CP56 sends CP24Time2a monitor types as their CP56Time2a twins (IEC
	// 104 does not carry the CP24Time2a types).
	CP56 bool
	// Send hands one encoded ASDU to the link; it may block (the session
	// queues in front of it).
	Send func(ctx context.Context, asdu []byte) error
}

// Session is one controlling station's view of the station: what it sends
// goes through its own queue, in order.
type Session struct {
	st  *Station
	cfg SessionConfig

	ctx    context.Context
	cancel context.CancelFunc
	mu     sync.Mutex
	queue  [][]byte
	kick   chan struct{}
}

// Attach adds a session; received ASDUs go to its Handle, and it receives
// every ASDU the station emits until Close.
func (s *Station) Attach(cfg SessionConfig) *Session {
	if cfg.Params == (iec60870.Params{}) {
		cfg.Params = s.cfg.Params
	}
	cfg.Params = cfg.Params.WithDefaults()
	if cfg.Loc == nil {
		cfg.Loc = s.cfg.Loc
	}
	if cfg.MaxASDU <= 0 {
		cfg.MaxASDU = iec60870.MaxASDU
	}
	ctx, cancel := context.WithCancel(context.Background())
	se := &Session{st: s, cfg: cfg, ctx: ctx, cancel: cancel, kick: make(chan struct{}, 1)}
	s.mu.Lock()
	s.sessions[se] = true
	s.mu.Unlock()
	go se.pump()
	return se
}

// Close detaches the session; what it had queued is dropped.
func (se *Session) Close() {
	se.cancel()
	s := se.st
	s.mu.Lock()
	delete(s.sessions, se)
	for k := range s.selected {
		if k.s == se {
			delete(s.selected, k)
		}
	}
	s.mu.Unlock()
}

// Pending is the number of ASDUs queued and not yet handed to the link.
func (se *Session) Pending() int {
	se.mu.Lock()
	defer se.mu.Unlock()
	return len(se.queue)
}

func (se *Session) pump() {
	for {
		select {
		case <-se.ctx.Done():
			return
		case <-se.kick:
		}
		for {
			se.mu.Lock()
			if len(se.queue) == 0 {
				se.mu.Unlock()
				break
			}
			b := se.queue[0]
			se.queue = se.queue[1:]
			se.mu.Unlock()
			if err := se.cfg.Send(se.ctx, b); err != nil && se.ctx.Err() != nil {
				return
			}
		}
	}
}

func (se *Session) push(b []byte) {
	se.mu.Lock()
	if len(se.queue) >= se.st.cfg.QueueLimit {
		se.queue = se.queue[1:]
		se.st.count(func(s *Stats) { s.Dropped++ })
	}
	se.queue = append(se.queue, b)
	se.mu.Unlock()
	select {
	case se.kick <- struct{}{}:
	default:
	}
}

// dropTimeTagged removes queued monitor ASDUs with time tags (reset of
// pending information with time tag, QRP 2).
func (se *Session) dropTimeTagged() {
	se.mu.Lock()
	defer se.mu.Unlock()
	kept := se.queue[:0:0]
	for _, b := range se.queue {
		if len(b) > 0 {
			t := iec60870.TypeID(b[0])
			if t.Monitor() && t.TimeTagged() {
				continue
			}
		}
		kept = append(kept, b)
	}
	se.queue = kept
}

// send encodes a for this session, splitting its objects over several
// ASDUs when they do not fit one.
func (se *Session) send(a *iec60870.ASDU) {
	m := *a
	if se.cfg.CP56 {
		m.Type = CP56(m.Type)
	}
	if m.Type.Monitor() && !m.Type.TimeTagged() {
		objs := make([]iec60870.Object, len(m.Objects))
		for i, o := range m.Objects {
			o.Time, o.TimeInvalid, o.TimeSubstituted = time.Time{}, false, false
			objs[i] = o
		}
		m.Objects = objs
	}
	per := len(m.Objects)
	if sz := m.Type.ObjectSize(); sz > 0 && per > 1 {
		if n := (se.cfg.MaxASDU - se.cfg.Params.Header()) / (se.cfg.Params.IOASize + sz); n < per {
			per = max(n, 1)
		}
	}
	if per == 0 {
		per = 1
	}
	objs := m.Objects
	for {
		part := m
		if len(objs) > per {
			part.Objects, objs = objs[:per], objs[per:]
		} else {
			part.Objects, objs = objs, nil
		}
		if b, err := part.EncodeMax(se.cfg.Params, se.cfg.Loc, se.cfg.MaxASDU); err == nil {
			se.push(b)
		}
		if len(objs) == 0 {
			return
		}
	}
}

// Handle decodes and answers one ASDU from the controlling station.
func (se *Session) Handle(b []byte) {
	a, err := iec60870.DecodeASDU(b, se.cfg.Params, se.cfg.Loc)
	if err != nil {
		if len(b) > 0 {
			// An unknown type: mirrored with cause 44 (the rest of the
			// header may be unreadable).
			se.send(&iec60870.ASDU{Type: iec60870.TypeID(b[0]), Cause: iec60870.CauseUnknownType, Negative: true, CA: se.st.cfg.CA,
				Objects: []iec60870.Object{{}}})
		}
		return
	}
	se.HandleASDU(a)
}

// HandleASDU answers one decoded ASDU from the controlling station.
func (se *Session) HandleASDU(a *iec60870.ASDU) { se.st.handle(se, a) }

// Group returns a cs104 redundancy group served by the station: its
// connections' requests are answered and the station's data is queued in
// the group (kept while no connection is started). Put it in a
// cs104.Server's Groups.
func (s *Station) Group(link cs104.LinkConfig) *cs104.Group {
	g := &cs104.Group{Config: link}
	s.serveGroup(g)
	return g
}

// PerConnection is for cs104.Server.PerConnection: each connection gets a
// redundancy group of its own, attached to the station while the
// connection lasts.
func (s *Station) PerConnection(link cs104.LinkConfig) func() *cs104.Group {
	return func() *cs104.Group {
		g := &cs104.Group{Config: link}
		se := s.serveGroup(g)
		g.OnClose = func(_ *cs104.Link, remaining int) {
			if remaining == 0 {
				se.Close()
			}
		}
		return g
	}
}

// ServeGroup makes an existing group serve the station (its OnASDU is
// replaced) and returns the session.
func (s *Station) ServeGroup(g *cs104.Group) *Session { return s.serveGroup(g) }

func (s *Station) serveGroup(g *cs104.Group) *Session {
	se := s.Attach(SessionConfig{Params: s.cfg.Params, CP56: true, MaxASDU: cs104.MaxASDU,
		Send: func(_ context.Context, b []byte) error { return g.Enqueue(b) }})
	g.OnASDU = func(_ *cs104.Link, b []byte) { se.Handle(b) }
	return se
}

// ServeSecondary serves the station on an IEC 101 line session until it
// ends (its ASDUs channel closes) or ctx does; prm are the line's field
// sizes (zero: one-octet cause and common address, two-octet object
// address), asize its link address size.
func (s *Station) ServeSecondary(ctx context.Context, sec *cs101.Secondary, prm iec60870.Params, asize int) {
	if prm == (iec60870.Params{}) {
		prm = iec60870.Params{COTSize: 1, CASize: 1, IOASize: 2}
	}
	se := s.Attach(SessionConfig{Params: prm, MaxASDU: cs101.MaxASDU(asize),
		Send: func(ctx context.Context, b []byte) error { return sec.Send(ctx, b) }})
	defer se.Close()
	for {
		select {
		case <-ctx.Done():
			return
		case b, ok := <-sec.ASDUs():
			if !ok {
				return
			}
			se.Handle(b)
		}
	}
}
