// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package cs104

import (
	"context"
	"errors"
	"net"
	"sync"
)

// Group is a redundancy group of a controlled station (IEC 60870-5-104
// clause 10, Figure 36): the connections of one controlling station
// accepted into it share one queue of monitor-direction ASDUs, and at most
// one of them is started. A STARTDT act on another connection closes the
// started one; the ASDUs that connection sent and never had acknowledged
// are sent again, first, on the connection that takes over (10.6), and
// ASDUs queued while no connection is started wait for the next one. A
// Group is one policy; Server picks the group of each connection, and an
// application with other rules can drive Accept and Link itself.
type Group struct {
	// Name names the group (for the application's logs).
	Name string
	// Config holds the link parameters of the group's connections (clause
	// 10.7: k, w and t0 to t3 per group).
	Config LinkConfig
	// Allow admits a controlling station by its address (nil: any; the
	// catch-all group).
	Allow func(net.Addr) bool
	// MaxConnections is the most connections the group holds at once (0:
	// no limit).
	MaxConnections int
	// Limit is the most ASDUs queued (default 10000); Enqueue refuses more
	// with ErrQueueFull rather than drop one.
	Limit int
	// OnStart runs when a connection of the group is started (after the
	// previously started one was closed), before its STARTDT confirmation
	// goes out; the station may queue its end of initialisation there. It
	// must not call Link.Send.
	OnStart func(*Link)
	// OnASDU receives the ASDUs the controlling station sends on any
	// connection of the group; answers go back with Link.Send on that
	// connection.
	OnASDU func(l *Link, asdu []byte)

	once     sync.Once
	sendOnce sync.Once
	mu       sync.Mutex
	links    map[*Link]*member
	act      *Link
	queue    [][]byte
	kick     chan struct{}
}

type member struct{ reclaim sync.Once }

// ErrQueueFull is returned by Enqueue when the group's queue is at its
// limit.
var ErrQueueFull = errors.New("the redundancy group's queue is full")

// ErrGroupFull is returned by Accept when the group holds MaxConnections.
var ErrGroupFull = errors.New("the redundancy group has its most connections")

func (g *Group) init() {
	g.once.Do(func() {
		g.links = map[*Link]*member{}
		g.kick = make(chan struct{}, 1)
	})
}

func (g *Group) poke() {
	select {
	case g.kick <- struct{}{}:
	default:
	}
}

// Accept runs the controlled station's side on conn as a connection of
// the group (see cs104.Accept); it fails when the group is full.
func (g *Group) Accept(ctx context.Context, conn net.Conn) (*Link, error) {
	g.init()
	g.mu.Lock()
	if g.MaxConnections > 0 && len(g.links) >= g.MaxConnections {
		g.mu.Unlock()
		return nil, ErrGroupFull
	}
	g.mu.Unlock()
	l := Accept(ctx, conn, g.Config, g.started, nil)
	g.mu.Lock()
	g.links[l] = &member{}
	g.mu.Unlock()
	g.sendOnce.Do(func() { go g.send(ctx) })
	go func() {
		for b := range l.ASDUs() {
			if g.OnASDU != nil {
				g.OnASDU(l, b)
			}
		}
	}()
	go func() {
		<-l.Done()
		g.reclaim(l)
		g.mu.Lock()
		delete(g.links, l)
		if g.act == l {
			g.act = nil
		}
		g.mu.Unlock()
	}()
	return l, nil
}

// started makes l the group's started connection (Figure 36): the one
// started before is closed and its unacknowledged ASDUs requeued in front.
func (g *Group) started(l *Link) {
	g.mu.Lock()
	old := g.act
	g.act = l
	g.mu.Unlock()
	if old != nil && old != l {
		old.Close()
		g.reclaim(old)
	}
	if g.OnStart != nil {
		g.OnStart(l)
	}
	g.poke()
}

// reclaim puts the ASDUs a connection sent and never had acknowledged at
// the front of the queue, once, after the connection ended.
func (g *Group) reclaim(l *Link) {
	g.mu.Lock()
	m := g.links[l]
	g.mu.Unlock()
	if m == nil {
		return
	}
	m.reclaim.Do(func() {
		un := l.Unacked()
		if len(un) == 0 {
			return
		}
		g.mu.Lock()
		g.queue = append(append([][]byte(nil), un...), g.queue...)
		g.mu.Unlock()
		g.poke()
	})
}

// Enqueue queues an ASDU for the group's started connection (now, or the
// next one to start).
func (g *Group) Enqueue(asdu []byte) error {
	g.init()
	limit := g.Limit
	if limit <= 0 {
		limit = 10000
	}
	g.mu.Lock()
	if len(g.queue) >= limit {
		g.mu.Unlock()
		return ErrQueueFull
	}
	g.queue = append(g.queue, asdu)
	g.mu.Unlock()
	g.poke()
	return nil
}

// Pending is the number of ASDUs queued and not yet sent.
func (g *Group) Pending() int {
	g.init()
	g.mu.Lock()
	defer g.mu.Unlock()
	return len(g.queue)
}

// Active is the started connection (nil: none).
func (g *Group) Active() *Link {
	g.init()
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.act
}

// Links is the number of connections in the group.
func (g *Group) Links() int {
	g.init()
	g.mu.Lock()
	defer g.mu.Unlock()
	return len(g.links)
}

// send moves queued ASDUs to the started connection, in order; an ASDU
// stays queued until the link took it (Send returned nil).
func (g *Group) send(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-g.kick:
		}
		for {
			g.mu.Lock()
			l := g.act
			if l == nil || len(g.queue) == 0 {
				g.mu.Unlock()
				break
			}
			a := g.queue[0]
			g.mu.Unlock()
			if len(a) == 0 {
				g.mu.Lock()
				g.queue = g.queue[1:]
				g.mu.Unlock()
				continue
			}
			if l.Send(ctx, a) != nil {
				break // stopped or closed: the next start sends it
			}
			g.mu.Lock()
			for i, q := range g.queue {
				if len(q) > 0 && &q[0] == &a[0] {
					g.queue = append(g.queue[:i:i], g.queue[i+1:]...)
					break
				}
			}
			g.mu.Unlock()
		}
	}
}

// Server accepts the controlling stations' connections and places each in
// a redundancy group: the first of Groups whose Allow admits its address,
// or, with PerConnection, a group of its own (each connection is its own
// redundancy group, started independently, every one receiving what the
// station enqueues). Connections no group admits are closed.
type Server struct {
	Groups []*Group
	// PerConnection, when set, makes a new group for every connection.
	PerConnection func() *Group
	// OnRefused, when set, learns of the connections refused.
	OnRefused func(addr net.Addr, err error)

	mu  sync.Mutex
	own map[*Group]bool
}

// ErrNoGroup is reported for a connection no group admits.
var ErrNoGroup = errors.New("no redundancy group admits the address")

// Serve accepts connections on ln until ctx ends or ln fails.
func (s *Server) Serve(ctx context.Context, ln net.Listener) error {
	go func() {
		<-ctx.Done()
		_ = ln.Close()
	}()
	for {
		c, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return err
		}
		s.place(ctx, c)
	}
}

func (s *Server) place(ctx context.Context, c net.Conn) {
	refuse := func(err error) {
		_ = c.Close()
		if s.OnRefused != nil {
			s.OnRefused(c.RemoteAddr(), err)
		}
	}
	if s.PerConnection != nil {
		g := s.PerConnection()
		l, err := g.Accept(ctx, c)
		if err != nil {
			refuse(err)
			return
		}
		s.mu.Lock()
		if s.own == nil {
			s.own = map[*Group]bool{}
		}
		s.own[g] = true
		s.mu.Unlock()
		go func() {
			<-l.Done()
			s.mu.Lock()
			delete(s.own, g)
			s.mu.Unlock()
		}()
		return
	}
	for _, g := range s.Groups {
		if g.Allow != nil && !g.Allow(c.RemoteAddr()) {
			continue
		}
		if _, err := g.Accept(ctx, c); err != nil {
			refuse(err)
		}
		return
	}
	refuse(ErrNoGroup)
}

// Enqueue queues an ASDU in every group (and every connection's own group
// with PerConnection); the first error is returned.
func (s *Server) Enqueue(asdu []byte) error {
	s.mu.Lock()
	gs := append([]*Group(nil), s.Groups...)
	for g := range s.own {
		gs = append(gs, g)
	}
	s.mu.Unlock()
	var first error
	for _, g := range gs {
		if err := g.Enqueue(asdu); err != nil && first == nil {
			first = err
		}
	}
	return first
}
