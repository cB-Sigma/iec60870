// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

// Package gateway republishes controlled stations reached through
// controlling-station sessions as sectors of one controlled station: the
// IEC 60870-5-101 to IEC 60870-5-104 gateway (stations behind serial lines
// become common addresses on IEC 104), and the same for any pairing the
// sessions allow (104 to 104, 101 to 101, 104 to 101).
//
// Each Route ties one downstream station (a cs101.Client or cs104.Client,
// or anything that is an iec60870.Peer) to a sector of the gateway's
// station.Station. Monitor data from below is kept in the sector (station
// and group interrogation are answered from it) and passed upward with its
// cause; CP24Time2a types reach IEC 104 sessions as their CP56Time2a
// twins. Commands from above go down with select-before-operate,
// deactivation and the test bit intact, and their confirmations and
// terminations come back. Counter interrogation, reset process, the test
// commands, parameters and, optionally, clock synchronisation are passed
// through with their answers. A lost station's points are marked invalid
// until it is back and interrogated again.
package gateway

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/cB-Sigma/iec60870"
	"github.com/cB-Sigma/iec60870/station"
)

// Gateway is a controlled station whose sectors mirror downstream
// stations.
type Gateway struct {
	st *station.Station

	mu     sync.Mutex
	routes map[uint16]*Route
	user   station.Config
}

// Route maps one downstream station onto a sector of the gateway.
type Route struct {
	// CA is the sector's common address on the gateway (upward).
	CA uint16
	// DownCA is the downstream station's common address (0: CA).
	DownCA uint16
	// Peer is the session to the downstream station; its OnData must
	// call Receive.
	Peer iec60870.Peer
	// Timeout bounds the wait for a downstream confirmation (zero: 10 s).
	Timeout time.Duration
	// Termination bounds the wait for a downstream activation termination
	// of a command (zero: 30 s); none in time ends the command upward with
	// a negative termination (outcome unknown). Negative: commands are
	// confirmed upward without a termination.
	Termination time.Duration
	// ForwardClockSync passes clock synchronisation down (the downstream
	// confirmation answers it); otherwise the gateway confirms it itself.
	ForwardClockSync bool
	// OfflineQuality are the quality bits set on the sector's points while
	// the station is offline (zero: IV).
	OfflineQuality uint8

	g      *Gateway
	sector *station.Sector
	cmd    sync.Mutex // one downstream request at a time
	mu     sync.Mutex
	online bool
}

// New creates a gateway; cfg configures its station (ControlFor and
// Intercept, when set, are consulted for addresses no route serves).
func New(cfg station.Config) *Gateway {
	g := &Gateway{routes: map[uint16]*Route{}, user: cfg}
	cfg.ControlFor = g.controlFor
	cfg.Intercept = g.intercept
	g.st = station.New(cfg)
	return g
}

// Station is the gateway's controlled station: serve it with Group,
// PerConnection or ServeSecondary.
func (g *Gateway) Station() *station.Station { return g.st }

// Add registers r and returns its sector.
func (g *Gateway) Add(r *Route) *station.Sector {
	if r.DownCA == 0 {
		r.DownCA = r.CA
	}
	if r.Timeout <= 0 {
		r.Timeout = 10 * time.Second
	}
	if r.Termination == 0 {
		r.Termination = 30 * time.Second
	}
	if r.OfflineQuality == 0 {
		r.OfflineQuality = iec60870.QInvalid
	}
	r.g = g
	r.sector = g.st.SectorAt(r.CA)
	r.online = true
	g.mu.Lock()
	g.routes[r.CA] = r
	g.mu.Unlock()
	return r.sector
}

// Route returns the route of sector ca.
func (g *Gateway) Route(ca uint16) (*Route, bool) {
	g.mu.Lock()
	defer g.mu.Unlock()
	r, ok := g.routes[ca]
	return r, ok
}

// Sector is the route's sector on the gateway.
func (r *Route) Sector() *station.Sector { return r.sector }

// Receive takes an ASDU the downstream station sent (the downstream
// client's OnData). Monitor data is stored in the sector; what is not an
// answer to an interrogation (causes 20 to 36) also goes upward with the
// sector's common address. An end of initialisation goes upward and
// starts a new interrogation of the station.
func (r *Route) Receive(a *iec60870.ASDU) {
	switch {
	case a.Type == iec60870.MEiNa1:
		r.g.st.Emit(&iec60870.ASDU{Type: a.Type, Cause: a.Cause, CA: r.CA, Objects: a.Objects})
		go func() { _ = r.Interrogate(context.Background()) }()
	case a.Type.Monitor():
		for _, o := range a.Objects {
			r.mu.Lock()
			if !r.online {
				o.Quality |= r.OfflineQuality
			}
			r.mu.Unlock()
			r.sector.Store(a.Type, o)
			switch c := a.Cause; {
			case c > iec60870.CauseInterrogated && c <= iec60870.CauseInterrogated+16:
				r.sector.AddGroup(o.IOA, int(c-iec60870.CauseInterrogated))
			case c > iec60870.CauseCounterGen && c <= iec60870.CauseCounterGen+4:
				r.sector.SetCounterGroup(o.IOA, int(c-iec60870.CauseCounterGen))
			}
		}
		if a.Cause >= iec60870.CauseInterrogated && a.Cause <= iec60870.CauseInterrogated+16 {
			return
		}
		r.g.st.Emit(&iec60870.ASDU{Type: a.Type, Cause: a.Cause, CA: r.CA, Test: a.Test, Objects: a.Objects})
	}
}

// Interrogate asks the downstream station for a station interrogation;
// its answers fill the sector through Receive.
func (r *Route) Interrogate(ctx context.Context) error {
	return r.Peer.Send(ctx, &iec60870.ASDU{Type: iec60870.CIcNa1, Cause: iec60870.CauseActivation, CA: r.DownCA,
		Objects: []iec60870.Object{{Value: iec60870.QOIStation}}})
}

// SetOnline records whether the downstream station is reachable. Going
// offline sets OfflineQuality on every point of the sector (reported
// upward); coming back clears it and interrogates the station.
func (r *Route) SetOnline(ctx context.Context, online bool) error {
	r.mu.Lock()
	was := r.online
	r.online = online
	r.mu.Unlock()
	if was == online {
		return nil
	}
	r.sector.SetQuality(r.OfflineQuality, !online)
	if online {
		return r.Interrogate(ctx)
	}
	return nil
}

// Online reports what SetOnline last recorded.
func (r *Route) Online() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.online
}

// ErrOffline is returned for requests to a station that is offline.
var ErrOffline = errors.New("the downstream station is offline")

func (g *Gateway) controlFor(ca uint16, ioa uint32) (station.Control, bool) {
	r, ok := g.Route(ca)
	if !ok {
		if g.user.ControlFor != nil {
			return g.user.ControlFor(ca, ioa)
		}
		return station.Control{}, false
	}
	return station.Control{IOA: ioa, NoTermination: r.Termination < 0,
		Select: func(ctx context.Context, c station.Command) error {
			return r.request(ctx, c.Type, iec60870.CauseActivation, c.Object, c.Test, nil)
		},
		Execute: func(ctx context.Context, c station.Command, confirm func()) error {
			return r.request(ctx, c.Type, iec60870.CauseActivation, c.Object, c.Test, confirm)
		},
		Cancel: func(ctx context.Context, c station.Command) error {
			return r.request(ctx, c.Type, iec60870.CauseDeactivation, c.Object, c.Test, nil)
		},
	}, true
}

// answers matches the downstream answers to a request of type t at ioa.
func answers(t iec60870.TypeID, ioa uint32, anyIOA bool) func(*iec60870.ASDU) bool {
	return func(a *iec60870.ASDU) bool {
		if a.Type != t || len(a.Objects) == 0 || !anyIOA && a.Objects[0].IOA != ioa {
			return false
		}
		switch a.Cause {
		case iec60870.CauseActCon, iec60870.CauseDeactCon, iec60870.CauseActTerm, iec60870.CauseUnknownType,
			iec60870.CauseUnknownCause, iec60870.CauseUnknownCA, iec60870.CauseUnknownObject:
			return true
		}
		return false
	}
}

func refused(a *iec60870.ASDU) error {
	switch a.Cause {
	case iec60870.CauseUnknownType, iec60870.CauseUnknownCause, iec60870.CauseUnknownObject:
		// Passed on upward with the same cause.
		return &station.Refusal{Cause: a.Cause}
	case iec60870.CauseUnknownCA:
		return fmt.Errorf("the downstream station refused %s: %s", a.Type, a.Cause)
	}
	if a.Negative {
		return fmt.Errorf("the downstream station refused %s (negative %s)", a.Type, a.Cause)
	}
	return nil
}

// request sends a command down and waits for its confirmation and, when
// confirm is set (an execute), its termination.
func (r *Route) request(ctx context.Context, t iec60870.TypeID, cause iec60870.Cause, o iec60870.Object, test bool, confirm func()) error {
	if !r.Online() {
		return ErrOffline
	}
	r.cmd.Lock()
	defer r.cmd.Unlock()
	ch, stop := r.Peer.Taps().Add(answers(t, o.IOA, false))
	defer stop()
	if err := r.Peer.Send(ctx, &iec60870.ASDU{Type: t, Cause: cause, CA: r.DownCA, Test: test, Objects: []iec60870.Object{o}}); err != nil {
		return err
	}
	want := iec60870.CauseActCon
	if cause == iec60870.CauseDeactivation {
		want = iec60870.CauseDeactCon
	}
	timer := time.NewTimer(r.Timeout)
	defer timer.Stop()
	confirmed := false
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-timer.C:
			if confirmed {
				return fmt.Errorf("no activation termination of %s within %s (outcome unknown)", t, r.Termination)
			}
			return fmt.Errorf("%w: no confirmation of %s within %s", iec60870.ErrNoAnswer, t, r.Timeout)
		case a := <-ch:
			if err := refused(a); err != nil && (a.Cause != iec60870.CauseActTerm || confirmed) {
				return err
			}
			switch {
			case !confirmed && a.Cause == want:
				if confirm == nil || o.Select || r.Termination < 0 {
					return nil
				}
				confirmed = true
				confirm()
				timer.Reset(r.Termination)
			case confirmed && a.Cause == iec60870.CauseActTerm:
				return nil
			}
		}
	}
}

// passed are the requests the gateway passes down with their answers
// (besides commands, which go through controls).
var passed = map[iec60870.TypeID]bool{
	iec60870.CCiNa1: true, iec60870.CRpNa1: true, iec60870.CTsNa1: true, iec60870.CTsTa1: true, iec60870.CCdNa1: true,
	iec60870.PMeNa1: true, iec60870.PMeNb1: true, iec60870.PMeNc1: true, iec60870.PAcNa1: true,
}

func (g *Gateway) intercept(a *iec60870.ASDU, reply func(*iec60870.ASDU)) bool {
	r, ok := g.Route(a.CA)
	if !ok {
		if g.user.Intercept != nil {
			return g.user.Intercept(a, reply)
		}
		return false
	}
	pass := passed[a.Type] || a.Type == iec60870.CCsNa1 && r.ForwardClockSync
	if !pass || a.Type == iec60870.CCdNa1 && a.Cause != iec60870.CauseActivation {
		return false
	}
	if !r.Online() {
		m := *a
		m.Cause, m.Negative = iec60870.CauseActCon, true
		reply(&m)
		return true
	}
	go r.relay(a, reply)
	return true
}

// relay passes a request down and its answers up: confirmation, refusal
// and, for a counter read, the termination (the counters themselves come
// up through Receive).
func (r *Route) relay(a *iec60870.ASDU, reply func(*iec60870.ASDU)) {
	r.cmd.Lock()
	defer r.cmd.Unlock()
	var ioa uint32
	if len(a.Objects) > 0 {
		ioa = a.Objects[0].IOA
	}
	ch, stop := r.Peer.Taps().Add(answers(a.Type, ioa, false))
	defer stop()
	down := *a
	down.CA = r.DownCA
	ctx := context.Background()
	if err := r.Peer.Send(ctx, &down); err != nil {
		m := *a
		m.Cause, m.Negative = iec60870.CauseActCon, true
		reply(&m)
		return
	}
	term := false
	if a.Type == iec60870.CCiNa1 && len(a.Objects) > 0 {
		_, frz := iec60870.SplitQCC(uint8(a.Objects[0].Value))
		term = frz == iec60870.FRZRead
	}
	wait := r.Timeout
	for {
		select {
		case m := <-ch:
			up := *m
			up.CA = a.CA
			reply(&up)
			if m.Cause == iec60870.CauseActCon && !m.Negative && term {
				wait = max(r.Termination, r.Timeout)
				continue
			}
			return
		case <-time.After(wait):
			return
		}
	}
}
