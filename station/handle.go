// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package station

import (
	"sort"
	"sync"
	"time"

	"github.com/cB-Sigma/iec60870"
)

func mirror(a *iec60870.ASDU, c iec60870.Cause, neg bool) *iec60870.ASDU {
	m := *a
	m.Cause, m.Negative = c, neg
	m.Objects = append([]iec60870.Object(nil), a.Objects...)
	return &m
}

// broadcast reports the global common address of the session's size.
func broadcast(ca uint16, prm iec60870.Params) bool {
	if prm.CASize == 1 {
		return ca == 0xff
	}
	return ca == 0xffff
}

// handle answers one request of session se.
func (s *Station) handle(se *Session, a *iec60870.ASDU) {
	reply := func(r *iec60870.ASDU) {
		if r.CA == 0 {
			r.CA = a.CA
		}
		se.send(r)
	}
	if s.cfg.Intercept != nil && s.cfg.Intercept(a, reply) {
		return
	}
	if !a.Type.Control() && !a.Type.File() {
		reply(mirror(a, iec60870.CauseUnknownType, true))
		return
	}
	if len(a.Objects) == 0 && !a.Type.File() {
		reply(mirror(a, iec60870.CauseUnknownCause, true))
		return
	}
	var targets []*Sector
	if broadcast(a.CA, se.cfg.Params) {
		switch a.Type {
		case iec60870.CIcNa1, iec60870.CCiNa1, iec60870.CCsNa1, iec60870.CRpNa1:
			targets = s.Sectors()
		default:
			reply(mirror(a, iec60870.CauseUnknownCA, true))
			return
		}
	} else if x, ok := s.Lookup(a.CA); ok {
		targets = []*Sector{x}
	} else {
		reply(mirror(a, iec60870.CauseUnknownCA, true))
		return
	}
	for _, x := range targets {
		r := *a
		r.CA = x.CA
		s.serve(se, x, &r, func(m *iec60870.ASDU) {
			m.CA = x.CA
			se.send(m)
		})
	}
}

// serve answers a request addressed to sector x.
func (s *Station) serve(se *Session, x *Sector, a *iec60870.ASDU, reply func(*iec60870.ASDU)) {
	if a.Type.File() {
		if s.cfg.Files == nil {
			reply(mirror(a, iec60870.CauseUnknownType, true))
			return
		}
		s.cfg.Files.Handle(se.ctx, a, reply)
		return
	}
	o := a.Objects[0]
	act := a.Cause == iec60870.CauseActivation
	switch a.Type {
	case iec60870.CIcNa1:
		s.interrogate(x, a, reply)
	case iec60870.CCiNa1:
		s.counters(x, a, reply)
	case iec60870.CRdNa1:
		if a.Cause != iec60870.CauseRequest {
			reply(mirror(a, iec60870.CauseUnknownCause, true))
			return
		}
		p, ok := x.Get(o.IOA)
		if !ok || isCounter(p.Type) || isEvent(p.Type) {
			reply(mirror(a, iec60870.CauseUnknownObject, true))
			return
		}
		reply(&iec60870.ASDU{Type: p.Type, Cause: iec60870.CauseRequest, Orig: a.Orig, Objects: []iec60870.Object{p.Object}})
	case iec60870.CCsNa1:
		if !act {
			reply(mirror(a, iec60870.CauseUnknownCause, true))
			return
		}
		s.count(func(st *Stats) { st.ClockSyncs++ })
		var err error
		if s.cfg.OnClockSync != nil {
			err = s.cfg.OnClockSync(o.Time)
		}
		if err == nil && !o.TimeInvalid {
			d, _ := s.Delay()
			s.mu.Lock()
			s.offset = o.Time.Add(d).Sub(s.cfg.Now())
			s.mu.Unlock()
		}
		m := mirror(a, iec60870.CauseActCon, err != nil || o.TimeInvalid)
		m.Objects[0].Time = s.Now()
		reply(m)
	case iec60870.CTsNa1:
		switch {
		case !act:
			reply(mirror(a, iec60870.CauseUnknownCause, true))
		case o.IOA != 0:
			reply(mirror(a, iec60870.CauseUnknownObject, true))
		default:
			reply(mirror(a, iec60870.CauseActCon, o.Value != iec60870.FBP))
		}
	case iec60870.CTsTa1:
		switch {
		case !act:
			reply(mirror(a, iec60870.CauseUnknownCause, true))
		case o.IOA != 0:
			reply(mirror(a, iec60870.CauseUnknownObject, true))
		default:
			reply(mirror(a, iec60870.CauseActCon, false))
		}
	case iec60870.CRpNa1:
		s.reset(se, x, a, reply)
	case iec60870.CCdNa1:
		switch a.Cause {
		case iec60870.CauseActivation:
			m := mirror(a, iec60870.CauseActCon, false)
			// The confirmation carries SDT plus the time spent here (IEC
			// 60870-5-5 6.13), modulo a minute; the answer leaves at once.
			m.Objects[0].Elapsed = o.Elapsed % time.Minute
			reply(m)
		case iec60870.CauseSpontaneous:
			s.mu.Lock()
			s.delay, s.delaySet = o.Elapsed, true
			s.mu.Unlock()
		default:
			reply(mirror(a, iec60870.CauseUnknownCause, true))
		}
	case iec60870.PMeNa1, iec60870.PMeNb1, iec60870.PMeNc1:
		s.parameter(x, a, reply)
	case iec60870.PAcNa1:
		s.activate(x, a, reply)
	default:
		if isCommand(a.Type) {
			s.command(se, x, a, reply)
			return
		}
		reply(mirror(a, iec60870.CauseUnknownType, true))
	}
}

// interrogate answers station (QOI 20) and group (21 to 36) interrogation.
func (s *Station) interrogate(x *Sector, a *iec60870.ASDU, reply func(*iec60870.ASDU)) {
	q := uint8(a.Objects[0].Value)
	switch a.Cause {
	case iec60870.CauseActivation:
	case iec60870.CauseDeactivation:
		reply(mirror(a, iec60870.CauseDeactCon, false))
		return
	default:
		reply(mirror(a, iec60870.CauseUnknownCause, true))
		return
	}
	if q < iec60870.QOIStation || q > iec60870.QOIStation+16 {
		reply(mirror(a, iec60870.CauseActCon, true))
		return
	}
	s.count(func(st *Stats) { st.Interrogations++ })
	g := iec60870.InterrogationGroup(q)
	reply(mirror(a, iec60870.CauseActCon, false))
	ps := x.snapshot(func(p *point) bool {
		if !inStation(p) {
			return false
		}
		if g == 0 {
			return true
		}
		for _, h := range p.Groups {
			if h == g {
				return true
			}
		}
		return false
	})
	for _, m := range batch(ps, iec60870.Cause(q), x.CA, Untagged) {
		m.Orig = a.Orig
		reply(m)
	}
	reply(mirror(a, iec60870.CauseActTerm, false))
}

// counters answers counter interrogation: read (cause 37 to 41, then
// ACTTERM), freeze, freeze with reset and reset (ACTCON only).
func (s *Station) counters(x *Sector, a *iec60870.ASDU, reply func(*iec60870.ASDU)) {
	if a.Cause != iec60870.CauseActivation {
		reply(mirror(a, iec60870.CauseUnknownCause, true))
		return
	}
	rqt, frz := iec60870.SplitQCC(uint8(a.Objects[0].Value))
	if rqt < 1 || rqt > iec60870.RQTGeneral {
		reply(mirror(a, iec60870.CauseActCon, true))
		return
	}
	s.count(func(st *Stats) { st.CounterInterrogations++ })
	reply(mirror(a, iec60870.CauseActCon, false))
	x.mu.Lock()
	var out []Point
	for _, p := range x.points {
		if !isCounter(p.Type) || rqt != iec60870.RQTGeneral && p.CounterGroup != int(rqt) {
			continue
		}
		v := p.Value
		switch frz {
		case iec60870.FRZRead:
			cp := p.Point
			cp.Value = v - x.base[p.IOA]
			if f, ok := x.frozen[p.IOA]; ok {
				cp.Value = f
			}
			out = append(out, cp)
		case iec60870.FRZFreeze:
			x.frozen[p.IOA] = v - x.base[p.IOA]
		case iec60870.FRZFreezeReset:
			x.frozen[p.IOA] = v - x.base[p.IOA]
			x.base[p.IOA] = v
		case iec60870.FRZReset:
			x.base[p.IOA] = v
			delete(x.frozen, p.IOA)
		}
	}
	x.mu.Unlock()
	if frz != iec60870.FRZRead {
		return
	}
	sortPoints(out)
	cause := iec60870.CauseCounterGen + iec60870.Cause(rqt%5)
	for _, m := range batch(out, cause, x.CA, func(t iec60870.TypeID) iec60870.TypeID { return t }) {
		m.Orig = a.Orig
		reply(m)
	}
	reply(mirror(a, iec60870.CauseActTerm, false))
}

// reset answers the reset process command.
func (s *Station) reset(se *Session, x *Sector, a *iec60870.ASDU, reply func(*iec60870.ASDU)) {
	if a.Cause != iec60870.CauseActivation {
		reply(mirror(a, iec60870.CauseUnknownCause, true))
		return
	}
	q := uint8(a.Objects[0].Value)
	if q != iec60870.QRPGeneral && q != iec60870.QRPEvents {
		reply(mirror(a, iec60870.CauseActCon, true))
		return
	}
	if s.cfg.OnResetProcess != nil {
		if err := s.cfg.OnResetProcess(q); err != nil {
			reply(mirror(a, iec60870.CauseActCon, true))
			return
		}
	}
	if q == iec60870.QRPEvents {
		se.dropTimeTagged()
		reply(mirror(a, iec60870.CauseActCon, false))
		return
	}
	s.mu.Lock()
	for k := range s.selected {
		if k.ca == x.CA {
			delete(s.selected, k)
		}
	}
	s.mu.Unlock()
	x.mu.Lock()
	x.frozen, x.base = map[uint32]float64{}, map[uint32]float64{}
	x.mu.Unlock()
	reply(mirror(a, iec60870.CauseActCon, false))
	reply(&iec60870.ASDU{Type: iec60870.MEiNa1, Cause: iec60870.CauseInitialised, Objects: []iec60870.Object{{Value: iec60870.COIRemote}}})
}

// parameter answers P_ME_NA/NB/NC_1: the parameter of the measured value
// at the same address; the confirmation carries the value in operation.
func (s *Station) parameter(x *Sector, a *iec60870.ASDU, reply func(*iec60870.ASDU)) {
	if a.Cause != iec60870.CauseActivation {
		reply(mirror(a, iec60870.CauseUnknownCause, true))
		return
	}
	o := a.Objects[0]
	kind := o.Qualifier & 0x3f
	p, ok := x.Get(o.IOA)
	if !ok || !isMeasured(p.Type) {
		reply(mirror(a, iec60870.CauseUnknownObject, true))
		return
	}
	if kind < iec60870.KPAThreshold || kind > iec60870.KPAHighLimit {
		reply(mirror(a, iec60870.CauseActCon, true))
		return
	}
	if s.cfg.OnParameter != nil {
		if err := s.cfg.OnParameter(x.CA, o.IOA, kind, o.Value); err != nil {
			m := mirror(a, iec60870.CauseActCon, true)
			if old, ok := x.Parameter(o.IOA, kind); ok {
				m.Objects[0].Value = old
			}
			reply(m)
			return
		}
	}
	x.mu.Lock()
	if x.params[o.IOA] == nil {
		x.params[o.IOA] = map[uint8]float64{}
	}
	x.params[o.IOA][kind] = o.Value
	if kind == iec60870.KPAThreshold {
		if q := x.points[o.IOA]; q != nil {
			q.Threshold = o.Value
		}
	}
	x.mu.Unlock()
	reply(mirror(a, iec60870.CauseActCon, false))
}

// activate answers P_AC_NA_1: QPA 1 (the parameters loaded before), 2
// (the parameter of the addressed object) and 3 (cyclic transmission of
// the addressed object).
func (s *Station) activate(x *Sector, a *iec60870.ASDU, reply func(*iec60870.ASDU)) {
	con := iec60870.CauseActCon
	switch a.Cause {
	case iec60870.CauseActivation:
	case iec60870.CauseDeactivation:
		con = iec60870.CauseDeactCon
	default:
		reply(mirror(a, iec60870.CauseUnknownCause, true))
		return
	}
	o := a.Objects[0]
	switch o.Qualifier {
	case 1:
		reply(mirror(a, con, false))
	case 2, iec60870.QPACyclic:
		x.mu.Lock()
		p, ok := x.points[o.IOA]
		if ok && o.Qualifier == iec60870.QPACyclic {
			p.Cyclic = a.Cause == iec60870.CauseActivation
		}
		x.mu.Unlock()
		if !ok {
			reply(mirror(a, iec60870.CauseUnknownObject, true))
			return
		}
		reply(mirror(a, con, false))
	default:
		reply(mirror(a, con, true))
	}
}

// command runs a command or set-point (IEC 60870-5-101 7.4.7): select,
// execute or deactivation of a select.
func (s *Station) command(se *Session, x *Sector, a *iec60870.ASDU, reply func(*iec60870.ASDU)) {
	o := a.Objects[0]
	if a.Type.TimeTagged() && s.cfg.MaxCommandDelay > 0 && s.Now().Sub(o.Time) > s.cfg.MaxCommandDelay {
		s.count(func(st *Stats) { st.Late++ })
		return
	}
	s.count(func(st *Stats) { st.Commands++ })
	ctl, ok := x.control(o.IOA)
	if !ok {
		reply(mirror(a, iec60870.CauseUnknownObject, true))
		return
	}
	if ctl.Type != 0 && ctl.Type != a.Type && commandTwin[ctl.Type] != a.Type {
		reply(mirror(a, iec60870.CauseUnknownType, true))
		return
	}
	cmd := Command{CA: x.CA, Type: a.Type, Object: o, Orig: a.Orig, Test: a.Test}
	key := selKey{se, x.CA, o.IOA}
	switch a.Cause {
	case iec60870.CauseActivation:
	case iec60870.CauseDeactivation:
		s.mu.Lock()
		_, sel := s.selected[key]
		delete(s.selected, key)
		s.mu.Unlock()
		var err error
		if sel && ctl.Cancel != nil {
			err = ctl.Cancel(se.ctx, cmd)
		}
		if c := refusal(err); c != 0 {
			reply(mirror(a, c, true))
			return
		}
		reply(mirror(a, iec60870.CauseDeactCon, !sel || err != nil))
		return
	default:
		reply(mirror(a, iec60870.CauseUnknownCause, true))
		return
	}
	if a.Test {
		// The test bit: confirmed (and terminated) without execution.
		reply(mirror(a, iec60870.CauseActCon, false))
		if !o.Select && !ctl.NoTermination {
			reply(mirror(a, iec60870.CauseActTerm, false))
		}
		return
	}
	if o.Select {
		go func() {
			var err error
			if ctl.Select != nil {
				err = ctl.Select(se.ctx, cmd)
			}
			if err == nil {
				s.mu.Lock()
				s.selected[key] = selection{t: a.Type, value: o.Value, qual: o.Qualifier, until: s.cfg.Now().Add(s.cfg.SelectTimeout)}
				s.mu.Unlock()
			}
			if c := refusal(err); c != 0 {
				reply(mirror(a, c, true))
				return
			}
			reply(mirror(a, iec60870.CauseActCon, err != nil))
		}()
		return
	}
	s.mu.Lock()
	sel, had := s.selected[key]
	delete(s.selected, key)
	s.mu.Unlock()
	valid := had && s.cfg.Now().Before(sel.until) && (sel.t == a.Type || commandTwin[sel.t] == a.Type) && sel.value == o.Value
	if ctl.SelectRequired && !valid {
		reply(mirror(a, iec60870.CauseActCon, true))
		return
	}
	go s.execute(se, x, ctl, cmd, a, reply)
}

func (s *Station) execute(se *Session, x *Sector, ctl Control, cmd Command, a *iec60870.ASDU, reply func(*iec60870.ASDU)) {
	var once sync.Once
	confirmed := false
	confirm := func() {
		once.Do(func() {
			confirmed = true
			reply(mirror(a, iec60870.CauseActCon, false))
		})
	}
	var err error
	if ctl.Execute != nil {
		err = ctl.Execute(se.ctx, cmd, confirm)
	} else {
		confirm()
		if ctl.Monitor != 0 {
			err = x.returnInfo(ctl.Monitor, cmd)
		}
	}
	if err != nil && !confirmed {
		if c := refusal(err); c != 0 {
			reply(mirror(a, c, true))
			return
		}
		reply(mirror(a, iec60870.CauseActCon, true))
		return
	}
	confirm()
	if !ctl.NoTermination {
		reply(mirror(a, iec60870.CauseActTerm, err != nil))
	}
}

// returnInfo applies a command to its monitored point and reports it.
func (x *Sector) returnInfo(ioa uint32, c Command) error {
	p, ok := x.Get(ioa)
	if !ok {
		return ErrUnknownPoint
	}
	o := p.Object
	o.Time = time.Time{}
	switch c.Type {
	case iec60870.CRcNa1, iec60870.CRcTa1:
		// RCS 1 lowers, 2 raises the step position by one.
		switch c.Value {
		case 1:
			o.Value--
		case 2:
			o.Value++
		}
	default:
		o.Value = c.Value
	}
	return x.ReturnInfo(o, false)
}

func sortPoints(ps []Point) { sort.Slice(ps, func(i, j int) bool { return ps[i].IOA < ps[j].IOA }) }
