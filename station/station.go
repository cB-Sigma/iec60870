// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package station

import (
	"context"
	"sort"
	"sync"
	"time"

	"github.com/cB-Sigma/iec60870"
)

// Station is a controlled station: sectors of points (one per common
// address) and the sessions of the controlling stations it serves. Its
// embedded Sector is the one at Config.CA.
type Station struct {
	*Sector
	cfg Config

	mu       sync.Mutex
	sectors  map[uint16]*Sector
	sessions map[*Session]bool
	selected map[selKey]selection
	offset   time.Duration // clock synchronisation: our time minus Now()
	delay    time.Duration // transmission delay loaded by C_CD_NA_1 cause 3
	delaySet bool
	stats    Stats
}

// Sector is the point database of one common address.
type Sector struct {
	CA uint16
	st *Station

	mu       sync.Mutex
	points   map[uint32]*point
	controls map[uint32]Control
	params   map[uint32]map[uint8]float64
	frozen   map[uint32]float64
	base     map[uint32]float64
}

type point struct {
	Point
	reported float64 // last value reported spontaneously (threshold)
}

type selKey struct {
	s   *Session
	ca  uint16
	ioa uint32
}

type selection struct {
	t     iec60870.TypeID
	value float64
	qual  uint8
	until time.Time
}

// New creates a station with an empty default sector at cfg.CA.
func New(cfg Config) *Station {
	cfg.Params = cfg.Params.WithDefaults()
	if cfg.Loc == nil {
		cfg.Loc = time.UTC
	}
	if cfg.SelectTimeout <= 0 {
		cfg.SelectTimeout = 30 * time.Second
	}
	if cfg.QueueLimit <= 0 {
		cfg.QueueLimit = 10000
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	s := &Station{cfg: cfg, sectors: map[uint16]*Sector{}, sessions: map[*Session]bool{}, selected: map[selKey]selection{}}
	s.Sector = s.SectorAt(cfg.CA)
	return s
}

// SectorAt returns the sector at common address ca, creating it when
// missing.
func (s *Station) SectorAt(ca uint16) *Sector {
	s.mu.Lock()
	defer s.mu.Unlock()
	if x := s.sectors[ca]; x != nil {
		return x
	}
	x := &Sector{CA: ca, st: s, points: map[uint32]*point{}, controls: map[uint32]Control{},
		params: map[uint32]map[uint8]float64{}, frozen: map[uint32]float64{}, base: map[uint32]float64{}}
	s.sectors[ca] = x
	return x
}

// Lookup returns the sector at ca, if there is one.
func (s *Station) Lookup(ca uint16) (*Sector, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	x, ok := s.sectors[ca]
	return x, ok
}

// Sectors returns every sector, by common address.
func (s *Station) Sectors() []*Sector {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]*Sector, 0, len(s.sectors))
	for _, x := range s.sectors {
		out = append(out, x)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CA < out[j].CA })
	return out
}

// Config returns the station's configuration (defaults filled in).
func (s *Station) Config() Config { return s.cfg }

// Now is the station's clock: Config.Now corrected by the last clock
// synchronisation.
func (s *Station) Now() time.Time {
	s.mu.Lock()
	off := s.offset
	s.mu.Unlock()
	return s.cfg.Now().Add(off)
}

// Delay is the transmission delay a controlling station loaded with
// C_CD_NA_1 (cause 3), and whether one was.
func (s *Station) Delay() (time.Duration, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.delay, s.delaySet
}

// Stats returns the counters.
func (s *Station) Stats() Stats {
	s.mu.Lock()
	defer s.mu.Unlock()
	st := s.stats
	st.Sessions = len(s.sessions)
	return st
}

func (s *Station) count(f func(*Stats)) {
	s.mu.Lock()
	f(&s.stats)
	s.mu.Unlock()
}

// Emit sends an ASDU in monitor direction to every session (a zero common
// address becomes the default sector's). Sessions split it when its
// objects do not fit one ASDU.
func (s *Station) Emit(a *iec60870.ASDU) {
	if a.CA == 0 {
		a.CA = s.cfg.CA
	}
	s.mu.Lock()
	ss := make([]*Session, 0, len(s.sessions))
	for x := range s.sessions {
		ss = append(ss, x)
	}
	s.mu.Unlock()
	for _, x := range ss {
		x.send(a)
	}
}

// EndOfInit sends the end of initialisation (M_EI_NA_1, cause 4) of every
// sector with cause of initialisation coi (0 local power on, 1 local
// reset, 2 remote reset; bit 8 set after a change of local parameters).
func (s *Station) EndOfInit(coi uint8) {
	for _, x := range s.Sectors() {
		s.Emit(&iec60870.ASDU{Type: iec60870.MEiNa1, Cause: iec60870.CauseInitialised, CA: x.CA,
			Objects: []iec60870.Object{{Value: float64(coi)}}})
	}
}

// Run sends cyclic and background data until ctx ends (nothing to do when
// neither period is set).
func (s *Station) Run(ctx context.Context) {
	tick := func(d time.Duration) <-chan time.Time {
		if d <= 0 {
			return nil
		}
		t := time.NewTicker(d)
		go func() { <-ctx.Done(); t.Stop() }()
		return t.C
	}
	cyc, bg := tick(s.cfg.CyclicPeriod), tick(s.cfg.BackgroundPeriod)
	if cyc == nil && bg == nil {
		return
	}
	for {
		select {
		case <-ctx.Done():
			return
		case <-cyc:
			for _, x := range s.Sectors() {
				s.emitAll(x.snapshot(func(p *point) bool { return p.Cyclic }), iec60870.CausePeriodic, x.CA)
			}
		case <-bg:
			for _, x := range s.Sectors() {
				s.emitAll(x.snapshot(inStation), iec60870.CauseBackground, x.CA)
			}
		}
	}
}

// emitAll sends points to every session, grouped by their untagged type.
func (s *Station) emitAll(ps []Point, cause iec60870.Cause, ca uint16) {
	for _, a := range batch(ps, cause, ca, Untagged) {
		s.Emit(a)
	}
}

// batch groups points (sorted by address) into ASDUs of one type each,
// keeping runs of the same type together.
func batch(ps []Point, cause iec60870.Cause, ca uint16, typeOf func(iec60870.TypeID) iec60870.TypeID) []*iec60870.ASDU {
	var out []*iec60870.ASDU
	var cur *iec60870.ASDU
	for _, p := range ps {
		t := typeOf(p.Type)
		o := p.Object
		if !t.TimeTagged() {
			o.Time, o.TimeInvalid, o.TimeSubstituted = time.Time{}, false, false
		}
		if cur == nil || cur.Type != t {
			cur = &iec60870.ASDU{Type: t, Cause: cause, CA: ca}
			out = append(out, cur)
		}
		cur.Objects = append(cur.Objects, o)
	}
	return out
}

// inStation selects the points of a station interrogation: everything but
// integrated totals and protection events.
func inStation(p *point) bool { return !isCounter(p.Type) && !isEvent(p.Type) }

// snapshot copies the points that want selects, sorted by address.
func (x *Sector) snapshot(want func(*point) bool) []Point {
	x.mu.Lock()
	defer x.mu.Unlock()
	var out []Point
	for _, p := range x.points {
		if want(p) {
			out = append(out, p.Point)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].IOA < out[j].IOA })
	return out
}

// Add stores a point (replacing one at the same address) without
// reporting it.
func (x *Sector) Add(p Point) {
	x.mu.Lock()
	defer x.mu.Unlock()
	cp := p
	cp.Groups = append([]int(nil), p.Groups...)
	x.points[p.IOA] = &point{Point: cp, reported: p.Value}
}

// Remove deletes the point at ioa.
func (x *Sector) Remove(ioa uint32) {
	x.mu.Lock()
	defer x.mu.Unlock()
	delete(x.points, ioa)
}

// Get returns the point at ioa.
func (x *Sector) Get(ioa uint32) (Point, bool) {
	x.mu.Lock()
	defer x.mu.Unlock()
	p, ok := x.points[ioa]
	if !ok {
		return Point{}, false
	}
	return p.Point, true
}

// Points returns every point, sorted by address.
func (x *Sector) Points() []Point { return x.snapshot(func(*point) bool { return true }) }

// AddControl makes ioa a command address.
func (x *Sector) AddControl(c Control) {
	x.mu.Lock()
	defer x.mu.Unlock()
	x.controls[c.IOA] = c
}

// Parameter returns a parameter of a measured value loaded by P_ME (kind
// 1 threshold, 2 smoothing, 3 low limit, 4 high limit).
func (x *Sector) Parameter(ioa uint32, kind uint8) (float64, bool) {
	x.mu.Lock()
	defer x.mu.Unlock()
	v, ok := x.params[ioa][kind]
	return v, ok
}

// Update changes the value and quality of the point at ioa, time-stamped
// now, and reports it spontaneously (see UpdateObject).
func (x *Sector) Update(ioa uint32, value float64, quality uint8) error {
	x.mu.Lock()
	p, ok := x.points[ioa]
	if !ok {
		x.mu.Unlock()
		return ErrUnknownPoint
	}
	o := p.Object
	x.mu.Unlock()
	o.Value, o.Quality, o.Time = value, quality, time.Time{}
	return x.UpdateObject(o)
}

// UpdateObject replaces the point's object (its address is o.IOA; a zero
// time becomes the station's clock) and reports it with cause 3 in the
// point's type when it changed, unless the point is Silent or a measured
// value stays within its Threshold.
func (x *Sector) UpdateObject(o iec60870.Object) error {
	return x.change(o, iec60870.CauseSpontaneous, false)
}

// Event reports o (protection events, packed points) with cause 3 whether
// or not it changed, and stores it.
func (x *Sector) Event(o iec60870.Object) error { return x.change(o, iec60870.CauseSpontaneous, true) }

// ReturnInfo stores o and reports it as return information: cause 11
// (remote) or 12 (local command) for single, double and step positions,
// cause 3 for other types.
func (x *Sector) ReturnInfo(o iec60870.Object, local bool) error {
	x.mu.Lock()
	p, ok := x.points[o.IOA]
	x.mu.Unlock()
	if !ok {
		return ErrUnknownPoint
	}
	c := returnCause(p.Type)
	if local && c == iec60870.CauseReturnRemote {
		c = iec60870.CauseReturnLocal
	}
	return x.change(o, c, true)
}

func (x *Sector) change(o iec60870.Object, cause iec60870.Cause, always bool) error {
	if o.Time.IsZero() {
		o.Time = x.st.Now()
	}
	x.mu.Lock()
	p, ok := x.points[o.IOA]
	if !ok {
		x.mu.Unlock()
		return ErrUnknownPoint
	}
	old := p.Object
	p.Object = o
	report := always
	if !report && !p.Silent {
		changed := o.Value != old.Value || o.Quality != old.Quality || o.Transient != old.Transient || o.Change != old.Change ||
			o.Seq != old.Seq || o.Elapsed != old.Elapsed
		report = changed
		if changed && isMeasured(p.Type) && p.Threshold > 0 && o.Quality == old.Quality {
			d := o.Value - p.reported
			report = d >= p.Threshold || -d >= p.Threshold
		}
	}
	t := p.Type
	if report {
		p.reported = o.Value
	}
	x.mu.Unlock()
	if report {
		x.st.Emit(&iec60870.ASDU{Type: t, Cause: cause, CA: x.CA, Objects: []iec60870.Object{o}})
	}
	return nil
}

// Store keeps o in the point at o.IOA, creating the point with type t when
// missing (the type is updated to t), without reporting it. Gateways
// mirror another station's data with it.
func (x *Sector) Store(t iec60870.TypeID, o iec60870.Object) {
	x.mu.Lock()
	defer x.mu.Unlock()
	p, ok := x.points[o.IOA]
	if !ok {
		p = &point{Point: Point{Type: t}}
		x.points[o.IOA] = p
	}
	p.Object, p.reported = o, o.Value
	// A value interrogated without time tag keeps the tagged type the
	// station reports spontaneously.
	if t != 0 && !(ok && !t.TimeTagged() && Untagged(p.Type) == t) {
		p.Type = t
	}
}

// AddGroup adds interrogation group g to the point at ioa (gateways learn
// groups from the causes 21 to 36 they receive).
func (x *Sector) AddGroup(ioa uint32, g int) {
	x.mu.Lock()
	defer x.mu.Unlock()
	p, ok := x.points[ioa]
	if !ok {
		return
	}
	for _, h := range p.Groups {
		if h == g {
			return
		}
	}
	p.Groups = append(p.Groups, g)
}

// SetCounterGroup sets the counter group of the integrated total at ioa.
func (x *Sector) SetCounterGroup(ioa uint32, g int) {
	x.mu.Lock()
	defer x.mu.Unlock()
	if p, ok := x.points[ioa]; ok {
		p.CounterGroup = g
	}
}

// SetQuality sets (or clears) quality bits on every point and reports each
// one whose quality changed; a gateway marks a lost station's points
// invalid with it.
func (x *Sector) SetQuality(bits uint8, set bool) {
	for _, p := range x.Points() {
		o := p.Object
		if set {
			o.Quality |= bits
		} else {
			o.Quality &^= bits
		}
		if o.Quality != p.Quality {
			o.Time = time.Time{}
			_ = x.UpdateObject(o)
		}
	}
}

func (x *Sector) control(ioa uint32) (Control, bool) {
	x.mu.Lock()
	c, ok := x.controls[ioa]
	x.mu.Unlock()
	if ok {
		return c, true
	}
	if f := x.st.cfg.ControlFor; f != nil {
		return f(x.CA, ioa)
	}
	return Control{}, false
}
