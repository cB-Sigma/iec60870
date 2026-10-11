package sec

import (
	"context"
	"sync"
	"time"

	"github.com/cB-Sigma/iec60870"
)

// SecureLink applies the IEC TS 60870-5-7 A-Profile (IEC 62351-5) to the
// connections of one association: a station of the controlling station, or
// a redundancy group (IEC 104) or line (IEC 101) of the controlled station.
// The connections of a redundancy group share it (TS 7.3.2); the started
// one carries the security messages. Only ASDUs are protected: APCI frames
// (TESTFR, STARTDT) are not (TS 7.3.2). IEC 101 uses it through Attach,
// Detach, Wrap and Unwrap.
type SecureLink struct {
	ep *Endpoint
	// OnChange, when set before Run, is called when the association's
	// validity (update or session keys) changes, for status reporting.
	OnChange func(Status)

	mu   sync.Mutex
	cur  any
	send func([]Frame)
}

// SecureConfig sets the endpoint configuration's Transmit to deliver the
// security messages on the started connection, builds the endpoint with
// build and returns the SecureLink (nil when build returns no endpoint).
func SecureConfig(base Config, build func(Config) (*Endpoint, error)) (*SecureLink, error) {
	s := &SecureLink{}
	base.Transmit = s.transmit
	ep, err := build(base)
	if err != nil || ep == nil {
		return nil, err
	}
	s.ep = ep
	return s, nil
}

// Endpoint is the association's endpoint.
func (s *SecureLink) Endpoint() *Endpoint { return s.ep }

// Run starts the endpoint (state kept over restarts) and its timers until
// ctx ends.
func (s *SecureLink) Run(ctx context.Context) {
	_ = s.ep.Start()
	// IEC 62351-9 certificate enrolment and renewal (Endpoint.SetEnrolment).
	go s.ep.RunEnrolment(ctx, nil)
	t := time.NewTicker(200 * time.Millisecond)
	defer t.Stop()
	var last Status
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-t.C:
			s.ep.Tick(now)
			if s.OnChange != nil {
				st := s.ep.Status()
				if st.UpdateKeysValid != last.UpdateKeysValid || st.SessionKeysValid != last.SessionKeysValid {
					s.OnChange(st)
				}
				last = st
			}
		}
	}
}

func (s *SecureLink) transmit(frames []Frame) {
	s.mu.Lock()
	send := s.send
	s.mu.Unlock()
	if send != nil {
		send(frames)
	}
}

// Attach makes conn the connection that carries the security messages
// (data transfer started on it): send must not block.
func (s *SecureLink) Attach(conn any, send func([]Frame)) {
	s.mu.Lock()
	s.cur, s.send = conn, send
	s.mu.Unlock()
	s.ep.LinkUp()
}

// Detach reports that conn stopped or ended; when it was the attached one,
// this is a communication failure for the A-Profile.
func (s *SecureLink) Detach(conn any) {
	s.mu.Lock()
	cur := s.cur == conn
	if cur {
		s.cur, s.send = nil, nil
	}
	s.mu.Unlock()
	if cur {
		s.ep.LinkDown()
	}
}

// Wrap protects an outgoing ASDU (see Endpoint.Wrap).
func (s *SecureLink) Wrap(asdu []byte) ([][]byte, error) { return s.ep.Wrap(asdu) }

// Unwrap passes a received ASDU through the endpoint and returns the
// application ASDU to deliver, if any.
func (s *SecureLink) Unwrap(asdu []byte) ([]byte, bool) {
	in, _ := s.ep.Receive(asdu)
	if in.Kind == Data || in.Kind == Plain {
		return in.ASDU, true
	}
	return nil, false
}

// SecParams converts the field sizes.
func SecParams(p iec60870.Params) Params {
	return Params{COTSize: p.COTSize, CASize: p.CASize}
}

// StatisticASDU encodes a security statistic report as an integrated total
// with time tag (M_IT_TB_1, TS 60870-5-7 5.4.2.3), spontaneous (cause 3)
// or answering a counter interrogation.
func StatisticASDU(r StatReport, ca uint16, cause iec60870.Cause, p iec60870.Params, loc *time.Location) ([]byte, error) {
	o := iec60870.Object{IOA: r.IOA, Value: float64(r.Value), Time: r.Time}
	if r.Carry {
		o.Quality |= iec60870.QCarry
	}
	a := &iec60870.ASDU{Type: iec60870.MItTb1, Cause: cause, Orig: p.Originator, CA: ca, Objects: []iec60870.Object{o}}
	return a.Encode(p, loc)
}
