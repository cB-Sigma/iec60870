// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package station

import (
	"context"
	"errors"
	"time"

	"github.com/cB-Sigma/iec60870"
)

// Point is one information object of the database.
type Point struct {
	// Object holds the address (IOA), value, quality, time tag and the
	// type's other elements (sequence number, elapsed time, change bits,
	// transient flag).
	iec60870.Object
	// Type is the monitor type sent spontaneously and in reads. Station
	// and group interrogation, cyclic and background data use its type
	// without time tag; IEC 104 sessions send the CP56Time2a twin of a
	// CP24Time2a type.
	Type iec60870.TypeID
	// Groups are the interrogation groups (1 to 16) the point answers
	// besides station interrogation.
	Groups []int
	// CounterGroup is the counter interrogation group (1 to 4) of an
	// integrated total; every total answers the general request.
	CounterGroup int
	// Cyclic points are sent every Config.CyclicPeriod with cause 1; P_AC
	// with QPA 3 switches it.
	Cyclic bool
	// Threshold, when positive, holds back spontaneous reports of a
	// measured value until it moved this far from the last value reported
	// (a quality change is always reported). P_ME with the threshold kind
	// sets it.
	Threshold float64
	// Silent points are never reported spontaneously (interrogation,
	// reads and cycles only).
	Silent bool
}

// Command is a command or set-point the station received.
type Command struct {
	CA   uint16
	Type iec60870.TypeID
	// Object holds the address, value (SCS, DCS, RCS, the set-point or
	// the bitstring), qualifier (QU or QL), S/E and the time tag.
	iec60870.Object
	Orig uint8
	// Test is the test bit of the cause of transmission: the station
	// confirms and terminates such a command without executing it.
	Test bool
}

// Control configures one command address of a sector.
type Control struct {
	IOA uint32
	// Type is the command type accepted; its twin with or without
	// CP56Time2a is accepted too (0: any command type).
	Type iec60870.TypeID
	// Monitor is the point the command changes when Execute is nil: it
	// takes the command's value (a regulating step moves a step position
	// by one) and is reported as return information.
	Monitor uint32
	// SelectRequired refuses an execute without a confirmed select of the
	// same type and value.
	SelectRequired bool
	// NoTermination: executes are confirmed but never terminated (no
	// ACTTERM).
	NoTermination bool
	// Select, when set, decides a select (nil error: positive
	// confirmation); an interlock check, or a select passed on to the
	// equipment.
	Select func(ctx context.Context, c Command) error
	// Execute, when set, carries out an execute. It calls confirm when it
	// accepts the command (the positive ACTCON goes out); returning nil
	// ends it with a positive ACTTERM, an error with a negative ACTTERM
	// (or a negative ACTCON when confirm was never called). It runs in a
	// goroutine of its own.
	Execute func(ctx context.Context, c Command, confirm func()) error
	// Cancel, when set, learns of a deactivated select; its error makes
	// the deactivation confirmation negative.
	Cancel func(ctx context.Context, c Command) error
}

// Config configures a Station.
type Config struct {
	// CA is the common address of the default sector (Station's embedded
	// Sector); further sectors come from Station.SectorAt.
	CA uint16
	// Params are the field sizes of IEC 104 sessions (zero: the IEC 104
	// defaults); cs101 sessions take theirs from ServeSecondary.
	Params iec60870.Params
	// Loc is the time zone of time tags (nil: UTC).
	Loc *time.Location
	// SelectTimeout is how long a confirmed select stays valid (zero: 30
	// s).
	SelectTimeout time.Duration
	// MaxCommandDelay, when positive, is the maximum allowable delay of a
	// time-tagged command (types 58 to 64): older ones are neither
	// executed nor answered.
	MaxCommandDelay time.Duration
	// CyclicPeriod and BackgroundPeriod, when positive, send the cyclic
	// points with cause 1 and every interrogated point with cause 2 (Run
	// drives them).
	CyclicPeriod     time.Duration
	BackgroundPeriod time.Duration
	// Files, when set, answers file transfer (types 120 to 127); without
	// it they are refused with cause 44.
	Files *iec60870.FileServer
	// OnClockSync decides a clock synchronisation (nil error: positive
	// confirmation, after which Now follows the time received). nil
	// accepts every one.
	OnClockSync func(t time.Time) error
	// OnResetProcess decides a reset process command (qualifier 1 general,
	// 2 time-tagged events); nil accepts both. After a positive general
	// reset the station sends its end of initialisation (COI 2).
	OnResetProcess func(qrp uint8) error
	// OnParameter decides a parameter of a measured value (kind 1
	// threshold, 2 smoothing, 3 low limit, 4 high limit); nil accepts it.
	OnParameter func(ca uint16, ioa uint32, kind uint8, v float64) error
	// ControlFor supplies controls not added with Sector.AddControl,
	// looked up per command.
	ControlFor func(ca uint16, ioa uint32) (Control, bool)
	// Intercept, when set, sees every received ASDU first; returning true
	// means it answered (through reply) or dropped it.
	Intercept func(a *iec60870.ASDU, reply func(*iec60870.ASDU)) bool
	// QueueLimit is the most ASDUs a session holds unsent (default 10000);
	// beyond it the oldest is dropped and counted (Stats).
	QueueLimit int
	// Now is the station's clock before any clock synchronisation (nil:
	// time.Now).
	Now func() time.Time
}

// ErrUnknownPoint is returned for an address the sector does not hold.
var ErrUnknownPoint = errors.New("no such information object")

// Refusal is an error a Select, Execute or Cancel handler returns to
// refuse a command with a cause of 44 to 47 (unknown type, cause, common
// address or object address) instead of a negative confirmation. A
// gateway passes a downstream station's refusal on with it.
type Refusal struct{ Cause iec60870.Cause }

func (r *Refusal) Error() string { return "refused: " + r.Cause.String() }

// refusal returns the cause of a Refusal in err (0: none).
func refusal(err error) iec60870.Cause {
	var r *Refusal
	if errors.As(err, &r) {
		return r.Cause
	}
	return 0
}

// Stats counts what the station did.
type Stats struct {
	Interrogations, CounterInterrogations, Commands, ClockSyncs int
	// Late counts time-tagged commands older than MaxCommandDelay.
	Late int
	// Dropped counts ASDUs dropped from full session queues.
	Dropped int
	// Sessions is the number of sessions attached now.
	Sessions int
}

// untagged maps a time-tagged monitor type to its type without time tag.
var untagged = map[iec60870.TypeID]iec60870.TypeID{
	iec60870.MSpTa1: iec60870.MSpNa1, iec60870.MSpTb1: iec60870.MSpNa1,
	iec60870.MDpTa1: iec60870.MDpNa1, iec60870.MDpTb1: iec60870.MDpNa1,
	iec60870.MStTa1: iec60870.MStNa1, iec60870.MStTb1: iec60870.MStNa1,
	iec60870.MBoTa1: iec60870.MBoNa1, iec60870.MBoTb1: iec60870.MBoNa1,
	iec60870.MMeTa1: iec60870.MMeNa1, iec60870.MMeTd1: iec60870.MMeNa1,
	iec60870.MMeTb1: iec60870.MMeNb1, iec60870.MMeTe1: iec60870.MMeNb1,
	iec60870.MMeTc1: iec60870.MMeNc1, iec60870.MMeTf1: iec60870.MMeNc1,
	iec60870.MItTa1: iec60870.MItNa1, iec60870.MItTb1: iec60870.MItNa1,
}

// Untagged returns the type without time tag of a monitor type (t itself
// when it has none or no such twin exists).
func Untagged(t iec60870.TypeID) iec60870.TypeID {
	if u, ok := untagged[t]; ok {
		return u
	}
	return t
}

// cp56 maps the CP24Time2a monitor types, which IEC 104 does not carry,
// to their CP56Time2a twins.
var cp56 = map[iec60870.TypeID]iec60870.TypeID{
	iec60870.MSpTa1: iec60870.MSpTb1, iec60870.MDpTa1: iec60870.MDpTb1, iec60870.MStTa1: iec60870.MStTb1,
	iec60870.MBoTa1: iec60870.MBoTb1, iec60870.MMeTa1: iec60870.MMeTd1, iec60870.MMeTb1: iec60870.MMeTe1,
	iec60870.MMeTc1: iec60870.MMeTf1, iec60870.MItTa1: iec60870.MItTb1, iec60870.MEpTa1: iec60870.MEpTd1,
	iec60870.MEpTb1: iec60870.MEpTe1, iec60870.MEpTc1: iec60870.MEpTf1,
}

// CP56 returns the CP56Time2a twin of a CP24Time2a monitor type (t itself
// otherwise): what an IEC 104 session sends in its place.
func CP56(t iec60870.TypeID) iec60870.TypeID {
	if u, ok := cp56[t]; ok {
		return u
	}
	return t
}

// commandTwin maps each command type to its twin with or without time
// tag.
var commandTwin = map[iec60870.TypeID]iec60870.TypeID{
	iec60870.CScNa1: iec60870.CScTa1, iec60870.CDcNa1: iec60870.CDcTa1, iec60870.CRcNa1: iec60870.CRcTa1,
	iec60870.CSeNa1: iec60870.CSeTa1, iec60870.CSeNb1: iec60870.CSeTb1, iec60870.CSeNc1: iec60870.CSeTc1,
	iec60870.CBoNa1: iec60870.CBoTa1,
	iec60870.CScTa1: iec60870.CScNa1, iec60870.CDcTa1: iec60870.CDcNa1, iec60870.CRcTa1: iec60870.CRcNa1,
	iec60870.CSeTa1: iec60870.CSeNa1, iec60870.CSeTb1: iec60870.CSeNb1, iec60870.CSeTc1: iec60870.CSeNc1,
	iec60870.CBoTa1: iec60870.CBoNa1,
}

func isCommand(t iec60870.TypeID) bool { _, ok := commandTwin[t]; return ok }

func isCounter(t iec60870.TypeID) bool {
	return t == iec60870.MItNa1 || t == iec60870.MItTa1 || t == iec60870.MItTb1
}

// isEvent reports the protection event types, which are sent
// spontaneously only.
func isEvent(t iec60870.TypeID) bool {
	return t >= iec60870.MEpTa1 && t <= iec60870.MEpTc1 || t >= iec60870.MEpTd1 && t <= iec60870.MEpTf1
}

func isMeasured(t iec60870.TypeID) bool {
	switch Untagged(t) {
	case iec60870.MMeNa1, iec60870.MMeNb1, iec60870.MMeNc1, iec60870.MMeNd1:
		return true
	}
	return false
}

// returnCause is the cause of return information for a point: 11 for
// single, double and step positions (IEC 60870-5-101 7.4.7), spontaneous
// for the rest.
func returnCause(t iec60870.TypeID) iec60870.Cause {
	switch Untagged(t) {
	case iec60870.MSpNa1, iec60870.MDpNa1, iec60870.MStNa1:
		return iec60870.CauseReturnRemote
	}
	return iec60870.CauseSpontaneous
}
