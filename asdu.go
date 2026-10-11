package iec60870

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"strings"
	"time"
)

// MaxASDU is the largest ASDU Encode produces: what an IEC 104 APDU
// carries (253 octets less the 4 control octets). IEC 101 frames carry up
// to 255 less the control and address octets (see EncodeMax).
const MaxASDU = 249

// MaxFrameASDU is the largest ASDU EncodeMax produces: what an IEC 101 frame
// without a link address field carries (L at most 255, less the control
// octet).
const MaxFrameASDU = 254

// TypeID identifies an ASDU's information object type (IEC 60870-5-101
// clause 7.2.1, reused by 104).
type TypeID uint8

// The type identifications this package encodes and decodes: IEC
// 60870-5-101 clause 7.3 (Tables 8 to 13) and the IEC 60870-5-104 types
// 58 to 64 and 107.
const (
	MSpNa1 TypeID = 1  // single-point information
	MSpTa1 TypeID = 2  // single-point with CP24Time2a
	MDpNa1 TypeID = 3  // double-point information
	MDpTa1 TypeID = 4  // double-point with CP24Time2a
	MStNa1 TypeID = 5  // step position
	MStTa1 TypeID = 6  // step position with CP24Time2a
	MBoNa1 TypeID = 7  // bitstring of 32 bits
	MBoTa1 TypeID = 8  // bitstring with CP24Time2a
	MMeNa1 TypeID = 9  // measured value, normalised
	MMeTa1 TypeID = 10 // normalised with CP24Time2a
	MMeNb1 TypeID = 11 // measured value, scaled
	MMeTb1 TypeID = 12 // scaled with CP24Time2a
	MMeNc1 TypeID = 13 // measured value, short floating point
	MMeTc1 TypeID = 14 // short float with CP24Time2a
	MItNa1 TypeID = 15 // integrated totals
	MItTa1 TypeID = 16 // integrated totals with CP24Time2a
	MEpTa1 TypeID = 17 // event of protection equipment with CP24Time2a
	MEpTb1 TypeID = 18 // packed start events of protection equipment with CP24Time2a
	MEpTc1 TypeID = 19 // packed output circuit information with CP24Time2a
	MPsNa1 TypeID = 20 // packed single-point information with status change detection
	MMeNd1 TypeID = 21 // measured value, normalised, without quality descriptor
	MSpTb1 TypeID = 30 // single-point with CP56Time2a
	MDpTb1 TypeID = 31 // double-point with CP56Time2a
	MStTb1 TypeID = 32 // step position with CP56Time2a
	MBoTb1 TypeID = 33 // bitstring with CP56Time2a
	MMeTd1 TypeID = 34 // normalised with CP56Time2a
	MMeTe1 TypeID = 35 // scaled with CP56Time2a
	MMeTf1 TypeID = 36 // short float with CP56Time2a
	MItTb1 TypeID = 37 // integrated totals with CP56Time2a
	MEpTd1 TypeID = 38 // event of protection equipment with CP56Time2a
	MEpTe1 TypeID = 39 // packed start events of protection equipment with CP56Time2a
	MEpTf1 TypeID = 40 // packed output circuit information with CP56Time2a
	CScNa1 TypeID = 45 // single command
	CDcNa1 TypeID = 46 // double command
	CRcNa1 TypeID = 47 // regulating step command
	CSeNa1 TypeID = 48 // set-point, normalised
	CSeNb1 TypeID = 49 // set-point, scaled
	CSeNc1 TypeID = 50 // set-point, short float
	CBoNa1 TypeID = 51 // bitstring of 32 bits (command)
	CScTa1 TypeID = 58 // single command with CP56Time2a
	CDcTa1 TypeID = 59 // double command with CP56Time2a
	CRcTa1 TypeID = 60 // regulating step command with CP56Time2a
	CSeTa1 TypeID = 61 // set-point, normalised, with CP56Time2a
	CSeTb1 TypeID = 62 // set-point, scaled, with CP56Time2a
	CSeTc1 TypeID = 63 // set-point, short float, with CP56Time2a
	CBoTa1 TypeID = 64 // bitstring of 32 bits with CP56Time2a (command)
	MEiNa1 TypeID = 70 // end of initialisation
	CIcNa1 TypeID = 100
	CCiNa1 TypeID = 101
	CRdNa1 TypeID = 102 // read command
	CCsNa1 TypeID = 103
	CTsNa1 TypeID = 104 // test command (IEC 60870-5-101 only)
	CRpNa1 TypeID = 105 // reset process command
	CCdNa1 TypeID = 106 // delay acquisition command (IEC 60870-5-101 only)
	CTsTa1 TypeID = 107 // test command with CP56Time2a (IEC 60870-5-104 clause 8.8)
	PMeNa1 TypeID = 110 // parameter of measured value, normalised
	PMeNb1 TypeID = 111 // parameter of measured value, scaled
	PMeNc1 TypeID = 112 // parameter of measured value, short float
	PAcNa1 TypeID = 113 // parameter activation
	FFrNa1 TypeID = 120 // file ready
	FSrNa1 TypeID = 121 // section ready
	FScNa1 TypeID = 122 // call directory, select file, call file, call section
	FLsNa1 TypeID = 123 // last section, last segment
	FAfNa1 TypeID = 124 // ack file, ack section
	FSgNa1 TypeID = 125 // segment
	FDrTa1 TypeID = 126 // directory
	FScNb1 TypeID = 127 // query log, request archive file (IEC 60870-5-104 clause 8.9)
)

var typeNames = map[TypeID]string{
	MSpNa1: "M_SP_NA_1", MDpNa1: "M_DP_NA_1", MMeNa1: "M_ME_NA_1", MMeNb1: "M_ME_NB_1", MMeNc1: "M_ME_NC_1",
	MItNa1: "M_IT_NA_1", MSpTb1: "M_SP_TB_1", MDpTb1: "M_DP_TB_1", MMeTd1: "M_ME_TD_1", MMeTe1: "M_ME_TE_1",
	MMeTf1: "M_ME_TF_1", MItTb1: "M_IT_TB_1", CScNa1: "C_SC_NA_1", CDcNa1: "C_DC_NA_1", CSeNa1: "C_SE_NA_1",
	CSeNb1: "C_SE_NB_1", CSeNc1: "C_SE_NC_1", CScTa1: "C_SC_TA_1", CDcTa1: "C_DC_TA_1", CSeTa1: "C_SE_TA_1",
	CSeTb1: "C_SE_TB_1", CSeTc1: "C_SE_TC_1", MEiNa1: "M_EI_NA_1", CIcNa1: "C_IC_NA_1", CCiNa1: "C_CI_NA_1",
	CCsNa1: "C_CS_NA_1", MSpTa1: "M_SP_TA_1", MDpTa1: "M_DP_TA_1", MStNa1: "M_ST_NA_1", MStTa1: "M_ST_TA_1",
	MBoNa1: "M_BO_NA_1", MBoTa1: "M_BO_TA_1", MMeTa1: "M_ME_TA_1", MMeTb1: "M_ME_TB_1", MMeTc1: "M_ME_TC_1",
	MItTa1: "M_IT_TA_1", MStTb1: "M_ST_TB_1", MBoTb1: "M_BO_TB_1", CRcNa1: "C_RC_NA_1", CBoNa1: "C_BO_NA_1",
	CRcTa1: "C_RC_TA_1", CBoTa1: "C_BO_TA_1", CTsTa1: "C_TS_TA_1",
	MEpTa1: "M_EP_TA_1", MEpTb1: "M_EP_TB_1", MEpTc1: "M_EP_TC_1", MPsNa1: "M_PS_NA_1", MMeNd1: "M_ME_ND_1",
	MEpTd1: "M_EP_TD_1", MEpTe1: "M_EP_TE_1", MEpTf1: "M_EP_TF_1", CRdNa1: "C_RD_NA_1", CTsNa1: "C_TS_NA_1",
	CRpNa1: "C_RP_NA_1", CCdNa1: "C_CD_NA_1", PMeNa1: "P_ME_NA_1", PMeNb1: "P_ME_NB_1", PMeNc1: "P_ME_NC_1",
	PAcNa1: "P_AC_NA_1", FFrNa1: "F_FR_NA_1", FSrNa1: "F_SR_NA_1", FScNa1: "F_SC_NA_1", FLsNa1: "F_LS_NA_1",
	FAfNa1: "F_AF_NA_1", FSgNa1: "F_SG_NA_1", FDrTa1: "F_DR_TA_1", FScNb1: "F_SC_NB_1",
}

// String is the type's name (M_SP_NA_1) or its number.
func (t TypeID) String() string {
	if n, ok := typeNames[t]; ok {
		return n
	}
	return fmt.Sprintf("type %d", uint8(t))
}

// TypeByName returns the type identification called n (such as
// "M_ME_NC_1").
func TypeByName(n string) (TypeID, bool) {
	for t, name := range typeNames {
		if name == n {
			return t, true
		}
	}
	return 0, false
}

// CP24 reports whether the type's objects carry a CP24Time2a time tag
// (the IEC 60870-5-101 only types).
func (t TypeID) CP24() bool { return shapes[t].tag == tagCP24 }

// ObjectSize is the octets of one information object of the type after its
// address: the elements and the time tag (0 for a type without a fixed
// layout).
func (t TypeID) ObjectSize() int { sh := shapes[t]; return sh.size + sh.tag }

// shape is how one information element of a type is laid out.
type shape struct {
	size int // element bytes, without a time tag (F_SG_NA_1: without the segment)
	tag  int // time tag bytes that follow: 0, 3 (CP24Time2a) or 7 (CP56Time2a)
}

// Time tag sizes.
const (
	noTag   = 0
	tagCP24 = 3
	tagCP56 = 7
)

// shapes follows the ASDU figures of IEC 60870-5-101 clause 7.3 (the
// element octets between the information object address and the time
// tag).
var shapes = map[TypeID]shape{
	MSpNa1: {1, noTag}, MDpNa1: {1, noTag}, MStNa1: {2, noTag}, MBoNa1: {5, noTag}, MMeNa1: {3, noTag},
	MMeNb1: {3, noTag}, MMeNc1: {5, noTag}, MItNa1: {5, noTag},
	MSpTa1: {1, tagCP24}, MDpTa1: {1, tagCP24}, MStTa1: {2, tagCP24}, MBoTa1: {5, tagCP24}, MMeTa1: {3, tagCP24},
	MMeTb1: {3, tagCP24}, MMeTc1: {5, tagCP24}, MItTa1: {5, tagCP24},
	// 7.3.1.17 to 7.3.1.19: SEP or SPE/OCI with QDP, then CP16Time2a.
	MEpTa1: {3, tagCP24}, MEpTb1: {4, tagCP24}, MEpTc1: {4, tagCP24},
	MPsNa1: {5, noTag}, MMeNd1: {2, noTag}, // SCD with QDS; NVA alone
	MSpTb1: {1, tagCP56}, MDpTb1: {1, tagCP56}, MStTb1: {2, tagCP56}, MBoTb1: {5, tagCP56}, MMeTd1: {3, tagCP56},
	MMeTe1: {3, tagCP56}, MMeTf1: {5, tagCP56}, MItTb1: {5, tagCP56},
	MEpTd1: {3, tagCP56}, MEpTe1: {4, tagCP56}, MEpTf1: {4, tagCP56},
	CScNa1: {1, noTag}, CDcNa1: {1, noTag}, CSeNa1: {3, noTag}, CSeNb1: {3, noTag}, CSeNc1: {5, noTag},
	CScTa1: {1, tagCP56}, CDcTa1: {1, tagCP56}, CSeTa1: {3, tagCP56}, CSeTb1: {3, tagCP56}, CSeTc1: {5, tagCP56},
	MEiNa1: {1, noTag}, CIcNa1: {1, noTag}, CCiNa1: {1, noTag}, CCsNa1: {0, tagCP56},
	// Clause 8 (Figures 25, 29 and 30): RCO is one octet (S/E, QU, RCS),
	// BSI four octets, TSC a 16-bit counter; each is followed by
	// CP56Time2a in the time-tagged types.
	CRcNa1: {1, noTag}, CRcTa1: {1, tagCP56}, CBoNa1: {4, noTag}, CBoTa1: {4, tagCP56}, CTsTa1: {2, tagCP56},
	// 7.3.4.3 to 7.3.4.7: no element (read), FBP, QRP, CP16Time2a.
	CRdNa1: {0, noTag}, CTsNa1: {2, noTag}, CRpNa1: {1, noTag}, CCdNa1: {2, noTag},
	// 7.3.5: the value and QPM; QPA.
	PMeNa1: {3, noTag}, PMeNb1: {3, noTag}, PMeNc1: {5, noTag}, PAcNa1: {1, noTag},
	// 7.3.6: NOF (2), NOS (1), LOF (3), LOS (1), the qualifier or CHS.
	FFrNa1: {6, noTag}, FSrNa1: {7, noTag}, FScNa1: {4, noTag}, FLsNa1: {5, noTag}, FAfNa1: {4, noTag},
	FSgNa1: {4, noTag}, FDrTa1: {6, tagCP56},
	// IEC 60870-5-104 Figure 31: NOF and two CP56Time2a (start, stop).
	FScNb1: {16, noTag}, // the element and both time tags
}

// TimeTagged reports whether the type carries a time tag (CP24Time2a or
// CP56Time2a).
func (t TypeID) TimeTagged() bool { return shapes[t].tag != noTag }

// Monitor reports whether t carries process information in monitor
// direction (types 1 to 40).
func (t TypeID) Monitor() bool { return t >= 1 && t <= 44 }

// File reports whether t is a file transfer type (120 to 127).
func (t TypeID) File() bool { return t >= 120 && t <= 127 }

// Control reports a type of the control direction answered with
// confirmations: process commands, system commands and parameters (45 to
// 69, 100 to 119).
func (t TypeID) Control() bool { return t >= 45 && t <= 69 || t >= 100 && t <= 119 }

// Cause is the cause of transmission (6 bits).
type Cause uint8

// Causes of transmission (IEC 60870-5-101 7.2.3 Table 14).
const (
	CausePeriodic     Cause = 1
	CauseBackground   Cause = 2
	CauseSpontaneous  Cause = 3
	CauseInitialised  Cause = 4
	CauseRequest      Cause = 5
	CauseActivation   Cause = 6
	CauseActCon       Cause = 7
	CauseDeactivation Cause = 8
	CauseDeactCon     Cause = 9
	CauseActTerm      Cause = 10
	CauseReturnRemote Cause = 11
	CauseReturnLocal  Cause = 12
	CauseFile         Cause = 13
	// IEC TS 60870-5-7 5.4.2.1 Table 1 (security extension).
	CauseDataProtection Cause = 14
	CauseSessionKey     Cause = 15
	CauseAssociation    Cause = 16
	CauseNotAuthorized  Cause = 17
	CauseInterrogated   Cause = 20 // station interrogation; 21–36 are groups 1–16
	CauseCounterGen     Cause = 37 // general counter request; 38–41 are groups 1–4
	CauseUnknownType    Cause = 44
	CauseUnknownCause   Cause = 45
	CauseUnknownCA      Cause = 46
	CauseUnknownObject  Cause = 47
)

var causeNames = map[Cause]string{
	1: "periodic", 2: "background", 3: "spontaneous", 4: "initialised", 5: "request", 6: "activation",
	7: "activation confirmation", 8: "deactivation", 9: "deactivation confirmation", 10: "activation termination",
	11: "return (remote command)", 12: "return (local command)", 13: "file transfer", 14: "application data protection",
	15: "maintenance of session key", 16: "maintenance of association and update key", 17: "operation not authorized", 20: "station interrogation",
	37: "counter interrogation", 44: "unknown type identification", 45: "unknown cause of transmission",
	46: "unknown common address", 47: "unknown information object address",
}

// String names the cause of transmission.
func (c Cause) String() string {
	if n, ok := causeNames[c]; ok {
		return n
	}
	switch {
	case c >= 21 && c <= 36:
		return fmt.Sprintf("group %d interrogation", c-20)
	case c >= 38 && c <= 41:
		return fmt.Sprintf("group %d counter interrogation", c-37)
	case c >= 48:
		return fmt.Sprintf("private cause %d", uint8(c))
	}
	return fmt.Sprintf("cause %d", uint8(c))
}

// Params are the system parameters fixed per connection: field sizes and
// our originator address.
type Params struct {
	COTSize    int   // 1 or 2 (default 2, as 104 prescribes)
	CASize     int   // 1 or 2 (default 2)
	IOASize    int   // 1, 2 or 3 (default 3)
	Originator uint8 // our originator address, sent when COTSize is 2
	// PackedStep is the address step between the objects of a packed
	// single-point sequence (M_PS_NA_1 with SQ=1): 0 or 16 follows
	// Amendment 1 (7.3.1.20: one address per status bit); 1 counts the
	// objects, as lib60870 2.4.1 and some stations do. Other values are
	// invalid.
	PackedStep int
}

// WithDefaults fills zero sizes with the IEC 60870-5-104 values.
func (p Params) WithDefaults() Params {
	if p.COTSize == 0 {
		p.COTSize = 2
	}
	if p.CASize == 0 {
		p.CASize = 2
	}
	if p.IOASize == 0 {
		p.IOASize = 3
	}
	return p
}

// Validate checks the sizes.
func (p Params) Validate() error {
	if p.COTSize != 1 && p.COTSize != 2 {
		return fmt.Errorf("cause of transmission size %d is not 1 or 2", p.COTSize)
	}
	if p.CASize != 1 && p.CASize != 2 {
		return fmt.Errorf("common address size %d is not 1 or 2", p.CASize)
	}
	if p.IOASize < 1 || p.IOASize > 3 {
		return fmt.Errorf("information object address size %d is not 1, 2 or 3", p.IOASize)
	}
	if p.PackedStep != 0 && p.PackedStep != 1 && p.PackedStep != 16 {
		return fmt.Errorf("packed single-point step %d is not 1 or 16", p.PackedStep)
	}
	return nil
}

// Header is the size of the data unit identifier.
func (p Params) Header() int { return 2 + p.COTSize + p.CASize }

// Quality descriptor bits (IEC 60870-5-101 7.2.6.1 to 7.2.6.4 and
// 7.2.6.10: SIQ, DIQ, QDS, QDP and SEP share BL, SB, NT and IV in bits 5
// to 8).
const (
	QOverflow    uint8 = 0x01 // OV (QDS, bit 1)
	QBlocked     uint8 = 0x10 // BL
	QSubstituted uint8 = 0x20 // SB
	QNotTopical  uint8 = 0x40 // NT
	QInvalid     uint8 = 0x80 // IV
	// Integrated totals use bits 5–7 differently (their sequence number is
	// in bits 0–4); Object.Quality holds them translated to these.
	QCarry    uint8 = 0x02 // CY: counter overflowed in the period
	QAdjusted uint8 = 0x04 // CA: counter was adjusted
	// QElapsedInvalid is EI of QDP and SEP (bit 4): the elapsed time of a
	// protection event is not valid.
	QElapsedInvalid uint8 = 0x08
)

// QualityString is "good" or the set flags, comma-separated.
func QualityString(q uint8) string {
	var f []string
	for _, x := range []struct {
		bit  uint8
		name string
	}{{QInvalid, "invalid"}, {QNotTopical, "not-topical"}, {QSubstituted, "substituted"}, {QBlocked, "blocked"},
		{QOverflow, "overflow"}, {QCarry, "carry"}, {QAdjusted, "adjusted"}, {QElapsedInvalid, "elapsed-invalid"}} {
		if q&x.bit != 0 {
			f = append(f, x.name)
		}
	}
	if len(f) == 0 {
		return "good"
	}
	return strings.Join(f, ",")
}

// Object is one information object. Which fields matter depends on the
// ASDU's type.
type Object struct {
	IOA uint32
	// Value: bool for single points and single commands; 0–3 (DPI/DCS) for
	// double points and commands; the scaled int16 or the float for
	// measured values, set-points and parameters (normalised values as
	// −1 … <1); the counter for integrated totals; the status bits (ST)
	// of packed single points; ES (0–3) of protection events and the SPE
	// or OCI octet of packed protection information; the qualifier for
	// C_IC (QOI), C_CI (QCC), C_RP (QRP) and M_EI (COI); the fixed test
	// pattern of C_TS_NA_1 and the counter of C_TS_TA_1.
	Value float64
	// Quality is the QDS/SIQ/DIQ/QDP/SEP flags; for integrated totals IV,
	// CY and CA translated to QInvalid, QCarry and QAdjusted.
	Quality uint8
	// Seq is an integrated total's sequence number (0–31).
	Seq uint8
	// Time is the time tag, for timed types; TimeInvalid is its IV bit and
	// TimeSubstituted its RES1 (GEN) bit. A CP24Time2a tag (milliseconds
	// and minutes only) is completed to a full time against the receiver's
	// clock when decoded (see CompleteCP24).
	Time            time.Time
	TimeInvalid     bool
	TimeSubstituted bool
	// Elapsed is a CP16Time2a: the elapsed, duration or operating time of
	// protection information, or the delay of C_CD_NA_1.
	Elapsed time.Duration
	// Change is the change detection bits (CD) of a packed single point.
	Change uint16
	// Select is S/E (true selects) and Qualifier QU/QL of commands and
	// set-points, QPM of parameters, QPA of parameter activation, and
	// FRQ, SRQ, SCQ, LSQ or AFQ of the file transfer types.
	Select    bool
	Qualifier uint8
	// Transient is a step position's transient flag (the equipment is
	// moving).
	Transient bool
	// File transfer: name of file (NOF), name of section (NOS), length of
	// file or section (LOF, LOS), checksum (CHS), status of file (SOF) and
	// a segment's octets.
	File     uint16
	Section  uint8
	Length   uint32
	Checksum uint8
	Status   uint8
	Segment  []byte
	// Stop is the RangeStopTime of F_SC_NB_1 (Time is RangeStartTime);
	// a zero time is sent as seven zero octets (no bound).
	Stop time.Time
}

// ASDU is an application service data unit.
type ASDU struct {
	Type     TypeID
	SQ       bool // elements are a sequence starting at Objects[0].IOA
	Cause    Cause
	Negative bool // P/N
	Test     bool
	Orig     uint8
	CA       uint16
	Objects  []Object
}

// String describes the ASDU for logs.
func (a *ASDU) String() string {
	pn := ""
	if a.Negative {
		pn = " negative"
	}
	return fmt.Sprintf("%s%s %s CA %d, %d objects", a.Type, pn, a.Cause, a.CA, len(a.Objects))
}

// ErrUnsupportedType is wrapped when a type identification is unknown.
var ErrUnsupportedType = errors.New("unsupported type identification")

// seqStep is the address step between the objects of a sequence (SQ=1):
// one, but sixteen for packed single points, whose object j carries
// the points from A+16(j−1) (Amendment 1, 7.3.1.20), unless p asks for one.
func seqStep(t TypeID, p Params) uint32 {
	if t == MPsNa1 && p.PackedStep != 1 {
		return 16
	}
	return 1
}

// Encode serialises the ASDU. loc is the time zone of time tags.
func (a *ASDU) Encode(p Params, loc *time.Location) ([]byte, error) {
	return a.EncodeMax(p, loc, MaxASDU)
}

// EncodeMax is Encode for a link that carries ASDUs of up to max octets
// (at most MaxFrameASDU): an IEC 101 frame takes up to 255 less its
// control and address octets, more than an IEC 104 APDU.
func (a *ASDU) EncodeMax(p Params, loc *time.Location, max int) ([]byte, error) {
	max = min(max, MaxFrameASDU)
	sh, ok := shapes[a.Type]
	if !ok {
		return nil, fmt.Errorf("%w %d", ErrUnsupportedType, a.Type)
	}
	// Amendment 1 (7.1): an ASDU may carry no information object.
	if len(a.Objects) > 127 {
		return nil, fmt.Errorf("an ASDU holds at most 127 objects, not %d", len(a.Objects))
	}
	if a.SQ && sh.tag != noTag && a.Type.Monitor() {
		return nil, fmt.Errorf("%s carries a time tag per object and cannot be a sequence (SQ=1)", a.Type)
	}
	b := []byte{byte(a.Type), byte(len(a.Objects))}
	if a.SQ {
		b[1] |= 0x80
	}
	cot := byte(a.Cause) & 0x3f
	if a.Negative {
		cot |= 0x40
	}
	if a.Test {
		cot |= 0x80
	}
	b = append(b, cot)
	if p.COTSize == 2 {
		b = append(b, a.Orig)
	}
	b = append(b, byte(a.CA))
	if p.CASize == 2 {
		b = append(b, byte(a.CA>>8))
	}
	for i, o := range a.Objects {
		if i == 0 || !a.SQ {
			for j := 0; j < p.IOASize; j++ {
				b = append(b, byte(o.IOA>>(8*j)))
			}
		}
		var err error
		if b, err = encodeElement(b, a.Type, o); err != nil {
			return nil, err
		}
		if a.Type == FScNb1 {
			// Figure 31: RangeStartTime and RangeStopTime; all zeros is no
			// bound.
			for _, x := range []time.Time{o.Time, o.Stop} {
				if x.IsZero() {
					b = append(b, 0, 0, 0, 0, 0, 0, 0)
				} else {
					b = append(b, cp56(x, false, false, true, loc)...)
				}
			}
		}
		// 7.4.6: the summer-time bit of a clock synchronisation is ignored
		// and set to zero.
		su := a.Type != CCsNa1
		switch sh.tag {
		case tagCP24:
			b = append(b, cp56(o.Time, o.TimeInvalid, o.TimeSubstituted, su, loc)[:3]...)
		case tagCP56:
			b = append(b, cp56(o.Time, o.TimeInvalid, o.TimeSubstituted, su, loc)...)
		}
	}
	if len(b) > max {
		return nil, fmt.Errorf("the ASDU is %d bytes; at most %d fit in a frame", len(b), max)
	}
	return b, nil
}

func quality(q uint8) byte { return q & (QOverflow | QBlocked | QSubstituted | QNotTopical | QInvalid) }

// qdp is the quality of protection information: BL, SB, NT, IV and EI.
func qdp(q uint8) byte {
	return q & (QBlocked | QSubstituted | QNotTopical | QInvalid | QElapsedInvalid)
}

func cp16(d time.Duration) ([]byte, error) {
	ms := d.Milliseconds()
	if ms < 0 || ms > 59999 {
		return nil, fmt.Errorf("CP16Time2a holds 0 to 59999 ms, not %d", ms)
	}
	return binary.LittleEndian.AppendUint16(nil, uint16(ms)), nil
}

func encodeElement(b []byte, t TypeID, o Object) ([]byte, error) {
	se := byte(0)
	if o.Select {
		se = 0x80
	}
	switch t {
	case MSpNa1, MSpTa1, MSpTb1:
		v := quality(o.Quality) &^ QOverflow
		if o.Value != 0 {
			v |= 1
		}
		return append(b, v), nil
	case MDpNa1, MDpTa1, MDpTb1:
		return append(b, quality(o.Quality)&^QOverflow|byte(o.Value)&3), nil
	case MStNa1, MStTa1, MStTb1:
		if o.Value < -64 || o.Value > 63 {
			return nil, fmt.Errorf("step position %v is outside -64 to 63", o.Value)
		}
		v := byte(int8(o.Value)) & 0x7f
		if o.Transient {
			v |= 0x80
		}
		return append(b, v, quality(o.Quality)), nil
	case MBoNa1, MBoTa1, MBoTb1:
		if o.Value < 0 || o.Value > math.MaxUint32 {
			return nil, fmt.Errorf("bitstring %v does not fit 32 bits", o.Value)
		}
		return append(binary.LittleEndian.AppendUint32(b, uint32(o.Value)), quality(o.Quality)), nil
	case MMeNa1, MMeTa1, MMeTd1:
		return append(binary.LittleEndian.AppendUint16(b, uint16(normalised(o.Value))), quality(o.Quality)), nil
	case MMeNd1:
		return binary.LittleEndian.AppendUint16(b, uint16(normalised(o.Value))), nil
	case MMeNb1, MMeTb1, MMeTe1:
		return append(binary.LittleEndian.AppendUint16(b, uint16(int16(o.Value))), quality(o.Quality)), nil
	case MMeNc1, MMeTc1, MMeTf1:
		return append(binary.LittleEndian.AppendUint32(b, math.Float32bits(float32(o.Value))), quality(o.Quality)), nil
	case MItNa1, MItTa1, MItTb1:
		f := o.Seq & 0x1f
		if o.Quality&QCarry != 0 {
			f |= 0x20
		}
		if o.Quality&QAdjusted != 0 {
			f |= 0x40
		}
		if o.Quality&QInvalid != 0 {
			f |= 0x80
		}
		return append(binary.LittleEndian.AppendUint32(b, uint32(int32(o.Value))), f), nil
	case MPsNa1:
		if o.Value < 0 || o.Value > math.MaxUint16 {
			return nil, fmt.Errorf("packed single points %v do not fit 16 bits", o.Value)
		}
		// Amendment 1: OV of this QDS is always 0.
		b = binary.LittleEndian.AppendUint16(b, uint16(o.Value))
		return append(binary.LittleEndian.AppendUint16(b, o.Change), quality(o.Quality)&^QOverflow), nil
	case MEpTa1, MEpTd1:
		el, err := cp16(o.Elapsed)
		if err != nil {
			return nil, err
		}
		return append(append(b, qdp(o.Quality)|byte(o.Value)&3), el...), nil
	case MEpTb1, MEpTe1, MEpTc1, MEpTf1:
		el, err := cp16(o.Elapsed)
		if err != nil {
			return nil, err
		}
		mask := byte(0x3f) // SPE: GS, SL1–SL3, SIE, SRD
		if t == MEpTc1 || t == MEpTf1 {
			mask = 0x0f // OCI: GC, CL1–CL3
		}
		return append(append(b, byte(o.Value)&mask, qdp(o.Quality)), el...), nil
	case CScNa1, CScTa1:
		v := se | (o.Qualifier&0x1f)<<2
		if o.Value != 0 {
			v |= 1
		}
		return append(b, v), nil
	case CDcNa1, CDcTa1, CRcNa1, CRcTa1:
		return append(b, se|(o.Qualifier&0x1f)<<2|byte(o.Value)&3), nil
	case CBoNa1, CBoTa1:
		if o.Value < 0 || o.Value > math.MaxUint32 {
			return nil, fmt.Errorf("bitstring %v does not fit 32 bits", o.Value)
		}
		return binary.LittleEndian.AppendUint32(b, uint32(o.Value)), nil
	case CTsTa1, CTsNa1:
		if o.Value < 0 || o.Value > math.MaxUint16 {
			return nil, fmt.Errorf("test value %v does not fit 16 bits", o.Value)
		}
		return binary.LittleEndian.AppendUint16(b, uint16(o.Value)), nil
	case CSeNa1, CSeTa1:
		return append(binary.LittleEndian.AppendUint16(b, uint16(normalised(o.Value))), se|o.Qualifier&0x7f), nil
	case CSeNb1, CSeTb1:
		if o.Value < math.MinInt16 || o.Value > math.MaxInt16 {
			return nil, fmt.Errorf("%v does not fit a scaled value", o.Value)
		}
		return append(binary.LittleEndian.AppendUint16(b, uint16(int16(math.Round(o.Value)))), se|o.Qualifier&0x7f), nil
	case CSeNc1, CSeTc1:
		return append(binary.LittleEndian.AppendUint32(b, math.Float32bits(float32(o.Value))), se|o.Qualifier&0x7f), nil
	case MEiNa1, CIcNa1, CCiNa1, CRpNa1:
		if o.Value < 0 || o.Value > 255 {
			return nil, fmt.Errorf("qualifier %v does not fit one octet", o.Value)
		}
		return append(b, byte(o.Value)), nil
	case CCsNa1, CRdNa1:
		return b, nil
	case CCdNa1:
		el, err := cp16(o.Elapsed)
		if err != nil {
			return nil, err
		}
		return append(b, el...), nil
	case PMeNa1:
		return append(binary.LittleEndian.AppendUint16(b, uint16(normalised(o.Value))), o.Qualifier), nil
	case PMeNb1:
		if o.Value < math.MinInt16 || o.Value > math.MaxInt16 {
			return nil, fmt.Errorf("%v does not fit a scaled value", o.Value)
		}
		return append(binary.LittleEndian.AppendUint16(b, uint16(int16(math.Round(o.Value)))), o.Qualifier), nil
	case PMeNc1:
		return append(binary.LittleEndian.AppendUint32(b, math.Float32bits(float32(o.Value))), o.Qualifier), nil
	case PAcNa1:
		return append(b, o.Qualifier), nil
	case FFrNa1:
		b = binary.LittleEndian.AppendUint16(b, o.File)
		return append(append24(b, o.Length), o.Qualifier), nil
	case FSrNa1:
		b = append(binary.LittleEndian.AppendUint16(b, o.File), o.Section)
		return append(append24(b, o.Length), o.Qualifier), nil
	case FScNa1, FAfNa1:
		return append(binary.LittleEndian.AppendUint16(b, o.File), o.Section, o.Qualifier), nil
	case FLsNa1:
		return append(binary.LittleEndian.AppendUint16(b, o.File), o.Section, o.Qualifier, o.Checksum), nil
	case FSgNa1:
		if len(o.Segment) > 255 {
			return nil, fmt.Errorf("a segment holds at most 255 octets, not %d", len(o.Segment))
		}
		b = append(binary.LittleEndian.AppendUint16(b, o.File), o.Section, byte(len(o.Segment)))
		return append(b, o.Segment...), nil
	case FDrTa1:
		b = binary.LittleEndian.AppendUint16(b, o.File)
		return append(append24(b, o.Length), o.Status), nil
	case FScNb1:
		return binary.LittleEndian.AppendUint16(b, o.File), nil // the range follows in Encode
	}
	return nil, fmt.Errorf("%w %d", ErrUnsupportedType, t)
}

func append24(b []byte, v uint32) []byte { return append(b, byte(v), byte(v>>8), byte(v>>16)) }

// normalised converts −1 … <1 to the 16-bit fixed-point form.
func normalised(v float64) int16 {
	x := math.Round(v * 32768)
	return int16(max(math.MinInt16, min(math.MaxInt16, x)))
}

// DecodeASDU parses an ASDU. loc is the time zone of time tags; CP24Time2a
// tags are completed against the current time.
func DecodeASDU(b []byte, p Params, loc *time.Location) (*ASDU, error) {
	return DecodeASDUAt(b, p, loc, time.Now())
}

// DecodeASDUAt is DecodeASDU with now as the receiver's clock, which
// supplies the date and hour of CP24Time2a time tags.
func DecodeASDUAt(b []byte, p Params, loc *time.Location, now time.Time) (*ASDU, error) {
	hdr := p.Header()
	if len(b) < hdr {
		return nil, fmt.Errorf("the ASDU is %d bytes, shorter than its header", len(b))
	}
	a := &ASDU{Type: TypeID(b[0]), SQ: b[1]&0x80 != 0}
	n := int(b[1] & 0x7f)
	a.Cause, a.Negative, a.Test = Cause(b[2]&0x3f), b[2]&0x40 != 0, b[2]&0x80 != 0
	i := 3
	if p.COTSize == 2 {
		a.Orig = b[3]
		i++
	}
	a.CA = uint16(b[i])
	if p.CASize == 2 {
		a.CA |= uint16(b[i+1]) << 8
	}
	i += p.CASize
	sh, ok := shapes[a.Type]
	if !ok {
		return a, fmt.Errorf("%w %d", ErrUnsupportedType, a.Type)
	}
	if a.SQ && sh.tag != noTag && a.Type.Monitor() && n > 1 {
		return a, fmt.Errorf("%s carries a time tag per object and cannot be a sequence (SQ=1)", a.Type)
	}
	if a.Type == FSgNa1 {
		// 7.3.6.6: one segment of LOS octets.
		if n > 1 || a.SQ {
			return a, fmt.Errorf("F_SG_NA_1 carries one segment, not %d objects", n)
		}
		if n == 1 {
			o, err := decodeSegment(b[i:], p)
			if err != nil {
				return a, err
			}
			a.Objects = []Object{o}
		} else if len(b) != i {
			return a, fmt.Errorf("F_SG_NA_1 without objects has %d trailing bytes", len(b)-i)
		}
		return a, nil
	}
	el := sh.size + sh.tag
	want := n * (el + p.IOASize)
	if a.SQ && n > 0 {
		want = p.IOASize + n*el
	}
	if len(b)-i != want {
		return a, fmt.Errorf("%s with %d objects needs %d bytes of objects, got %d", a.Type, n, want, len(b)-i)
	}
	var ioa uint32
	for k := 0; k < n; k++ {
		if k == 0 || !a.SQ {
			ioa = 0
			for j := 0; j < p.IOASize; j++ {
				ioa |= uint32(b[i+j]) << (8 * j)
			}
			i += p.IOASize
		} else {
			ioa += seqStep(a.Type, p)
		}
		o := decodeElement(a.Type, b[i:i+sh.size])
		o.IOA = ioa
		if a.Type == FScNb1 {
			for k, dst := range []*time.Time{&o.Time, &o.Stop} {
				x := b[i+2+7*k : i+9+7*k]
				if !bytes.Equal(x, make([]byte, 7)) {
					tt, _ := parseCP56(x, loc, true)
					*dst = tt.Time
				}
			}
		}
		i += sh.size
		su := a.Type != CCsNa1
		switch sh.tag {
		case tagCP24:
			o.Time, o.TimeInvalid = ParseCP24(b[i:i+3], loc, now)
			o.TimeSubstituted = b[i+2]&0x40 != 0
		case tagCP56:
			var tt TimeTag
			tt, o.TimeInvalid = parseCP56(b[i:i+7], loc, su)
			o.Time, o.TimeSubstituted = tt.Time, tt.Substituted
		}
		i += sh.tag
		a.Objects = append(a.Objects, o)
	}
	return a, nil
}

func decodeSegment(b []byte, p Params) (Object, error) {
	if len(b) < p.IOASize+4 {
		return Object{}, fmt.Errorf("F_SG_NA_1 is too short (%d bytes of object)", len(b))
	}
	var o Object
	for j := 0; j < p.IOASize; j++ {
		o.IOA |= uint32(b[j]) << (8 * j)
	}
	e := b[p.IOASize:]
	o.File, o.Section = binary.LittleEndian.Uint16(e), e[2]
	los := int(e[3])
	if len(e) != 4+los {
		return Object{}, fmt.Errorf("F_SG_NA_1 announces %d octets of segment, carries %d", los, len(e)-4)
	}
	o.Length = uint32(los)
	o.Segment = append([]byte(nil), e[4:]...)
	return o, nil
}

func u24(b []byte) uint32 { return uint32(b[0]) | uint32(b[1])<<8 | uint32(b[2])<<16 }

func decodeElement(t TypeID, e []byte) Object {
	var o Object
	switch t {
	case MSpNa1, MSpTa1, MSpTb1:
		o.Value, o.Quality = float64(e[0]&1), e[0]&0xf0
	case MDpNa1, MDpTa1, MDpTb1:
		o.Value, o.Quality = float64(e[0]&3), e[0]&0xf0
	case MStNa1, MStTa1, MStTb1:
		// VTI: a 7-bit two's complement value and the transient bit.
		v := int(e[0] & 0x7f)
		if v >= 64 {
			v -= 128
		}
		o.Value, o.Transient, o.Quality = float64(v), e[0]&0x80 != 0, e[1]&0xf1
	case MBoNa1, MBoTa1, MBoTb1:
		o.Value, o.Quality = float64(binary.LittleEndian.Uint32(e)), e[4]&0xf1
	case MMeNa1, MMeTa1, MMeTd1:
		o.Value, o.Quality = float64(int16(binary.LittleEndian.Uint16(e)))/32768, e[2]&0xf1
	case MMeNd1:
		o.Value = float64(int16(binary.LittleEndian.Uint16(e))) / 32768
	case MMeNb1, MMeTb1, MMeTe1:
		o.Value, o.Quality = float64(int16(binary.LittleEndian.Uint16(e))), e[2]&0xf1
	case MMeNc1, MMeTc1, MMeTf1:
		o.Value, o.Quality = float64(math.Float32frombits(binary.LittleEndian.Uint32(e))), e[4]&0xf1
	case MItNa1, MItTa1, MItTb1:
		o.Value = float64(int32(binary.LittleEndian.Uint32(e)))
		o.Seq = e[4] & 0x1f
		if e[4]&0x20 != 0 {
			o.Quality |= QCarry
		}
		if e[4]&0x40 != 0 {
			o.Quality |= QAdjusted
		}
		if e[4]&0x80 != 0 {
			o.Quality |= QInvalid
		}
	case MPsNa1:
		o.Value, o.Change, o.Quality = float64(binary.LittleEndian.Uint16(e)), binary.LittleEndian.Uint16(e[2:]), e[4]&0xf0
	case MEpTa1, MEpTd1:
		o.Value, o.Quality = float64(e[0]&3), e[0]&0xf8
		o.Elapsed = time.Duration(binary.LittleEndian.Uint16(e[1:])) * time.Millisecond
	case MEpTb1, MEpTe1:
		o.Value, o.Quality = float64(e[0]&0x3f), e[1]&0xf8
		o.Elapsed = time.Duration(binary.LittleEndian.Uint16(e[2:])) * time.Millisecond
	case MEpTc1, MEpTf1:
		o.Value, o.Quality = float64(e[0]&0x0f), e[1]&0xf8
		o.Elapsed = time.Duration(binary.LittleEndian.Uint16(e[2:])) * time.Millisecond
	case CScNa1, CScTa1:
		o.Value, o.Select, o.Qualifier = float64(e[0]&1), e[0]&0x80 != 0, e[0]>>2&0x1f
	case CDcNa1, CDcTa1, CRcNa1, CRcTa1:
		o.Value, o.Select, o.Qualifier = float64(e[0]&3), e[0]&0x80 != 0, e[0]>>2&0x1f
	case CBoNa1, CBoTa1:
		o.Value = float64(binary.LittleEndian.Uint32(e))
	case CTsTa1, CTsNa1:
		o.Value = float64(binary.LittleEndian.Uint16(e))
	case CSeNa1, CSeTa1:
		o.Value, o.Select, o.Qualifier = float64(int16(binary.LittleEndian.Uint16(e)))/32768, e[2]&0x80 != 0, e[2]&0x7f
	case CSeNb1, CSeTb1:
		o.Value, o.Select, o.Qualifier = float64(int16(binary.LittleEndian.Uint16(e))), e[2]&0x80 != 0, e[2]&0x7f
	case CSeNc1, CSeTc1:
		o.Value, o.Select, o.Qualifier = float64(math.Float32frombits(binary.LittleEndian.Uint32(e))), e[4]&0x80 != 0, e[4]&0x7f
	case MEiNa1, CIcNa1, CCiNa1, CRpNa1:
		o.Value = float64(e[0])
	case CCdNa1:
		o.Elapsed = time.Duration(binary.LittleEndian.Uint16(e)) * time.Millisecond
	case PMeNa1:
		o.Value, o.Qualifier = float64(int16(binary.LittleEndian.Uint16(e)))/32768, e[2]
	case PMeNb1:
		o.Value, o.Qualifier = float64(int16(binary.LittleEndian.Uint16(e))), e[2]
	case PMeNc1:
		o.Value, o.Qualifier = float64(math.Float32frombits(binary.LittleEndian.Uint32(e))), e[4]
	case PAcNa1:
		o.Qualifier = e[0]
	case FFrNa1:
		o.File, o.Length, o.Qualifier = binary.LittleEndian.Uint16(e), u24(e[2:]), e[5]
	case FSrNa1:
		o.File, o.Section, o.Length, o.Qualifier = binary.LittleEndian.Uint16(e), e[2], u24(e[3:]), e[6]
	case FScNa1, FAfNa1:
		o.File, o.Section, o.Qualifier = binary.LittleEndian.Uint16(e), e[2], e[3]
	case FLsNa1:
		o.File, o.Section, o.Qualifier, o.Checksum = binary.LittleEndian.Uint16(e), e[2], e[3], e[4]
	case FDrTa1:
		o.File, o.Length, o.Status = binary.LittleEndian.Uint16(e), u24(e[2:]), e[5]
	case FScNb1:
		o.File = binary.LittleEndian.Uint16(e) // the range is read in DecodeASDUAt
	}
	return o
}

// TimeTag is a decoded CP56Time2a with its flags (IEC 60870-5-4 6.8 and
// IEC 60870-5-101 7.2.6.18).
type TimeTag struct {
	Time        time.Time
	Invalid     bool // IV
	Substituted bool // RES1 (GEN): the time tag was substituted
	Summer      bool // SU
	// OutOfRange is set when a field lies outside its range (milliseconds
	// above 59 999, minutes above 59, hours above 23, day 0, month 0 or
	// above 12); the decoded time is then marked invalid.
	OutOfRange bool
}

// CP56 encodes a time as CP56Time2a in loc (7 bytes: milliseconds within
// the minute, minute with RES1 and IV, hour with SU, day of month with day
// of week (1 Monday to 7 Sunday), month, year within the century). SU is
// set when loc observes summer time at t (Amendment 1, 7.2.6.18: a tag
// with SU set names the same instant as the tag an hour earlier with SU
// clear).
func CP56(t time.Time, invalid bool, loc *time.Location) []byte {
	return cp56(t, invalid, false, true, loc)
}

func cp56(t time.Time, invalid, substituted, su bool, loc *time.Location) []byte {
	if loc == nil {
		loc = time.UTC
	}
	t = t.In(loc)
	ms := uint16(t.Second()*1000 + t.Nanosecond()/1e6)
	b := []byte{byte(ms), byte(ms >> 8), byte(t.Minute()), byte(t.Hour()), 0, byte(t.Month()), byte(t.Year() % 100)}
	if invalid {
		b[2] |= 0x80
	}
	if substituted {
		b[2] |= 0x40
	}
	if su && t.IsDST() {
		b[3] |= 0x80
	}
	wd := int(t.Weekday())
	if wd == 0 {
		wd = 7
	}
	b[4] = byte(t.Day()) | byte(wd)<<5
	return b
}

// ParseCP56 decodes a CP56Time2a in loc. Years are taken as 2000–2099.
func ParseCP56(b []byte, loc *time.Location) (time.Time, bool) {
	tt, iv := parseCP56(b, loc, true)
	return tt.Time, iv
}

// DecodeCP56 decodes a CP56Time2a in loc with its flags.
func DecodeCP56(b []byte, loc *time.Location) TimeTag {
	tt, _ := parseCP56(b, loc, true)
	return tt
}

// parseCP56 reads the fields; with su the SU bit selects the zone's
// summer (SU=1) or standard offset for the wall time, otherwise the
// zone's own rule decides (the bit is ignored, as 7.4.6 has it for clock
// synchronisation). The second result is IV, or a field out of range.
func parseCP56(b []byte, loc *time.Location, su bool) (TimeTag, bool) {
	if loc == nil {
		loc = time.UTC
	}
	ms := int(binary.LittleEndian.Uint16(b))
	minute, hour, day, month, year := int(b[2]&0x3f), int(b[3]&0x1f), int(b[4]&0x1f), int(b[5]&0x0f), 2000+int(b[6]&0x7f)
	tt := TimeTag{Invalid: b[2]&0x80 != 0, Substituted: b[2]&0x40 != 0, Summer: b[3]&0x80 != 0}
	tt.OutOfRange = ms > 59999 || minute > 59 || hour > 23 || day == 0 || month == 0 || month > 12
	wall := time.Date(year, time.Month(month), day, hour, minute, ms/1000, (ms%1000)*1e6, loc)
	tt.Time = wall
	if su {
		_, off := wall.Zone()
		std := off
		if wall.IsDST() {
			std -= 3600
		}
		if tt.Summer {
			std += 3600
		}
		u := time.Date(year, time.Month(month), day, hour, minute, ms/1000, (ms%1000)*1e6, time.UTC)
		tt.Time = u.Add(-time.Duration(std) * time.Second).In(loc)
	}
	return tt, tt.Invalid || tt.OutOfRange
}

// CP24 encodes the milliseconds-within-the-minute and minute of a time as
// CP24Time2a (IEC 60870-5-4 binary time, 3 bytes) in loc.
func CP24(t time.Time, invalid bool, loc *time.Location) []byte {
	return CP56(t, invalid, loc)[:3]
}

// ParseCP24 decodes a CP24Time2a in loc and completes it with CompleteCP24.
func ParseCP24(b []byte, loc *time.Location, now time.Time) (time.Time, bool) {
	ms := int(binary.LittleEndian.Uint16(b))
	return CompleteCP24(ms, int(b[2]&0x3f), loc, now), b[2]&0x80 != 0 || ms > 59999 || b[2]&0x3f > 59
}

// CP16 encodes a CP16Time2a (milliseconds 0 to 59 999).
func CP16(d time.Duration) ([]byte, error) { return cp16(d) }

// CompleteCP24 gives a CP24Time2a tag (ms within the minute, minute within
// the hour) its hour and date from the receiver's clock now, in loc: of
// the three candidates in the hour before, the hour of and the hour after
// now, the one nearest to now is taken. A tag from a few minutes before the
// hour that arrives just after it therefore stays in the previous hour
// (and day), and a sender clock slightly ahead of ours does not push the
// tag an hour back. Tags older than half an hour cannot be told apart
// from newer ones; that is inherent in the 3-byte format.
func CompleteCP24(ms, minute int, loc *time.Location, now time.Time) time.Time {
	if loc == nil {
		loc = time.UTC
	}
	n := now.In(loc)
	// The start of now's hour in loc (zones with half-hour offsets, such
	// as IST, have their hour boundaries at half past the UTC hour).
	hour := time.Date(n.Year(), n.Month(), n.Day(), n.Hour(), 0, 0, 0, loc)
	within := time.Duration(minute)*time.Minute + time.Duration(ms)*time.Millisecond
	best := hour.Add(within)
	for _, h := range []time.Duration{-time.Hour, time.Hour} {
		c := hour.Add(h).Add(within)
		if absDur(c.Sub(now)) < absDur(best.Sub(now)) {
			best = c
		}
	}
	return best.In(loc)
}

func absDur(d time.Duration) time.Duration {
	if d < 0 {
		return -d
	}
	return d
}
