package iec60870

import "fmt"

// Qualifiers and other information elements of IEC 60870-5-101 clause
// 7.2.6, with the values the standard assigns. Values not listed are
// reserved (compatible range) or private.

// QOI, qualifier of interrogation (7.2.6.22): 20 is the station
// (global) interrogation, 21 to 36 groups 1 to 16.
const QOIStation = 20

// QOIGroup is the qualifier of interrogation of group g (1 to 16).
func QOIGroup(g int) uint8 { return uint8(20 + g) }

// InterrogationGroup is the group (1 to 16) a QOI or cause of
// transmission 21 to 36 names; 0 for the station interrogation (20).
func InterrogationGroup(q uint8) int {
	if q >= 21 && q <= 36 {
		return int(q) - 20
	}
	return 0
}

// QCC, qualifier of counter interrogation (7.2.6.23): RQT in bits 1 to 6
// names the counters, FRZ in bits 7 and 8 the operation.
const (
	RQTGeneral = 5 // general request counter; 1 to 4 are groups 1 to 4

	FRZRead        = 0 // read (no freeze or reset)
	FRZFreeze      = 1 // counter freeze without reset (integrated total)
	FRZFreezeReset = 2 // counter freeze with reset (incremental information)
	FRZReset       = 3 // counter reset
)

// QCC composes a qualifier of counter interrogation.
func QCC(rqt, frz uint8) uint8 { return rqt&0x3f | frz&3<<6 }

// SplitQCC returns RQT and FRZ of a qualifier of counter interrogation.
func SplitQCC(q uint8) (rqt, frz uint8) { return q & 0x3f, q >> 6 }

// FRZ names.
var frzNames = map[string]uint8{"read": FRZRead, "freeze": FRZFreeze, "freeze-reset": FRZFreezeReset, "reset": FRZReset}

// ParseFRZ reads a counter operation name: read, freeze, freeze-reset or
// reset ("" is read).
func ParseFRZ(s string) (uint8, error) {
	if s == "" {
		return FRZRead, nil
	}
	f, ok := frzNames[s]
	if !ok {
		return 0, fmt.Errorf("counter operation %q is not read, freeze, freeze-reset or reset", s)
	}
	return f, nil
}

// QU, the qualifier of a command's pulse (QOC bits 3 to 7, 7.2.6.26).
const (
	QUNone       = 0 // no additional definition (the controlled station decides)
	QUShortPulse = 1 // short pulse, duration a controlled-station parameter
	QULongPulse  = 2 // long pulse, duration a controlled-station parameter
	QUPersistent = 3 // persistent output
)

var quNames = map[string]uint8{"none": QUNone, "short": QUShortPulse, "long": QULongPulse, "persistent": QUPersistent}

// ParseQU reads a pulse qualifier name (none, short, long, persistent).
func ParseQU(s string) (uint8, bool) { q, ok := quNames[s]; return q, ok }

// QPM, qualifier of parameter of measured values (7.2.6.24): KPA in
// bits 1 to 6; LPC (bit 7) and POP (bit 8) are not used by IEC
// 60870-5-101 and are sent as 0.
const (
	KPAThreshold = 1 // threshold value
	KPASmoothing = 2 // smoothing factor (filter time constant)
	KPALowLimit  = 3 // low limit for transmission of measured values
	KPAHighLimit = 4 // high limit for transmission of measured values
)

var kpaNames = map[string]uint8{"threshold": KPAThreshold, "smoothing": KPASmoothing, "low-limit": KPALowLimit, "high-limit": KPAHighLimit}

// ParseKPA reads a parameter kind (threshold, smoothing, low-limit,
// high-limit).
func ParseKPA(s string) (uint8, error) {
	k, ok := kpaNames[s]
	if !ok {
		return 0, fmt.Errorf("parameter kind %q is not threshold, smoothing, low-limit or high-limit", s)
	}
	return k, nil
}

// KPAName is the name of a parameter kind, or "kind n".
func KPAName(k uint8) string {
	for n, v := range kpaNames {
		if v == k&0x3f {
			return n
		}
	}
	return fmt.Sprintf("kind %d", k&0x3f)
}

// QPA, qualifier of parameter activation (7.2.6.25). IEC 60870-5-101
// 7.4.9 uses only 3: act/deact of persistent cyclic or periodic
// transmission of the addressed object (1 and 2 are not used).
const QPACyclic = 3

// QRP, qualifier of reset process command (7.2.6.27).
const (
	QRPGeneral = 1 // general reset of process
	QRPEvents  = 2 // reset of pending information with time tag of the event buffer
)

// COI, cause of initialisation (7.2.6.21): bits 1 to 7 the cause, bit 8
// set after a change of local parameters.
const (
	COILocalPower = 0 // local power switch on
	COILocalReset = 1 // local manual reset
	COIRemote     = 2 // remote reset
	COIChanged    = 0x80
)

// COIString describes a cause of initialisation.
func COIString(c uint8) string {
	s := ""
	switch c & 0x7f {
	case COILocalPower:
		s = "local power switch on"
	case COILocalReset:
		s = "local manual reset"
	case COIRemote:
		s = "remote reset"
	default:
		if c&0x7f >= 32 {
			s = fmt.Sprintf("private cause %d", c&0x7f)
		} else {
			s = fmt.Sprintf("reserved cause %d", c&0x7f)
		}
	}
	if c&COIChanged != 0 {
		s += ", after a change of local parameters"
	}
	return s
}

// FBP, the fixed test bit pattern of C_TS_NA_1 (7.2.6.14).
const FBP = 0x55AA

// File transfer qualifiers (7.2.6.28 to 7.2.6.39).
const (
	// SCQ, select and call qualifier: bits 1 to 4.
	SCQDefault           = 0 // default (call directory)
	SCQSelectFile        = 1
	SCQRequestFile       = 2
	SCQDeactivateFile    = 3
	SCQDeleteFile        = 4
	SCQSelectSection     = 5
	SCQRequestSection    = 6
	SCQDeactivateSection = 7

	// LSQ, last section or segment qualifier.
	LSQFile            = 1 // file transfer without deactivation
	LSQFileDeact       = 2 // file transfer with deactivation
	LSQSection         = 3 // section transfer without deactivation
	LSQSectionDeact    = 4 // section transfer with deactivation
	AFQFileOK          = 1 // positive acknowledge of file transfer
	AFQFileNegative    = 2
	AFQSectionOK       = 3
	AFQSectionNegative = 4

	// Error bits 5 to 8 of SCQ and AFQ.
	FileErrMemory   = 1 // requested memory space not available
	FileErrChecksum = 2 // checksum failed
	FileErrService  = 3 // unexpected communication service
	FileErrName     = 4 // unexpected name of file
	FileErrSection  = 5 // unexpected name of section

	// FRQ and SRQ bit 8: negative confirmation (FRQ) or section not
	// ready (SRQ).
	FRQNegative = 0x80
	SRQNotReady = 0x80

	// SOF, status of file: STATUS in bits 1 to 5, LFD bit 6 (last file of
	// the directory), FOR bit 7 (name defines a subdirectory), FA bit 8
	// (transfer of this file is active).
	SOFLastFile     = 0x20
	SOFSubdirectory = 0x40
	SOFActive       = 0x80
)

// Name of file values (7.4.11.1.1, Amendment 1: 0 is the default).
const (
	FileTransparent = 1
	FileDisturbance = 2
	FileEvents      = 3 // sequences of events
	FileAnalogue    = 4 // sequences of recorded analogue values
)

// FileError describes the error nibble of an SCQ or AFQ.
func FileError(q uint8) string {
	switch q >> 4 {
	case 0:
		return ""
	case FileErrMemory:
		return "requested memory space not available"
	case FileErrChecksum:
		return "checksum failed"
	case FileErrService:
		return "unexpected communication service"
	case FileErrName:
		return "unexpected name of file"
	case FileErrSection:
		return "unexpected name of section"
	}
	return fmt.Sprintf("error %d", q>>4)
}

// Checksum is CHS (7.2.6.37): the arithmetic sum modulo 256 of the octets.
func Checksum(b []byte) uint8 {
	var s uint8
	for _, c := range b {
		s += c
	}
	return s
}

// SPE bits (7.2.6.11): start events of protection equipment.
const (
	SPEGeneral = 0x01 // GS
	SPEL1      = 0x02 // SL1
	SPEL2      = 0x04
	SPEL3      = 0x08
	SPEEarth   = 0x10 // SIE, earth current
	SPEReverse = 0x20 // SRD, reverse direction
)

// OCI bits (7.2.6.12): output circuit information of protection equipment.
const (
	OCIGeneral = 0x01 // GC
	OCIL1      = 0x02 // CL1
	OCIL2      = 0x04
	OCIL3      = 0x08
)
