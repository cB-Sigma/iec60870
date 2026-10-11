package sec

import "fmt"

// Type identifiers added by TS 60870-5-7 5.4.2.2 Table 2.
const (
	SAQNA1 uint8 = 81 // association request
	SAPNA1 uint8 = 82 // association response
	SUHNA1 uint8 = 83 // update key change request
	SUPNA1 uint8 = 84 // update key change response
	SSINA1 uint8 = 85 // session initiation request
	SSQNA1 uint8 = 86 // session request
	SSPNA1 uint8 = 87 // session response
	SKHNA1 uint8 = 88 // session key change request
	SKPNA1 uint8 = 89 // session key change response
	SSDNA1 uint8 = 91 // secure data
)

// Causes of transmission added by TS 60870-5-7 5.4.2.1 Table 1.
const (
	CauseDataProtection  uint8  = 14 // application data authentication / protection
	CauseSessionKey      uint8  = 15 // maintenance of session key
	CauseAssociation     uint8  = 16 // maintenance of association and update key
	CauseNotAuthorized   uint8  = 17 // operation not authorized (controlled station only)
	TypeIntegratedTotals uint8  = 37 // integrated totals with CP56Time2a, carries statistics (5.4.2.3)
	defaultBroadcastCA1  uint16 = 0xFF
	defaultBroadcastCA2  uint16 = 0xFFFF
)

// Direction is the direction of an ASDU.
type Direction int

const (
	// Control is the control direction (controlling to controlled station).
	Control Direction = iota
	// Monitor is the monitor direction (controlled to controlling station).
	Monitor
)

// String names the direction.
func (d Direction) String() string {
	if d == Control {
		return "control"
	}
	return "monitor"
}

// typeInfo holds the name and permitted cause per direction (0 = not
// permitted) of each security type, from the CAUSES OF TRANSMISSION lists
// of 5.4.3.3 to 5.4.3.13.
type typeInfo struct {
	name    string
	control uint8
	monitor uint8
	mac     bool // MAC protected per 5.4.3.2 (91 is MAC or AEAD)
}

var types = map[uint8]typeInfo{
	SAQNA1: {"S_AQ_NA_1", CauseAssociation, 0, false},
	SAPNA1: {"S_AP_NA_1", 0, CauseAssociation, false},
	SUHNA1: {"S_UH_NA_1", CauseAssociation, 0, true},
	SUPNA1: {"S_UP_NA_1", 0, CauseAssociation, true},
	SSINA1: {"S_SI_NA_1", 0, CauseSessionKey, true},
	SSQNA1: {"S_SQ_NA_1", CauseSessionKey, 0, false},
	SSPNA1: {"S_SP_NA_1", 0, CauseSessionKey, true},
	SKHNA1: {"S_KH_NA_1", CauseSessionKey, 0, true},
	SKPNA1: {"S_KP_NA_1", 0, CauseSessionKey, true},
	SSDNA1: {"S_SD_NA_1", CauseDataProtection, CauseDataProtection, false},
}

// IsSecurityType reports whether t is one of the TS 60870-5-7 type identifiers.
func IsSecurityType(t uint8) bool { _, ok := types[t]; return ok }

// TypeName returns the mnemonic of a security type, or "" for others.
func TypeName(t uint8) string { return types[t].name }

// PermittedCause returns the cause of transmission the TS permits for type t
// in direction d, and false when the type is not permitted in that direction.
func PermittedCause(t uint8, d Direction) (uint8, bool) {
	ti, ok := types[t]
	if !ok {
		return 0, false
	}
	c := ti.control
	if d == Monitor {
		c = ti.monitor
	}
	return c, c != 0
}

// MACProtected reports whether type t always carries a MAC (5.4.3.2).
func MACProtected(t uint8) bool { return types[t].mac }

// ProtocolInfo is the PRI field of S_AQ_NA_1 (Figure 7) and S_SQ_NA_1
// (Figure 13): the version octet (major in bits 5 to 8, minor in bits 1 to 4)
// and a second octet, reserved (0) in the association request and carrying
// the BK flag in bit 1 of the session request.
type ProtocolInfo struct {
	Major, Minor uint8
	Broadcast    bool // BK, session request only (IEC 101 only)
	Reserved     uint8
}

// ConformingPRI is the protocol version devices claiming conformance use
// (5.4.3.4.2/3, 5.4.3.9.2.2/3): major 1, minor 0.
var ConformingPRI = ProtocolInfo{Major: 1, Minor: 0}

func (p ProtocolInfo) encode(session bool) ([2]byte, error) {
	if p.Major > 15 || p.Minor > 15 {
		return [2]byte{}, fmt.Errorf("iec60870sec: protocol version %d.%d out of range", p.Major, p.Minor)
	}
	b := [2]byte{p.Major<<4 | p.Minor, p.Reserved}
	if session {
		b[1] &^= 1
		if p.Broadcast {
			b[1] |= 1
		}
	}
	return b, nil
}

func decodePRI(b []byte, session bool) ProtocolInfo {
	p := ProtocolInfo{Major: b[0] >> 4, Minor: b[0] & 0x0F, Reserved: b[1]}
	if session {
		p.Broadcast = b[1]&1 != 0
		p.Reserved = b[1] &^ 1
	}
	return p
}
