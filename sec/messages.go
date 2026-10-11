package sec

import (
	"encoding/binary"
	"fmt"
)

// Field widths follow the message tables of IEC 62351-5:2023 (Tables 9 to
// 29) with the ASDU framing of TS 60870-5-7 Figures 6 to 20; multi-octet
// integers are least significant octet first (IEC 62351-5:2023 8.2.1). Every
// random data length (CGL) is one octet (UI8), as the standard defines it
// (F-414). Messages are held as their information object after
// the DUI, without the ASC octet (the form protected by the MAC, 5.4.2.5).

// Message is a decoded security ASDU information object.
type Message interface {
	// TypeID is the type identification of the message.
	TypeID() uint8
	// encode appends the information object; it must not include the MAC
	// when withMAC is false.
	encode(withMAC bool) ([]byte, error)
}

// AssociationRequest is S_AQ_NA_1 (Figure 6).
type AssociationRequest struct {
	AIM, AIS uint16
	PRI      ProtocolInfo
	CertData []byte // CDC, length CDL (2 octets)
}

// AssociationResponse is S_AP_NA_1 (Figure 8).
type AssociationResponse struct {
	AIM, AIS uint16
	CertData []byte // CDC, length CDL (2 octets)
	Random   []byte // CGD, 4 to 64 octets, length CGL (1 octet)
}

// UpdateKeyChangeRequest is S_UH_NA_1 (Figure 9).
type UpdateKeyChangeRequest struct {
	AIM, AIS uint16
	KWA, MAL uint8  // enumerations of IEC 62351-5 8.3.5.4.4/5 (F-411)
	Random   []byte // CGD, length CGL (1 octet)
	MAC      []byte
}

// UpdateKeyChangeResponse is S_UP_NA_1 (Figure 10).
type UpdateKeyChangeResponse struct {
	AIM, AIS uint16
	MAC      []byte
}

// SessionInitiationRequest is S_SI_NA_1 (Figure 11, 5.4.3.8).
type SessionInitiationRequest struct {
	AIM, AIS uint16
	Random   []byte // CGD, 4 to 64 octets, length CGL (1 octet, F-414)
	MAC      []byte
}

// SessionRequest is S_SQ_NA_1 (Figure 12).
type SessionRequest struct {
	AIM, AIS uint16
	PRI      ProtocolInfo
	Random   []byte // CGD, length CGL (1 octet)
}

// SessionResponse is S_SP_NA_1 (Figure 14, IEC 62351-5 Table 19).
type SessionResponse struct {
	AIM, AIS uint16
	Random   []byte // CGD, 4 to 64 octets, length CGL (1 octet)
	MAC      []byte
}

// SessionKeyChangeRequest is S_KH_NA_1 (Figure 15).
type SessionKeyChangeRequest struct {
	AIM, AIS uint16
	DPA      uint8  // enumeration of IEC 62351-5 8.4.2.4.4 (F-411)
	Wrapped  []byte // WKD, length WKL (2 octets)
	MAC      []byte
}

// SessionKeyChangeResponse is S_KP_NA_1 (Figure 18).
type SessionKeyChangeResponse struct {
	AIM, AIS uint16
	MAC      []byte
}

// SecureData is S_SD_NA_1 (Figure 20). Rest is everything after DSQ: with a
// MAC algorithm ADL (2 octets), the protected ASDU and the MAC (IEC 62351-5
// Table 30); with AEAD the payload the algorithm output, the ciphertext of
// ADL and the ASDU followed by the tag (Table 32, TS Figure 19).
type SecureData struct {
	AIM, AIS uint16
	DSQ      uint32
	Rest     []byte
}

// TypeID is the type identification SAQNA1.
func (AssociationRequest) TypeID() uint8 { return SAQNA1 }

// TypeID is the type identification SAPNA1.
func (AssociationResponse) TypeID() uint8 { return SAPNA1 }

// TypeID is the type identification SUHNA1.
func (UpdateKeyChangeRequest) TypeID() uint8 { return SUHNA1 }

// TypeID is the type identification SUPNA1.
func (UpdateKeyChangeResponse) TypeID() uint8 { return SUPNA1 }

// TypeID is the type identification SSINA1.
func (SessionInitiationRequest) TypeID() uint8 { return SSINA1 }

// TypeID is the type identification SSQNA1.
func (SessionRequest) TypeID() uint8 { return SSQNA1 }

// TypeID is the type identification SSPNA1.
func (SessionResponse) TypeID() uint8 { return SSPNA1 }

// TypeID is the type identification SKHNA1.
func (SessionKeyChangeRequest) TypeID() uint8 { return SKHNA1 }

// TypeID is the type identification SKPNA1.
func (SessionKeyChangeResponse) TypeID() uint8 { return SKPNA1 }

// TypeID is the type identification SSDNA1.
func (SecureData) TypeID() uint8 { return SSDNA1 }

func ids(aim, ais uint16) []byte {
	return binary.LittleEndian.AppendUint16(binary.LittleEndian.AppendUint16(nil, aim), ais)
}

func lenPrefixed(b []byte, v []byte, size int, max int, name string) ([]byte, error) {
	if len(v) > max {
		return nil, fmt.Errorf("iec60870sec: %s of %d octets exceeds %d", name, len(v), max)
	}
	if size == 1 {
		b = append(b, byte(len(v)))
	} else {
		b = binary.LittleEndian.AppendUint16(b, uint16(len(v)))
	}
	return b, nil
}

func (m AssociationRequest) encode(bool) ([]byte, error) {
	b := ids(m.AIM, m.AIS)
	pri, err := m.PRI.encode(false)
	if err != nil {
		return nil, err
	}
	b = append(b, pri[:]...)
	if b, err = lenPrefixed(b, m.CertData, 2, 0xFFFF, "certificate data"); err != nil {
		return nil, err
	}
	return append(b, m.CertData...), nil
}

func (m AssociationResponse) encode(bool) ([]byte, error) {
	b := ids(m.AIM, m.AIS)
	var err error
	if b, err = lenPrefixed(b, m.CertData, 2, 0xFFFF, "certificate data"); err != nil {
		return nil, err
	}
	if b, err = lenPrefixed(b, m.Random, 1, 0xFF, "random data"); err != nil {
		return nil, err
	}
	return append(append(b, m.CertData...), m.Random...), nil
}

func withMAC(b, mac []byte, on bool) []byte {
	if on {
		return append(b, mac...)
	}
	return b
}

func (m UpdateKeyChangeRequest) encode(mac bool) ([]byte, error) {
	b := append(ids(m.AIM, m.AIS), m.KWA, m.MAL)
	b, err := lenPrefixed(b, m.Random, 1, 0xFF, "random data")
	if err != nil {
		return nil, err
	}
	return withMAC(append(b, m.Random...), m.MAC, mac), nil
}

func (m UpdateKeyChangeResponse) encode(mac bool) ([]byte, error) {
	return withMAC(ids(m.AIM, m.AIS), m.MAC, mac), nil
}

func (m SessionInitiationRequest) encode(mac bool) ([]byte, error) {
	if m.AIM == 0 || m.AIS == 0 {
		return nil, fmt.Errorf("iec60870sec: session initiation request association IDs must be 1 to 65535")
	}
	if len(m.Random) < 4 || len(m.Random) > 64 {
		return nil, fmt.Errorf("iec60870sec: session initiation request random data of %d octets, want 4 to 64", len(m.Random))
	}
	b, _ := lenPrefixed(ids(m.AIM, m.AIS), m.Random, 1, 64, "random data")
	return withMAC(append(b, m.Random...), m.MAC, mac), nil
}

func (m SessionRequest) encode(bool) ([]byte, error) {
	b := ids(m.AIM, m.AIS)
	pri, err := m.PRI.encode(true)
	if err != nil {
		return nil, err
	}
	b = append(b, pri[:]...)
	if b, err = lenPrefixed(b, m.Random, 1, 0xFF, "random data"); err != nil {
		return nil, err
	}
	return append(b, m.Random...), nil
}

func (m SessionResponse) encode(mac bool) ([]byte, error) {
	b, err := lenPrefixed(ids(m.AIM, m.AIS), m.Random, 1, 0xFF, "random data")
	if err != nil {
		return nil, err
	}
	return withMAC(append(b, m.Random...), m.MAC, mac), nil
}

func (m SessionKeyChangeRequest) encode(mac bool) ([]byte, error) {
	b, err := lenPrefixed(append(ids(m.AIM, m.AIS), m.DPA), m.Wrapped, 2, 0xFFFF, "wrapped key data")
	if err != nil {
		return nil, err
	}
	return withMAC(append(b, m.Wrapped...), m.MAC, mac), nil
}

func (m SessionKeyChangeResponse) encode(mac bool) ([]byte, error) {
	return withMAC(ids(m.AIM, m.AIS), m.MAC, mac), nil
}

func (m SecureData) encode(bool) ([]byte, error) {
	b := binary.LittleEndian.AppendUint32(ids(m.AIM, m.AIS), m.DSQ)
	return append(b, m.Rest...), nil
}

// Encode returns the whole ASDU (DUI and information object, no ASC) with
// the DUI's type set from the message and VSQ 1 (single object, SQ=0).
func Encode(d DUI, p Params, m Message) ([]byte, error) {
	return encodeASDU(d, p, m, true)
}

// MACInput returns the ASDU without its trailing MAC: the "entire message"
// of 5.4.3.2, which starts with the DUI and leaves out the ASC.
func MACInput(d DUI, p Params, m Message) ([]byte, error) {
	return encodeASDU(d, p, m, false)
}

func encodeASDU(d DUI, p Params, m Message, mac bool) ([]byte, error) {
	if err := p.validate(); err != nil {
		return nil, err
	}
	d.Type, d.VSQ = m.TypeID(), 1
	body, err := m.encode(mac)
	if err != nil {
		return nil, err
	}
	return append(d.Encode(p), body...), nil
}

type reader struct {
	b   []byte
	err error
}

func (r *reader) take(n int) []byte {
	if r.err != nil || n > len(r.b) {
		r.err = errShort
		return nil
	}
	v := r.b[:n:n]
	r.b = r.b[n:]
	return v
}

func (r *reader) u8() uint8 {
	if v := r.take(1); v != nil {
		return v[0]
	}
	return 0
}

func (r *reader) u16() uint16 {
	if v := r.take(2); v != nil {
		return binary.LittleEndian.Uint16(v)
	}
	return 0
}

func (r *reader) u32() uint32 {
	if v := r.take(4); v != nil {
		return binary.LittleEndian.Uint32(v)
	}
	return 0
}

func (r *reader) rest() []byte { v := r.b; r.b = nil; return v }

// Decode parses a whole security ASDU (DUI and information object, as
// returned by the Reassembler). It checks VSQ 1 and the cause permitted for
// the type in direction dir (the direction the ASDU travels).
func Decode(asdu []byte, p Params, dir Direction) (DUI, Message, error) {
	if err := p.validate(); err != nil {
		return DUI{}, nil, err
	}
	d, err := ParseDUI(asdu, p)
	if err != nil {
		return d, nil, err
	}
	if !IsSecurityType(d.Type) {
		return d, nil, fmt.Errorf("iec60870sec: type %d is not a security type", d.Type)
	}
	if d.VSQ != 1 {
		return d, nil, fmt.Errorf("iec60870sec: %s with VSQ %#02x, want 0x01", TypeName(d.Type), d.VSQ)
	}
	if c, ok := PermittedCause(d.Type, dir); !ok || c != d.Cause {
		return d, nil, fmt.Errorf("iec60870sec: %s with cause %d not permitted in %s direction", TypeName(d.Type), d.Cause, dir)
	}
	r := &reader{b: asdu[p.DUILen():]}
	var m Message
	switch d.Type {
	case SAQNA1:
		v := AssociationRequest{AIM: r.u16(), AIS: r.u16()}
		if pri := r.take(2); pri != nil {
			v.PRI = decodePRI(pri, false)
		}
		v.CertData = r.take(int(r.u16()))
		m = v
	case SAPNA1:
		v := AssociationResponse{AIM: r.u16(), AIS: r.u16()}
		cdl, cgl := int(r.u16()), int(r.u8())
		v.CertData, v.Random = r.take(cdl), r.take(cgl)
		m = v
	case SUHNA1:
		v := UpdateKeyChangeRequest{AIM: r.u16(), AIS: r.u16(), KWA: r.u8(), MAL: r.u8()}
		v.Random = r.take(int(r.u8()))
		v.MAC = r.rest()
		m = v
	case SUPNA1:
		m = UpdateKeyChangeResponse{AIM: r.u16(), AIS: r.u16(), MAC: r.rest()}
	case SSINA1:
		v := SessionInitiationRequest{AIM: r.u16(), AIS: r.u16()}
		cgl := int(r.u8())
		if r.err == nil && (cgl < 4 || cgl > 64) {
			return d, nil, fmt.Errorf("iec60870sec: S_SI_NA_1 random data length %d, want 4 to 64", cgl)
		}
		v.Random = r.take(cgl)
		v.MAC = r.rest()
		if r.err == nil && (v.AIM == 0 || v.AIS == 0) {
			return d, nil, fmt.Errorf("iec60870sec: S_SI_NA_1 association ID 0")
		}
		m = v
	case SSQNA1:
		v := SessionRequest{AIM: r.u16(), AIS: r.u16()}
		if pri := r.take(2); pri != nil {
			v.PRI = decodePRI(pri, true)
		}
		v.Random = r.take(int(r.u8()))
		m = v
	case SSPNA1:
		v := SessionResponse{AIM: r.u16(), AIS: r.u16()}
		v.Random = r.take(int(r.u8()))
		v.MAC = r.rest()
		m = v
	case SKHNA1:
		v := SessionKeyChangeRequest{AIM: r.u16(), AIS: r.u16(), DPA: r.u8()}
		v.Wrapped = r.take(int(r.u16()))
		v.MAC = r.rest()
		m = v
	case SKPNA1:
		m = SessionKeyChangeResponse{AIM: r.u16(), AIS: r.u16(), MAC: r.rest()}
	case SSDNA1:
		m = SecureData{AIM: r.u16(), AIS: r.u16(), DSQ: r.u32(), Rest: r.rest()}
	}
	if r.err != nil {
		return d, nil, fmt.Errorf("iec60870sec: %s: %w", TypeName(d.Type), r.err)
	}
	if len(r.b) != 0 {
		return d, nil, fmt.Errorf("iec60870sec: %s has %d trailing octets", TypeName(d.Type), len(r.b))
	}
	return d, m, nil
}
