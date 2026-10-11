package cs104

import (
	"errors"
	"fmt"
	"io"

	"github.com/cB-Sigma/iec60870"
)

// APCI framing (IEC 60870-5-104 clause 5): a start byte, the length of
// what follows, four control octets, then the ASDU for I-format frames.
const (
	startByte = 0x68
	// MaxASDU is the largest ASDU an APDU carries (253 − 4 control octets).
	MaxASDU = iec60870.MaxASDU
	// seqMod is the modulus of the 15-bit send and receive sequence numbers.
	seqMod = 1 << 15
)

// Format is an APDU's control field format.
type Format uint8

// Formats.
const (
	FormatI Format = iota // numbered information transfer
	FormatS               // numbered supervisory (acknowledgement)
	FormatU               // unnumbered control
)

// U-format functions (one bit each in the first control octet).
const (
	UStartDTAct uint8 = 0x04
	UStartDTCon uint8 = 0x08
	UStopDTAct  uint8 = 0x10
	UStopDTCon  uint8 = 0x20
	UTestFRAct  uint8 = 0x40
	UTestFRCon  uint8 = 0x80
)

// APDU is one frame.
type APDU struct {
	Format Format
	SendSeq,
	RecvSeq uint16 // N(S) (I only) and N(R) (I and S)
	U    uint8  // U-format function bit
	ASDU []byte // I only
}

// String describes the APDU for logs.
func (a APDU) String() string {
	switch a.Format {
	case FormatI:
		return fmt.Sprintf("I(%d,%d) %d bytes", a.SendSeq, a.RecvSeq, len(a.ASDU))
	case FormatS:
		return fmt.Sprintf("S(%d)", a.RecvSeq)
	}
	names := map[uint8]string{UStartDTAct: "STARTDT act", UStartDTCon: "STARTDT con", UStopDTAct: "STOPDT act",
		UStopDTCon: "STOPDT con", UTestFRAct: "TESTFR act", UTestFRCon: "TESTFR con"}
	return "U " + names[a.U]
}

// Encode serialises the frame.
func (a APDU) Encode() ([]byte, error) {
	switch a.Format {
	case FormatI:
		if len(a.ASDU) == 0 || len(a.ASDU) > MaxASDU {
			return nil, fmt.Errorf("an I-format frame carries 1 to %d ASDU bytes, not %d", MaxASDU, len(a.ASDU))
		}
		b := make([]byte, 6, 6+len(a.ASDU))
		b[0], b[1] = startByte, byte(4+len(a.ASDU))
		b[2], b[3] = byte(a.SendSeq<<1), byte(a.SendSeq>>7)
		b[4], b[5] = byte(a.RecvSeq<<1), byte(a.RecvSeq>>7)
		return append(b, a.ASDU...), nil
	case FormatS:
		return []byte{startByte, 4, 0x01, 0, byte(a.RecvSeq << 1), byte(a.RecvSeq >> 7)}, nil
	case FormatU:
		switch a.U {
		case UStartDTAct, UStartDTCon, UStopDTAct, UStopDTCon, UTestFRAct, UTestFRCon:
			return []byte{startByte, 4, 0x03 | a.U, 0, 0, 0}, nil
		}
		return nil, fmt.Errorf("U-format function %#x is not one function bit", a.U)
	}
	return nil, errors.New("unknown frame format")
}

// ErrFrame is wrapped by framing errors: the connection cannot continue.
var ErrFrame = errors.New("malformed APDU")

// ReadAPDU reads one frame.
func ReadAPDU(r io.Reader) (APDU, error) {
	var h [2]byte
	if _, err := io.ReadFull(r, h[:]); err != nil {
		return APDU{}, err
	}
	if h[0] != startByte {
		return APDU{}, fmt.Errorf("%w: start byte %#02x", ErrFrame, h[0])
	}
	n := int(h[1])
	if n < 4 || n > 253 {
		return APDU{}, fmt.Errorf("%w: length %d", ErrFrame, n)
	}
	b := make([]byte, n)
	if _, err := io.ReadFull(r, b); err != nil {
		return APDU{}, err
	}
	return ParseAPDU(b)
}

// ParseAPDU parses the control octets and ASDU of a frame (without the
// start and length bytes).
func ParseAPDU(b []byte) (APDU, error) {
	if len(b) < 4 {
		return APDU{}, fmt.Errorf("%w: %d control octets", ErrFrame, len(b))
	}
	// Figures 6 to 8 fix the bits that are not sequence numbers or
	// function bits: bit 1 of octet 3 is 0 in every format, octet 2 of an
	// S-format frame is 0, and octets 2 to 4 of a U-format frame are 0.
	switch {
	case b[0]&0x01 == 0:
		if len(b) == 4 {
			return APDU{}, fmt.Errorf("%w: I-format frame without an ASDU", ErrFrame)
		}
		if b[2]&0x01 != 0 {
			return APDU{}, fmt.Errorf("%w: I-format control octet 3 %#02x has bit 1 set", ErrFrame, b[2])
		}
		return APDU{Format: FormatI, SendSeq: uint16(b[0])>>1 | uint16(b[1])<<7,
			RecvSeq: uint16(b[2])>>1 | uint16(b[3])<<7, ASDU: append([]byte(nil), b[4:]...)}, nil
	case b[0]&0x03 == 0x01:
		if len(b) != 4 {
			return APDU{}, fmt.Errorf("%w: S-format frame with data", ErrFrame)
		}
		if b[0] != 0x01 || b[1] != 0 || b[2]&0x01 != 0 {
			return APDU{}, fmt.Errorf("%w: S-format control % x has reserved bits set", ErrFrame, b[:4])
		}
		return APDU{Format: FormatS, RecvSeq: uint16(b[2])>>1 | uint16(b[3])<<7}, nil
	default:
		f := b[0] &^ 0x03
		if len(b) != 4 || f == 0 || f&(f-1) != 0 {
			return APDU{}, fmt.Errorf("%w: U-format control %#02x", ErrFrame, b[0])
		}
		if b[1] != 0 || b[2] != 0 || b[3] != 0 {
			return APDU{}, fmt.Errorf("%w: U-format control octets 2 to 4 (% x) are not zero", ErrFrame, b[1:4])
		}
		return APDU{Format: FormatU, U: f}, nil
	}
}

// seqDiff is how far b is ahead of a, modulo 2^15 (clause 5.1: both
// sequence numbers count modulo 32768).
func seqDiff(a, b uint16) int { return int((b - a + seqMod) % seqMod) }
