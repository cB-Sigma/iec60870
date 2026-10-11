package cs101

import (
	"errors"
	"fmt"
	"io"
)

// FT1.2 transmission frames (IEC 60870-5-1 clause 6.2.4.2) and the link
// control field (IEC 60870-5-2 clause 5.1.2, profile in IEC 60870-5-101
// clause 6).

// Frame delimiters.
const (
	SingleACK  = 0xE5 // single character: positive acknowledgement / no data
	startFixed = 0x10
	startVar   = 0x68
	stopByte   = 0x16
)

// Control field bits.
const (
	CtrlDIR = 0x80 // balanced: set in frames from the controlling station (A)
	CtrlPRM = 0x40 // frame from the primary (initiating) station
	CtrlFCB = 0x20 // primary: frame count bit
	CtrlFCV = 0x10 // primary: frame count bit valid
	CtrlACD = 0x20 // secondary, unbalanced: class 1 data waiting
	CtrlDFC = 0x10 // secondary: data flow control (station busy)
)

// Function codes from a primary station.
const (
	FnResetLink       = 0
	FnResetProcess    = 1
	FnTestLink        = 2 // balanced
	FnUserDataConfirm = 3
	FnUserDataNoReply = 4
	FnRequestAccess   = 8
	FnRequestStatus   = 9
	FnRequestClass1   = 10 // unbalanced
	FnRequestClass2   = 11 // unbalanced
)

// Function codes from a secondary station.
const (
	FnAck            = 0
	FnNack           = 1
	FnUserData       = 8
	FnNoData         = 9
	FnStatus         = 11
	FnNotFunctioning = 14
	FnNotImplemented = 15
)

// Frame is one FT1.2 frame.
type Frame struct {
	Single bool   // the single character E5
	C      byte   // control field
	Addr   uint16 // link address (0 when the size is 0)
	// ASDU is the user data of a variable-length frame; nil for a
	// fixed-length frame.
	ASDU []byte
}

// PRM reports a primary (request) frame.
func (f Frame) PRM() bool { return !f.Single && f.C&CtrlPRM != 0 }

// Fn is the function code.
func (f Frame) Fn() byte { return f.C & 0x0f }

// String describes the frame for logs.
func (f Frame) String() string {
	if f.Single {
		return "E5"
	}
	return fmt.Sprintf("C=%02X A=%d fn=%d len=%d", f.C, f.Addr, f.Fn(), len(f.ASDU))
}

// Encode serialises the frame with an asize-byte link address (0, 1 or
// 2). A frame with ASDU set is variable-length, otherwise fixed.
func (f Frame) Encode(asize int) []byte {
	if f.Single {
		return []byte{SingleACK}
	}
	body := []byte{f.C}
	for i := 0; i < asize; i++ {
		body = append(body, byte(f.Addr>>(8*i)))
	}
	if f.ASDU != nil {
		body = append(body, f.ASDU...)
		n := byte(len(body))
		out := []byte{startVar, n, n, startVar}
		out = append(out, body...)
		return append(out, sum(body), stopByte)
	}
	out := append([]byte{startFixed}, body...)
	return append(out, sum(body), stopByte)
}

func sum(b []byte) byte {
	var s byte
	for _, c := range b {
		s += c
	}
	return s
}

// ErrFrame is wrapped by framing errors (bad checksum, length or stop).
var ErrFrame = errors.New("invalid FT1.2 frame")

// MaxUserData is the most bytes of control, address and ASDU in one
// variable frame (the length field is one byte).
const MaxUserData = 255

// ReadFrame reads the next frame. Bytes before a start character are
// skipped; a damaged frame returns ErrFrame (the caller may read on).
// Errors from r (timeouts, closed ports) are returned as they are.
func ReadFrame(r io.ByteReader, asize int) (Frame, error) {
	var c byte
	var err error
	for {
		if c, err = r.ReadByte(); err != nil {
			return Frame{}, err
		}
		if c == SingleACK || c == startFixed || c == startVar {
			break
		}
	}
	switch c {
	case SingleACK:
		return Frame{Single: true}, nil
	case startFixed:
		body := make([]byte, 1+asize)
		if err := readFull(r, body); err != nil {
			return Frame{}, err
		}
		tail := make([]byte, 2)
		if err := readFull(r, tail); err != nil {
			return Frame{}, err
		}
		if tail[0] != sum(body) || tail[1] != stopByte {
			return Frame{}, fmt.Errorf("%w: fixed frame checksum or end character wrong", ErrFrame)
		}
		return decodeBody(body, asize, false), nil
	}
	hdr := make([]byte, 3)
	if err := readFull(r, hdr); err != nil {
		return Frame{}, err
	}
	if hdr[0] != hdr[1] || hdr[2] != startVar {
		return Frame{}, fmt.Errorf("%w: the two length fields differ or the second start character is missing", ErrFrame)
	}
	n := int(hdr[0])
	if n < 1+asize {
		return Frame{}, fmt.Errorf("%w: length %d is shorter than control and address", ErrFrame, n)
	}
	body := make([]byte, n+2)
	if err := readFull(r, body); err != nil {
		return Frame{}, err
	}
	if body[n] != sum(body[:n]) || body[n+1] != stopByte {
		return Frame{}, fmt.Errorf("%w: variable frame checksum or end character wrong", ErrFrame)
	}
	return decodeBody(body[:n], asize, true), nil
}

func decodeBody(b []byte, asize int, variable bool) Frame {
	f := Frame{C: b[0]}
	for i := 0; i < asize; i++ {
		f.Addr |= uint16(b[1+i]) << (8 * i)
	}
	if variable {
		f.ASDU = append([]byte{}, b[1+asize:]...)
	}
	return f
}

func readFull(r io.ByteReader, b []byte) error {
	for i := range b {
		c, err := r.ReadByte()
		if err != nil {
			return err
		}
		b[i] = c
	}
	return nil
}
