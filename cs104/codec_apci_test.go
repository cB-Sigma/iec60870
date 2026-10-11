package cs104

import (
	"bytes"
	"errors"
	"testing"
)

// Covers: SIG-IPE-140
func TestAPCIFrames(t *testing.T) {
	for _, tc := range []struct {
		a    APDU
		want []byte
	}{
		{APDU{Format: FormatU, U: UStartDTAct}, []byte{0x68, 4, 0x07, 0, 0, 0}},
		{APDU{Format: FormatU, U: UStartDTCon}, []byte{0x68, 4, 0x0b, 0, 0, 0}},
		{APDU{Format: FormatU, U: UStopDTAct}, []byte{0x68, 4, 0x13, 0, 0, 0}},
		{APDU{Format: FormatU, U: UStopDTCon}, []byte{0x68, 4, 0x23, 0, 0, 0}},
		{APDU{Format: FormatU, U: UTestFRAct}, []byte{0x68, 4, 0x43, 0, 0, 0}},
		{APDU{Format: FormatU, U: UTestFRCon}, []byte{0x68, 4, 0x83, 0, 0, 0}},
		{APDU{Format: FormatS, RecvSeq: 5}, []byte{0x68, 4, 0x01, 0, 0x0a, 0}},
		{APDU{Format: FormatS, RecvSeq: 300}, []byte{0x68, 4, 0x01, 0, 0x58, 0x02}},
		{APDU{Format: FormatI, SendSeq: 1, RecvSeq: 2, ASDU: []byte{0x64}}, []byte{0x68, 5, 0x02, 0, 0x04, 0, 0x64}},
		{APDU{Format: FormatI, SendSeq: 32767, RecvSeq: 128, ASDU: []byte{1, 2}}, []byte{0x68, 6, 0xfe, 0xff, 0x00, 0x01, 1, 2}},
	} {
		got, err := tc.a.Encode()
		if err != nil || !bytes.Equal(got, tc.want) {
			t.Errorf("%s encodes to % x (%v), want % x", tc.a, got, err, tc.want)
			continue
		}
		back, err := ReadAPDU(bytes.NewReader(got))
		if err != nil || back.Format != tc.a.Format || back.SendSeq != tc.a.SendSeq || back.RecvSeq != tc.a.RecvSeq ||
			back.U != tc.a.U || !bytes.Equal(back.ASDU, tc.a.ASDU) {
			t.Errorf("% x decodes to %+v (%v), want %+v", got, back, err, tc.a)
		}
	}
	for _, bad := range [][]byte{
		{0x67, 4, 0x07, 0, 0, 0},         // wrong start byte
		{0x68, 3, 0x07, 0, 0},            // length below 4
		{0x68, 4, 0x0f, 0, 0, 0},         // two U functions at once
		{0x68, 4, 0x00, 0, 0, 0},         // I-format without ASDU
		{0x68, 5, 0x01, 0, 0, 0, 9},      // S-format with data
		{0x68, 4, 0x03, 0, 0, 0},         // U-format with no function
		{0x68, 255, 0x00, 0, 0, 0, 0, 0}, // length above 253
	} {
		if _, err := ReadAPDU(bytes.NewReader(bad)); !errors.Is(err, ErrFrame) {
			t.Errorf("% x: error %v, want ErrFrame", bad, err)
		}
	}
	if _, err := (APDU{Format: FormatI, ASDU: make([]byte, 250)}).Encode(); err == nil {
		t.Error("a 250-byte ASDU was framed")
	}
	if seqDiff(32766, 1) != 3 || seqDiff(5, 5) != 0 {
		t.Error("sequence arithmetic does not wrap at 2^15")
	}
}
