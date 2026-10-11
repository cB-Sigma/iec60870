package cs101

import (
	"bufio"
	"bytes"
	"encoding/hex"
	"errors"
	"testing"
)

func hx(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// Covers: SIG-IPE-300
func TestFT12Frames(t *testing.T) {
	// Hand-built frames following the FT1.2 rules (checksum is the byte sum
	// of control, address and user data).
	vectors := []struct {
		name  string
		f     Frame
		asize int
		wire  string
	}{
		{"request status of link, address 1", Frame{C: CtrlPRM | FnRequestStatus, Addr: 1}, 1, "1049014a16"},
		{"reset of remote link, address 1", Frame{C: CtrlPRM | FnResetLink, Addr: 1}, 1, "1040014116"},
		{"class 2 request, FCB 1", Frame{C: CtrlPRM | CtrlFCB | CtrlFCV | FnRequestClass2, Addr: 1}, 1, "107b017c16"},
		{"class 2 request, FCB 0", Frame{C: CtrlPRM | CtrlFCV | FnRequestClass2, Addr: 1}, 1, "105b015c16"},
		{"status of link answer", Frame{C: FnStatus, Addr: 1}, 1, "100b010c16"},
		{"single character", Frame{Single: true}, 1, "e5"},
		{"general interrogation in user data", Frame{C: CtrlPRM | CtrlFCB | CtrlFCV | FnUserDataConfirm, Addr: 1,
			ASDU: []byte{0x64, 0x01, 0x06, 0x01, 0x00, 0x00, 0x14}}, 1, "680909687301640106010000" + "14f416"},
		{"two-byte link address", Frame{C: CtrlPRM | FnRequestStatus, Addr: 0x0102}, 2, "104902014c16"},
		{"no link address (balanced), DIR set", Frame{C: CtrlDIR | CtrlPRM | FnTestLink | CtrlFCV}, 0, "10d2d216"},
	}
	for _, v := range vectors {
		got := v.f.Encode(v.asize)
		if hex.EncodeToString(got) != v.wire {
			t.Errorf("%s: encoded %x, want %s", v.name, got, v.wire)
		}
		back, err := ReadFrame(bytes.NewReader(hx(t, v.wire)), v.asize)
		if err != nil {
			t.Fatalf("%s: %v", v.name, err)
		}
		if back.Single != v.f.Single || back.C != v.f.C || back.Addr != v.f.Addr || !bytes.Equal(back.ASDU, v.f.ASDU) {
			t.Errorf("%s: decoded %+v, want %+v", v.name, back, v.f)
		}
	}
	// Noise before a start character is skipped.
	r := bufio.NewReader(bytes.NewReader(append([]byte{0x00, 0xff, 0x33}, hx(t, "1049014a16")...)))
	if f, err := ReadFrame(r, 1); err != nil || f.Fn() != FnRequestStatus {
		t.Errorf("after noise: %v %v", f, err)
	}
	// Damaged frames are refused with ErrFrame.
	for _, bad := range []string{"1049014b16", "1049014a17", "6809086873010000000000000016", "680909687301640106010000" + "14f516"} {
		if _, err := ReadFrame(bytes.NewReader(hx(t, bad)), 1); !errors.Is(err, ErrFrame) {
			t.Errorf("%s: err %v, want ErrFrame", bad, err)
		}
	}
	// Truncated input is an I/O error, not a frame.
	if _, err := ReadFrame(bytes.NewReader(hx(t, "680909")), 1); err == nil || errors.Is(err, ErrFrame) {
		t.Errorf("truncated: %v", err)
	}
}
