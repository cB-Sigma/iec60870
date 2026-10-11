package iec60870

import (
	"bytes"
	"errors"
	"math"
	"testing"
	"time"
)

// Covers: SIG-IPE-141
func TestASDUCodec(t *testing.T) {
	p := Params{}.WithDefaults()
	// Hand-built: M_ME_NC_1, one object, spontaneous, originator 0, CA 1,
	// IOA 1, 1.5 (0x3FC00000 little-endian), QDS good.
	raw := []byte{13, 1, 3, 0, 1, 0, 1, 0, 0, 0x00, 0x00, 0xc0, 0x3f, 0x00}
	a, err := DecodeASDU(raw, p, time.UTC)
	if err != nil || a.Type != MMeNc1 || a.Cause != CauseSpontaneous || a.CA != 1 || len(a.Objects) != 1 ||
		a.Objects[0].IOA != 1 || a.Objects[0].Value != 1.5 {
		t.Fatalf("decoded %+v %v", a, err)
	}
	if b, _ := a.Encode(p, time.UTC); !bytes.Equal(b, raw) {
		t.Errorf("re-encoded % x, want % x", b, raw)
	}
	// CP56Time2a of Thursday 24 Sep 2026 10:15:30.250: milliseconds 30250
	// (0x762A), minute 15, hour 10, day 24 with weekday 4, month 9, year 26.
	ts := time.Date(2026, 9, 24, 10, 15, 30, 250e6, time.UTC)
	if got, want := CP56(ts, false, time.UTC), []byte{0x2a, 0x76, 0x0f, 0x0a, 24 | 4<<5, 9, 26}; !bytes.Equal(got, want) {
		t.Errorf("CP56 = % x, want % x", got, want)
	}
	if back, iv := ParseCP56(CP56(ts, true, time.UTC), time.UTC); !back.Equal(ts) || !iv {
		t.Errorf("CP56 round trip = %v %v", back, iv)
	}
	ist, _ := time.LoadLocation("Asia/Kolkata")
	if back, _ := ParseCP56(CP56(ts, false, ist), ist); !back.Equal(ts) {
		t.Errorf("CP56 in IST = %v, want %v", back, ts)
	}
	ts = ts.Truncate(time.Millisecond)
	cases := []struct {
		typ TypeID
		o   Object
	}{
		{MSpNa1, Object{IOA: 100, Value: 1, Quality: QInvalid | QBlocked}},
		{MDpNa1, Object{IOA: 101, Value: 2, Quality: QNotTopical}},
		{MMeNa1, Object{IOA: 102, Value: -0.5, Quality: QOverflow}},
		{MMeNb1, Object{IOA: 103, Value: -1234, Quality: QSubstituted}},
		{MMeNc1, Object{IOA: 104, Value: 49.875}},
		{MItNa1, Object{IOA: 105, Value: -123456, Seq: 7, Quality: QCarry | QAdjusted | QInvalid}},
		{MSpTb1, Object{IOA: 106, Value: 0, Time: ts}},
		{MDpTb1, Object{IOA: 107, Value: 3, Time: ts, TimeInvalid: true}},
		{MMeTd1, Object{IOA: 108, Value: 0.25, Time: ts}},
		{MMeTe1, Object{IOA: 109, Value: 32767, Time: ts}},
		{MMeTf1, Object{IOA: 110, Value: -3.25, Quality: QInvalid, Time: ts}},
		{MItTb1, Object{IOA: 111, Value: 99, Seq: 31, Time: ts}},
		{CScNa1, Object{IOA: 112, Value: 1, Select: true, Qualifier: 1}},
		{CDcNa1, Object{IOA: 113, Value: 2, Qualifier: 3}},
		{CSeNa1, Object{IOA: 114, Value: 0.75, Select: true}},
		{CSeNb1, Object{IOA: 115, Value: -7, Qualifier: 5}},
		{CSeNc1, Object{IOA: 116, Value: 12.5}},
		{CScTa1, Object{IOA: 117, Value: 0, Time: ts}},
		{CDcTa1, Object{IOA: 118, Value: 1, Select: true, Time: ts}},
		{CSeTa1, Object{IOA: 119, Value: -1, Time: ts}},
		{CSeTb1, Object{IOA: 120, Value: 300, Time: ts}},
		{CSeTc1, Object{IOA: 121, Value: 1e6, Select: true, Qualifier: 100, Time: ts}},
		{MEiNa1, Object{IOA: 0, Value: 2}},
		{CIcNa1, Object{IOA: 0, Value: 20}},
		{CCiNa1, Object{IOA: 0, Value: 5}},
		{CCsNa1, Object{IOA: 0, Time: ts}},
	}
	for _, sizes := range []Params{p, {COTSize: 1, CASize: 1, IOASize: 1}, {COTSize: 2, CASize: 2, IOASize: 2, Originator: 9}} {
		for _, tc := range cases {
			in := &ASDU{Type: tc.typ, Cause: CauseActivation, Negative: true, Test: true, Orig: sizes.Originator, CA: 7, Objects: []Object{tc.o}}
			if sizes.IOASize == 1 {
				in.Objects[0].IOA &= 0xff
			}
			b, err := in.Encode(sizes, time.UTC)
			if err != nil {
				t.Fatalf("%s: %v", tc.typ, err)
			}
			out, err := DecodeASDU(b, sizes, time.UTC)
			if err != nil {
				t.Fatalf("%s: %v", tc.typ, err)
			}
			got, want := out.Objects[0], in.Objects[0]
			if out.Type != tc.typ || out.Cause != CauseActivation || !out.Negative || !out.Test || out.CA != 7 || out.Orig != sizes.Originator ||
				got.IOA != want.IOA || math.Abs(got.Value-want.Value) > 1e-4 || got.Quality != want.Quality || got.Seq != want.Seq ||
				got.Select != want.Select || got.Qualifier != want.Qualifier || !got.Time.Equal(want.Time) || got.TimeInvalid != want.TimeInvalid {
				t.Errorf("%s with sizes %+v: got %+v, want %+v", tc.typ, sizes, got, want)
			}
		}
	}
	// A sequence (SQ=1) carries one IOA for consecutive objects.
	seq := &ASDU{Type: MMeNb1, SQ: true, Cause: CauseInterrogated, CA: 1, Objects: []Object{{IOA: 500, Value: 1}, {Value: 2}, {Value: 3}}}
	b, _ := seq.Encode(p, time.UTC)
	if len(b) != 6+3+3*3 {
		t.Errorf("SQ ASDU is %d bytes, want 18", len(b))
	}
	out, err := DecodeASDU(b, p, time.UTC)
	if err != nil || out.Objects[2].IOA != 502 || out.Objects[2].Value != 3 {
		t.Errorf("SQ decode = %+v %v", out, err)
	}
	// Length mismatches and unknown types are refused.
	if _, err := DecodeASDU(raw[:len(raw)-1], p, time.UTC); err == nil {
		t.Error("a short ASDU was accepted")
	}
	if _, err := DecodeASDU([]byte{200, 1, 3, 0, 1, 0, 1, 0, 0, 0}, p, time.UTC); !errors.Is(err, ErrUnsupportedType) {
		t.Errorf("type 200: %v", err)
	}
	if QualityString(0) != "good" || QualityString(QInvalid|QNotTopical) != "invalid,not-topical" {
		t.Errorf("quality strings: %q %q", QualityString(0), QualityString(QInvalid|QNotTopical))
	}
	if CauseActCon.String() != "activation confirmation" || Cause(25).String() != "group 5 interrogation" {
		t.Error("cause names")
	}
}
