package iec60870

import (
	"bytes"
	"errors"
	"math"
	"testing"
	"time"
)

// Covers: SIG-IPE-630
func TestCP24TimeTaggedTypes(t *testing.T) {
	p := Params{}.WithDefaults()
	// Hand-built M_ME_TC_1: one object, spontaneous, originator 0, CA 1,
	// IOA 7, 1.5 (0x3FC00000), QDS good, CP24Time2a 15 min 30.250 s
	// (milliseconds 30250 = 0x762A, minute 15 = 0x0F).
	raw := []byte{14, 1, 3, 0, 1, 0, 7, 0, 0, 0x00, 0x00, 0xc0, 0x3f, 0x00, 0x2a, 0x76, 0x0f}
	now := time.Date(2026, 9, 24, 10, 16, 2, 0, time.UTC)
	a, err := DecodeASDUAt(raw, p, time.UTC, now)
	if err != nil || a.Type != MMeTc1 || len(a.Objects) != 1 || a.Objects[0].IOA != 7 || a.Objects[0].Value != 1.5 {
		t.Fatalf("decoded %+v %v", a, err)
	}
	if want := time.Date(2026, 9, 24, 10, 15, 30, 250e6, time.UTC); !a.Objects[0].Time.Equal(want) || a.Objects[0].TimeInvalid {
		t.Errorf("time = %v (invalid %v), want %v", a.Objects[0].Time, a.Objects[0].TimeInvalid, want)
	}
	if b, _ := a.Encode(p, time.UTC); !bytes.Equal(b, raw) {
		t.Errorf("re-encoded % x, want % x", b, raw)
	}
	if got := CP24(time.Date(2026, 9, 24, 10, 15, 30, 250e6, time.UTC), true, time.UTC); !bytes.Equal(got, []byte{0x2a, 0x76, 0x8f}) {
		t.Errorf("CP24 with IV = % x", got)
	}

	ts := now.Add(-3 * time.Second).Truncate(time.Millisecond)
	cases := []struct {
		typ TypeID
		o   Object
	}{
		{MSpTa1, Object{IOA: 1, Value: 1, Quality: QBlocked, Time: ts}},
		{MDpTa1, Object{IOA: 2, Value: 2, Time: ts, TimeInvalid: true}},
		{MStNa1, Object{IOA: 3, Value: -64, Transient: true, Quality: QInvalid}},
		{MStTa1, Object{IOA: 4, Value: 63, Quality: QOverflow, Time: ts}},
		{MStTb1, Object{IOA: 5, Value: -1, Transient: true, Time: ts}},
		{MBoNa1, Object{IOA: 6, Value: 0xdeadbeef, Quality: QNotTopical}},
		{MBoTa1, Object{IOA: 7, Value: 1, Time: ts}},
		{MBoTb1, Object{IOA: 8, Value: 0xffffffff, Time: ts}},
		{MMeTa1, Object{IOA: 9, Value: -0.25, Quality: QSubstituted, Time: ts}},
		{MMeTb1, Object{IOA: 10, Value: -32768, Time: ts}},
		{MMeTc1, Object{IOA: 11, Value: 49.875, Time: ts, TimeInvalid: true}},
		{MItTa1, Object{IOA: 12, Value: 123456, Seq: 3, Quality: QCarry, Time: ts}},
	}
	for _, sizes := range []Params{p, {COTSize: 1, CASize: 1, IOASize: 2}} {
		for _, tc := range cases {
			in := &ASDU{Type: tc.typ, Cause: CauseSpontaneous, CA: 3, Objects: []Object{tc.o}}
			b, err := in.Encode(sizes, time.UTC)
			if err != nil {
				t.Fatalf("%s: %v", tc.typ, err)
			}
			if sh := shapes[tc.typ]; len(b) != 2+sizes.COTSize+sizes.CASize+sizes.IOASize+sh.size+sh.tag {
				t.Errorf("%s is %d bytes", tc.typ, len(b))
			}
			out, err := DecodeASDUAt(b, sizes, time.UTC, now)
			if err != nil {
				t.Fatalf("%s: %v", tc.typ, err)
			}
			got, want := out.Objects[0], in.Objects[0]
			if got.IOA != want.IOA || math.Abs(got.Value-want.Value) > 1e-4 || got.Quality != want.Quality || got.Seq != want.Seq ||
				got.Transient != want.Transient || !got.Time.Equal(want.Time) || got.TimeInvalid != want.TimeInvalid {
				t.Errorf("%s: got %+v, want %+v", tc.typ, got, want)
			}
			if tc.typ.TimeTagged() != !want.Time.IsZero() {
				t.Errorf("%s: TimeTagged = %v", tc.typ, tc.typ.TimeTagged())
			}
		}
	}
	// A step position outside the 7-bit range and a negative bitstring are
	// refused.
	for _, bad := range []*ASDU{
		{Type: MStNa1, Cause: CauseSpontaneous, Objects: []Object{{Value: 64}}},
		{Type: MBoNa1, Cause: CauseSpontaneous, Objects: []Object{{Value: -1}}},
	} {
		if _, err := bad.Encode(p, time.UTC); err == nil {
			t.Errorf("%s with %v was encoded", bad.Type, bad.Objects[0].Value)
		}
	}
	// A CP24 type with one byte missing is refused.
	if _, err := DecodeASDUAt(raw[:len(raw)-1], p, time.UTC, now); err == nil || errors.Is(err, ErrUnsupportedType) {
		t.Errorf("short M_ME_TC_1: %v", err)
	}
	for typ, name := range map[TypeID]string{MSpTa1: "M_SP_TA_1", MItTa1: "M_IT_TA_1", MBoTb1: "M_BO_TB_1", MStNa1: "M_ST_NA_1"} {
		if typ.String() != name {
			t.Errorf("%d is %s, want %s", typ, typ, name)
		}
	}
}

// Covers: SIG-IPE-631
func TestCP24Completion(t *testing.T) {
	ist, _ := time.LoadLocation("Asia/Kolkata")
	utc := func(y int, mo time.Month, d, h, mi, s, ms int) time.Time {
		return time.Date(y, mo, d, h, mi, s, ms*1e6, time.UTC)
	}
	for _, tc := range []struct {
		name       string
		ms, minute int
		loc        *time.Location
		now, want  time.Time
	}{
		{"same hour", 30250, 15, time.UTC, utc(2026, 9, 24, 10, 16, 0, 0), utc(2026, 9, 24, 10, 15, 30, 250)},
		{"tag before the hour, received after it", 58000, 59, time.UTC, utc(2026, 9, 24, 11, 0, 1, 0), utc(2026, 9, 24, 10, 59, 58, 0)},
		{"tag before midnight, received after it", 59000, 59, time.UTC, utc(2026, 9, 25, 0, 0, 2, 0), utc(2026, 9, 24, 23, 59, 59, 0)},
		{"tag before new year, received after it", 59999, 59, time.UTC, utc(2027, 1, 1, 0, 0, 0, 500), utc(2026, 12, 31, 23, 59, 59, 999)},
		{"sender clock slightly ahead, across the hour", 1000, 0, time.UTC, utc(2026, 9, 24, 10, 59, 59, 0), utc(2026, 9, 24, 11, 0, 1, 0)},
		{"sender clock slightly ahead, same hour", 20000, 16, time.UTC, utc(2026, 9, 24, 10, 16, 5, 0), utc(2026, 9, 24, 10, 16, 20, 0)},
		// IST is UTC+5:30: its hours begin at half past the UTC hour.
		{"IST hour boundary", 50000, 59, ist, utc(2026, 9, 24, 0, 30, 10, 0), utc(2026, 9, 24, 0, 29, 50, 0)},
		{"IST same hour", 0, 5, ist, utc(2026, 9, 24, 0, 36, 0, 0), utc(2026, 9, 24, 0, 35, 0, 0)},
	} {
		got := CompleteCP24(tc.ms, tc.minute, tc.loc, tc.now)
		if !got.Equal(tc.want) {
			t.Errorf("%s: %v, want %v", tc.name, got.UTC(), tc.want)
		}
	}
	// Through the codec: IV and the minute's reserved bit.
	if got, iv := ParseCP24([]byte{0x10, 0x27, 0xc5}, time.UTC, utc(2026, 9, 24, 10, 6, 0, 0)); !got.Equal(utc(2026, 9, 24, 10, 5, 10, 0)) || !iv {
		t.Errorf("ParseCP24 = %v %v", got, iv)
	}
}
