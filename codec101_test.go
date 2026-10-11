package iec60870_test

import (
	"bytes"
	"encoding/hex"
	"math"
	"strings"
	"testing"
	"time"

	"github.com/cB-Sigma/iec60870"
)

// The ASDU figures of IEC 60870-5-101 clause 7.3 give
// each type's octets: type identification, variable structure qualifier,
// cause, common address, object address, then the elements in the order
// drawn. Each vector below is written from its figure with the usual
// IEC 101 sizes (one-octet cause and common address, two-octet object
// address), decoded, checked field by field and encoded back to the same
// octets.

var p101 = iec60870.Params{COTSize: 1, CASize: 1, IOASize: 2}

func unhex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(strings.ReplaceAll(s, " ", ""))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// cp56At is a CP56Time2a of 2026-09-24 10:15:30.250 UTC (a Thursday).
const cp56At = "2a760f0a98091a"

var at = time.Date(2026, 9, 24, 10, 15, 30, 250e6, time.UTC)

// Covers: SIG-IPE-1320
func TestCodec101Figures(t *testing.T) {
	now := at.Add(10 * time.Second) // completes the CP24Time2a tags
	for _, tc := range []struct {
		name  string
		hex   string
		check func(t *testing.T, a *iec60870.ASDU)
	}{
		{"7.3.1.20 M_PS_NA_1 sequence (Amendment 1: object j at A+16(j-1), OV always 0)",
			"14 82 03 07 1000 0201 0100 80 ffff 0000 10", func(t *testing.T, a *iec60870.ASDU) {
				if len(a.Objects) != 2 || a.Objects[0].IOA != 16 || a.Objects[1].IOA != 32 {
					t.Fatalf("addresses %+v", a.Objects)
				}
				o := a.Objects[0]
				if o.Value != 0x0102 || o.Change != 1 || o.Quality != iec60870.QInvalid || a.Objects[1].Quality != iec60870.QBlocked {
					t.Errorf("SCD/QDS %+v", a.Objects)
				}
			}},
		{"7.3.1.21 M_ME_ND_1 (NVA only)", "15 01 01 07 0500 0040", func(t *testing.T, a *iec60870.ASDU) {
			if a.Cause != iec60870.CausePeriodic || a.Objects[0].Value != 0.5 || a.Objects[0].Quality != 0 {
				t.Errorf("%+v", a.Objects[0])
			}
		}},
		{"7.3.1.17 M_EP_TA_1 (SEP, CP16 elapsed, CP24)", "11 01 03 07 0a00 8a dc05 2a760f", func(t *testing.T, a *iec60870.ASDU) {
			o := a.Objects[0]
			if o.Value != 2 || o.Quality != iec60870.QInvalid|iec60870.QElapsedInvalid || o.Elapsed != 1500*time.Millisecond || !o.Time.Equal(at) {
				t.Errorf("%+v", o)
			}
		}},
		{"7.3.1.18 M_EP_TB_1 (SPE, QDP, CP16 duration, CP24)", "12 01 03 07 0b00 13 00 fa00 2a760f", func(t *testing.T, a *iec60870.ASDU) {
			o := a.Objects[0]
			if o.Value != float64(iec60870.SPEGeneral|iec60870.SPEL1|iec60870.SPEEarth) || o.Elapsed != 250*time.Millisecond {
				t.Errorf("%+v", o)
			}
		}},
		{"7.3.1.19 M_EP_TC_1 (OCI, QDP, CP16 operating time, CP24)", "13 01 03 07 0c00 0f 10 6400 2a760f", func(t *testing.T, a *iec60870.ASDU) {
			o := a.Objects[0]
			if o.Value != 15 || o.Quality != iec60870.QBlocked || o.Elapsed != 100*time.Millisecond {
				t.Errorf("%+v", o)
			}
		}},
		{"7.3.1 M_EP_TD_1 (SEP, CP16, CP56)", "26 01 03 07 0a00 01 e803 " + cp56At, func(t *testing.T, a *iec60870.ASDU) {
			if o := a.Objects[0]; o.Value != 1 || o.Elapsed != time.Second || !o.Time.Equal(at) {
				t.Errorf("%+v", o)
			}
		}},
		{"7.3.1 M_EP_TE_1 (SPE, QDP, CP16, CP56)", "27 01 03 07 0b00 21 00 0100 " + cp56At, func(t *testing.T, a *iec60870.ASDU) {
			if o := a.Objects[0]; o.Value != float64(iec60870.SPEGeneral|iec60870.SPEReverse) || o.Elapsed != time.Millisecond {
				t.Errorf("%+v", o)
			}
		}},
		{"7.3.1 M_EP_TF_1 (OCI, QDP, CP16, CP56)", "28 01 03 07 0c00 03 00 0000 " + cp56At, func(t *testing.T, a *iec60870.ASDU) {
			if o := a.Objects[0]; o.Value != float64(iec60870.OCIGeneral|iec60870.OCIL1) {
				t.Errorf("%+v", o)
			}
		}},
		{"7.3.3 M_EI_NA_1 (COI remote reset after a change of local parameters)", "46 01 04 07 0000 82", func(t *testing.T, a *iec60870.ASDU) {
			if c := uint8(a.Objects[0].Value); c != iec60870.COIRemote|iec60870.COIChanged || !strings.Contains(iec60870.COIString(c), "remote reset, after a change") {
				t.Errorf("COI %d %q", c, iec60870.COIString(c))
			}
		}},
		{"7.3.4.2 C_CI_NA_1 (QCC group 2, freeze with reset)", "65 01 06 07 0000 82", func(t *testing.T, a *iec60870.ASDU) {
			if rqt, frz := iec60870.SplitQCC(uint8(a.Objects[0].Value)); rqt != 2 || frz != iec60870.FRZFreezeReset {
				t.Errorf("RQT %d FRZ %d", rqt, frz)
			}
		}},
		{"7.3.4.3 C_RD_NA_1 (object address only)", "66 01 05 07 3412", func(t *testing.T, a *iec60870.ASDU) {
			if a.Objects[0].IOA != 0x1234 || a.Cause != iec60870.CauseRequest {
				t.Errorf("%+v", a)
			}
		}},
		{"7.3.4.5 C_TS_NA_1 (FBP 55AA)", "68 01 06 07 0000 aa55", func(t *testing.T, a *iec60870.ASDU) {
			if a.Objects[0].Value != iec60870.FBP {
				t.Errorf("FBP %v", a.Objects[0].Value)
			}
		}},
		{"7.3.4.6 C_RP_NA_1 (QRP 1)", "69 01 06 07 0000 01", func(t *testing.T, a *iec60870.ASDU) {
			if a.Objects[0].Value != iec60870.QRPGeneral {
				t.Errorf("QRP %v", a.Objects[0].Value)
			}
		}},
		{"7.3.4.7 C_CD_NA_1 (CP16Time2a)", "6a 01 03 07 0000 1027", func(t *testing.T, a *iec60870.ASDU) {
			if a.Objects[0].Elapsed != 10*time.Second {
				t.Errorf("delay %v", a.Objects[0].Elapsed)
			}
		}},
		{"7.3.5.1 Figure 79 P_ME_NA_1 (NVA, QPM threshold)", "6e 01 06 07 0100 00c0 01", func(t *testing.T, a *iec60870.ASDU) {
			if o := a.Objects[0]; o.Value != -0.5 || o.Qualifier != iec60870.KPAThreshold {
				t.Errorf("%+v", o)
			}
		}},
		{"7.3.5.2 Figure 80 P_ME_NB_1 (SVA, QPM low limit)", "6f 01 06 07 0100 3930 03", func(t *testing.T, a *iec60870.ASDU) {
			if o := a.Objects[0]; o.Value != 12345 || iec60870.KPAName(o.Qualifier) != "low-limit" {
				t.Errorf("%+v", o)
			}
		}},
		{"7.3.5.3 Figure 81 P_ME_NC_1 (IEEE 754, QPM high limit)", "70 01 07 07 0100 0000c03f 04", func(t *testing.T, a *iec60870.ASDU) {
			if o := a.Objects[0]; o.Value != 1.5 || o.Qualifier != iec60870.KPAHighLimit {
				t.Errorf("%+v", o)
			}
		}},
		{"7.3.5.4 Figure 82 P_AC_NA_1 (QPA 3)", "71 01 08 07 0100 03", func(t *testing.T, a *iec60870.ASDU) {
			if a.Objects[0].Qualifier != iec60870.QPACyclic || a.Cause != iec60870.CauseDeactivation {
				t.Errorf("%+v", a)
			}
		}},
		{"7.3.6.1 Figure 83 F_FR_NA_1 (NOF, LOF, FRQ negative)", "78 01 0d 07 0010 0100 030201 80", func(t *testing.T, a *iec60870.ASDU) {
			if o := a.Objects[0]; o.IOA != 0x1000 || o.File != 1 || o.Length != 0x010203 || o.Qualifier != iec60870.FRQNegative {
				t.Errorf("%+v", o)
			}
		}},
		{"7.3.6.2 Figure 84 F_SR_NA_1 (NOF, NOS, LOF, SRQ)", "79 01 0d 07 0010 0100 02 640000 00", func(t *testing.T, a *iec60870.ASDU) {
			if o := a.Objects[0]; o.Section != 2 || o.Length != 100 || o.Qualifier != 0 {
				t.Errorf("%+v", o)
			}
		}},
		{"7.3.6.3 Figure 85 F_SC_NA_1 call directory (cause 5, address 0, SCQ 0)", "7a 01 05 07 0000 0000 00 00", func(t *testing.T, a *iec60870.ASDU) {
			if o := a.Objects[0]; o.IOA != 0 || o.Qualifier != iec60870.SCQDefault {
				t.Errorf("%+v", o)
			}
		}},
		{"7.3.6.4 Figure 86 F_LS_NA_1 (LSQ last segment, CHS)", "7b 01 0d 07 0010 0100 02 03 ab", func(t *testing.T, a *iec60870.ASDU) {
			if o := a.Objects[0]; o.Qualifier != iec60870.LSQSection || o.Checksum != 0xab {
				t.Errorf("%+v", o)
			}
		}},
		{"7.3.6.5 Figure 87 F_AF_NA_1 (AFQ negative section, checksum failed)", "7c 01 0d 07 0010 0100 02 24", func(t *testing.T, a *iec60870.ASDU) {
			o := a.Objects[0]
			if o.Qualifier&0x0f != iec60870.AFQSectionNegative || iec60870.FileError(o.Qualifier) != "checksum failed" {
				t.Errorf("%+v %q", o, iec60870.FileError(o.Qualifier))
			}
		}},
		{"7.3.6.6 Figure 88 F_SG_NA_1 (NOF, NOS, LOS, segment)", "7d 01 0d 07 0010 0100 02 03 616263", func(t *testing.T, a *iec60870.ASDU) {
			if o := a.Objects[0]; string(o.Segment) != "abc" || o.Length != 3 || o.Section != 2 {
				t.Errorf("%+v", o)
			}
		}},
		{"7.3.6.7 Figure 89 F_DR_TA_1 sequence (NOF, LOF, SOF with LFD, CP56)", "7e 82 05 07 0010 0100 100000 00 " + cp56At + " 0300 000000 20 " + cp56At,
			func(t *testing.T, a *iec60870.ASDU) {
				if len(a.Objects) != 2 || a.Objects[1].IOA != 0x1001 || a.Objects[1].Status != iec60870.SOFLastFile || a.Objects[0].Length != 16 || !a.Objects[0].Time.Equal(at) {
					t.Errorf("%+v", a.Objects)
				}
			}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b := unhex(t, tc.hex)
			a, err := iec60870.DecodeASDUAt(b, p101, time.UTC, now)
			if err != nil {
				t.Fatal(err)
			}
			if a.CA != 7 {
				t.Errorf("CA %d", a.CA)
			}
			tc.check(t, a)
			back, err := a.Encode(p101, time.UTC)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(back, b) {
				t.Errorf("re-encoded\n% x\nwant\n% x", back, b)
			}
		})
	}
}

// Covers: SIG-IPE-1321
func TestInformationElementBits(t *testing.T) {
	// 7.2.6.1 to 7.2.6.4: SPI in bit 1, DPI in bits 1 and 2, OV in bit 1 of
	// QDS; BL, SB, NT, IV in bits 5 to 8; bits 2 to 4 reserved (0).
	for _, tc := range []struct {
		typ iec60870.TypeID
		el  string
		v   float64
		q   uint8
	}{
		{iec60870.MSpNa1, "f1", 1, 0xf0},
		{iec60870.MDpNa1, "12", 2, iec60870.QBlocked},
		{iec60870.MMeNb1, "ffff 21", -1, iec60870.QOverflow | iec60870.QSubstituted},
		// 7.2.6.5 VTI: value bits 1 to 7 (two's complement), transient bit 8.
		{iec60870.MStNa1, "c0 40", -64, iec60870.QNotTopical},
		// 7.2.6.9 BCR: counter I32, then SQ bits 1-5, CY 6, CA 7, IV 8.
		{iec60870.MItNa1, "ffffff7f fe", math.MaxInt32, iec60870.QCarry | iec60870.QAdjusted | iec60870.QInvalid},
		// 5-4 6.4.1 F16: -1 is 8000, 1-2^-15 is 7fff.
		{iec60870.MMeNa1, "0080 00", -1, 0},
		{iec60870.MMeNa1, "ff7f 00", 32767.0 / 32768, 0},
	} {
		b := append(unhex(t, "01 01 03 07 0100"), unhex(t, tc.el)...)
		b[0] = byte(tc.typ)
		a, err := iec60870.DecodeASDU(b, p101, time.UTC)
		if err != nil {
			t.Fatalf("%s: %v", tc.typ, err)
		}
		o := a.Objects[0]
		if o.Value != tc.v || o.Quality != tc.q {
			t.Errorf("%s % x: value %v quality %#x, want %v %#x", tc.typ, b, o.Value, o.Quality, tc.v, tc.q)
		}
		if tc.typ == iec60870.MStNa1 && !o.Transient {
			t.Error("VTI transient bit 8 not read")
		}
		if tc.typ == iec60870.MItNa1 && o.Seq != 0x1e {
			t.Errorf("BCR sequence number %d, want 30", o.Seq)
		}
		back, _ := a.Encode(p101, time.UTC)
		if !bytes.Equal(back, b) {
			t.Errorf("%s re-encoded % x, want % x", tc.typ, back, b)
		}
	}
	// 5-4 6.5 R32-IEEE STD 754: fraction in octets 1 to 3 (LSB first), the
	// exponent's low bit in octet 3's bit 8, sign and exponent in octet 4.
	a := &iec60870.ASDU{Type: iec60870.MMeNc1, Cause: 3, CA: 7, Objects: []iec60870.Object{{IOA: 1, Value: -2.5}}}
	if b, _ := a.Encode(p101, time.UTC); !bytes.Equal(b[6:10], []byte{0x00, 0x00, 0x20, 0xc0}) {
		t.Errorf("-2.5 as R32 % x", b[6:10])
	}
	// QOC (7.2.6.26): QU in bits 3 to 7, S/E in bit 8; SCS bit 1, bit 2 reserved.
	c := &iec60870.ASDU{Type: iec60870.CScNa1, Cause: 6, CA: 7, Objects: []iec60870.Object{{IOA: 1, Value: 1, Select: true, Qualifier: iec60870.QULongPulse}}}
	if b, _ := c.Encode(p101, time.UTC); b[6] != 0x80|2<<2|1 {
		t.Errorf("SCO %#x", b[6])
	}
	if q, ok := iec60870.ParseQU("persistent"); !ok || q != 3 {
		t.Errorf("persistent output is QU %d", q)
	}
	// 7.2.6.17 RCS: 1 next step lower, 2 next step higher.
	r := &iec60870.ASDU{Type: iec60870.CRcNa1, Cause: 6, CA: 7, Objects: []iec60870.Object{{IOA: 1, Value: 2, Qualifier: iec60870.QUShortPulse}}}
	if b, _ := r.Encode(p101, time.UTC); b[6] != 1<<2|2 {
		t.Errorf("RCO %#x", b[6])
	}
	// QOI 20 station, 21 to 36 groups; QCC RQT 1-5, FRZ bits 7 and 8.
	if iec60870.QOIGroup(16) != 36 || iec60870.InterrogationGroup(21) != 1 || iec60870.InterrogationGroup(20) != 0 {
		t.Error("QOI values")
	}
	if iec60870.QCC(iec60870.RQTGeneral, iec60870.FRZReset) != 0xc5 {
		t.Errorf("QCC %#x", iec60870.QCC(iec60870.RQTGeneral, iec60870.FRZReset))
	}
	for s, want := range map[string]uint8{"": 0, "read": 0, "freeze": 1, "freeze-reset": 2, "reset": 3} {
		if f, err := iec60870.ParseFRZ(s); err != nil || f != want {
			t.Errorf("FRZ %q = %d %v", s, f, err)
		}
	}
	if _, err := iec60870.ParseFRZ("zap"); err == nil {
		t.Error("unknown counter operation accepted")
	}
	// 7.2.6.37 CHS: arithmetic sum modulo 256.
	if iec60870.Checksum([]byte{0xff, 0x02, 0x10}) != 0x11 {
		t.Error("CHS")
	}
}

// Covers: SIG-IPE-1322
func TestTimeTags101(t *testing.T) {
	// CP56Time2a (5-4 6.8, 101 7.2.6.18): IV bit 8 and RES1/GEN bit 7 of
	// the minutes octet, SU bit 8 of the hours octet, day of week 1
	// (Monday) to 7 in bits 6 to 8 of the day octet.
	tt := iec60870.DecodeCP56(unhex(t, "2a76cf0a98091a"), time.UTC)
	if !tt.Invalid || !tt.Substituted || tt.Summer || !tt.Time.Equal(at) {
		t.Errorf("IV and GEN: %+v", tt)
	}
	if b := iec60870.CP56(time.Date(2026, 9, 27, 0, 0, 0, 0, time.UTC), false, time.UTC); b[4]>>5 != 7 {
		t.Errorf("Sunday is day of week %d", b[4]>>5)
	}
	// Amendment 1: a tag with SU set is the same instant as the tag an
	// hour earlier with SU clear.
	su := iec60870.DecodeCP56(unhex(t, "2a760f8b98091a"), time.UTC) // 11:15 SU
	if !su.Summer || !su.Time.Equal(at) {
		t.Errorf("SU tag %v, want %v", su.Time, at)
	}
	berlin, err := time.LoadLocation("Europe/Berlin")
	if err != nil {
		t.Skip("no zone data")
	}
	b := iec60870.CP56(at, false, berlin) // 12:15 CEST, SU set
	if b[3] != 0x80|12 {
		t.Errorf("summer time hour octet %#x", b[3])
	}
	if back, _ := iec60870.ParseCP56(b, berlin); !back.Equal(at) {
		t.Errorf("summer time round trip %v", back)
	}
	// 7.4.6: the clock synchronisation carries SU 0 and ignores it.
	cs := &iec60870.ASDU{Type: iec60870.CCsNa1, Cause: 6, CA: 7, Objects: []iec60870.Object{{Time: at}}}
	enc, _ := cs.Encode(p101, berlin)
	if enc[6+3]&0x80 != 0 {
		t.Error("C_CS_NA_1 sent with SU set")
	}
	enc[6+3] |= 0x80
	if dec, err := iec60870.DecodeASDU(enc, p101, berlin); err != nil || !dec.Objects[0].Time.Equal(at) {
		t.Errorf("C_CS_NA_1 SU not ignored: %v %v", dec.Objects[0].Time, err)
	}
	// Fields out of range make the time invalid.
	if bad := iec60870.DecodeCP56(unhex(t, "60ea0f0a98091a"), time.UTC); !bad.OutOfRange {
		t.Error("60000 ms accepted")
	}
	if _, iv := iec60870.ParseCP56(unhex(t, "00000f0a000a1a"), time.UTC); !iv {
		t.Error("day 0 accepted as valid")
	}
	// CP24Time2a keeps IV and GEN (the first three octets).
	a, err := iec60870.DecodeASDUAt(unhex(t, "02 01 03 07 0100 01 2a76cf"), p101, time.UTC, at)
	if err != nil || !a.Objects[0].TimeInvalid || !a.Objects[0].TimeSubstituted {
		t.Errorf("CP24 flags %+v %v", a.Objects, err)
	}
	// CP16Time2a: 0 to 59 999 ms.
	if _, err := iec60870.CP16(time.Minute); err == nil {
		t.Error("CP16Time2a of a minute accepted")
	}
	if c, _ := iec60870.CP16(59999 * time.Millisecond); !bytes.Equal(c, []byte{0x5f, 0xea}) {
		t.Errorf("CP16 % x", c)
	}
}

// Covers: SIG-IPE-1320
func TestCodec101Structure(t *testing.T) {
	// 7.3: time-tagged monitor types carry a tag per object: no sequence.
	if _, err := iec60870.DecodeASDU(unhex(t, "1e 82 03 07 0100 01"+cp56At+"00"+cp56At), p101, time.UTC); err == nil {
		t.Error("M_SP_TB_1 sequence decoded")
	}
	if _, err := (&iec60870.ASDU{Type: iec60870.MSpTb1, SQ: true, Objects: []iec60870.Object{{}, {}}}).Encode(p101, time.UTC); err == nil {
		t.Error("M_SP_TB_1 sequence encoded")
	}
	// A segment whose LOS disagrees with its octets.
	if _, err := iec60870.DecodeASDU(unhex(t, "7d 01 0d 07 0010 0100 02 04 616263"), p101, time.UTC); err == nil {
		t.Error("short segment decoded")
	}
	// Amendment 1 7.1: an ASDU may carry no object (an empty directory).
	a, err := iec60870.DecodeASDU(unhex(t, "7e 00 05 07"), p101, time.UTC)
	if err != nil || len(a.Objects) != 0 {
		t.Errorf("empty ASDU: %v %v", a, err)
	}
	if b, err := a.Encode(p101, time.UTC); err != nil || len(b) != 4 {
		t.Errorf("empty ASDU encoded % x %v", b, err)
	}
	// 7.2.3: cause in bits 1 to 6, P/N bit 7, T bit 8; originator in the
	// second octet (0 when unused).
	b := unhex(t, "2d 01 c7 09 0700 0100 81")
	a, err = iec60870.DecodeASDU(b, iec60870.Params{COTSize: 2, CASize: 2, IOASize: 2}, time.UTC)
	if err != nil || !a.Test || !a.Negative || a.Cause != iec60870.CauseActCon || a.Orig != 9 {
		t.Errorf("COT %+v %v", a, err)
	}
	// Type names and private causes.
	for id, name := range map[iec60870.TypeID]string{20: "M_PS_NA_1", 102: "C_RD_NA_1", 126: "F_DR_TA_1", 113: "P_AC_NA_1"} {
		if got, ok := iec60870.TypeByName(name); !ok || got != id || id.String() != name {
			t.Errorf("type %d name %s", id, id)
		}
	}
	if iec60870.Cause(50).String() != "private cause 50" {
		t.Error(iec60870.Cause(50).String())
	}
}

// Covers: SIG-IPE-1341
func TestQueryLogFigure31(t *testing.T) {
	// IEC 60870-5-104 Figure 31: F_SC_NB_1 carries the name of file and two
	// CP56Time2a (RangeStartTime, RangeStopTime); all zeros is no bound.
	p := iec60870.Params{}.WithDefaults()
	b := unhex(t, "7f 01 0d 00 0700 102700 0300 "+cp56At+" 00000000000000")
	a, err := iec60870.DecodeASDU(b, p, time.UTC)
	if err != nil {
		t.Fatal(err)
	}
	o := a.Objects[0]
	if o.IOA != 10000 || o.File != iec60870.FileEvents || !o.Time.Equal(at) || !o.Stop.IsZero() {
		t.Errorf("%+v", o)
	}
	if back, _ := a.Encode(p, time.UTC); !bytes.Equal(back, b) {
		t.Errorf("re-encoded % x", back)
	}
}
