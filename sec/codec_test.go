package sec

import (
	"bytes"
	"encoding/hex"
	"reflect"
	"testing"
)

func unhex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// Covers: SIG-IPE-1410
func TestTypeIdentifiersAndCauses(t *testing.T) {
	// Table 2 numbers and the TYPE IDENTIFICATION bit patterns of Figures 6 to 20.
	bits := map[uint8]string{
		SAQNA1: "01010001", SAPNA1: "01010010", SUHNA1: "01010011", SUPNA1: "01010100",
		SSINA1: "01010101", SSQNA1: "01010110", SSPNA1: "01010111", SKHNA1: "01011000",
		SKPNA1: "01011001", SSDNA1: "01011011",
	}
	for id, pat := range bits {
		var v uint8
		for _, c := range pat {
			v = v<<1 | uint8(c-'0')
		}
		if v != id {
			t.Errorf("%s: figure pattern %s = %d, constant %d", TypeName(id), pat, v, id)
		}
	}
	if IsSecurityType(90) || IsSecurityType(80) || IsSecurityType(92) {
		t.Error("90, 80 and 92 are not security types")
	}
	// Causes per direction (5.4.3.3 to 5.4.3.13).
	want := []struct {
		id      uint8
		control uint8
		monitor uint8
	}{
		{SAQNA1, 16, 0}, {SAPNA1, 0, 16}, {SUHNA1, 16, 0}, {SUPNA1, 0, 16},
		{SSINA1, 0, 15}, {SSQNA1, 15, 0}, {SSPNA1, 0, 15}, {SKHNA1, 15, 0},
		{SKPNA1, 0, 15}, {SSDNA1, 14, 14},
	}
	for _, w := range want {
		c, ok := PermittedCause(w.id, Control)
		if c != w.control || ok != (w.control != 0) {
			t.Errorf("%s control: %d %v", TypeName(w.id), c, ok)
		}
		m, ok := PermittedCause(w.id, Monitor)
		if m != w.monitor || ok != (w.monitor != 0) {
			t.Errorf("%s monitor: %d %v", TypeName(w.id), m, ok)
		}
	}
	// 5.4.3.2: types 83, 84, 85, 87, 88 and 89 carry a MAC.
	for _, id := range []uint8{83, 84, 85, 87, 88, 89} {
		if !MACProtected(id) {
			t.Errorf("%d should be MAC protected", id)
		}
	}
	for _, id := range []uint8{81, 82, 86} {
		if MACProtected(id) {
			t.Errorf("%d carries no MAC", id)
		}
	}
	// A request in the wrong direction, with the wrong cause or VSQ is refused.
	p := Params104
	a, _ := Encode(DUI{Cause: 16, CA: 7}, p, AssociationRequest{AIM: 1, AIS: 2, PRI: ConformingPRI})
	if _, _, err := Decode(a, p, Monitor); err == nil {
		t.Error("S_AQ_NA_1 in monitor direction accepted")
	}
	bad := bytes.Clone(a)
	bad[2] = 15
	if _, _, err := Decode(bad, p, Control); err == nil {
		t.Error("S_AQ_NA_1 with cause 15 accepted")
	}
	bad = bytes.Clone(a)
	bad[1] = 0x81
	if _, _, err := Decode(bad, p, Control); err == nil {
		t.Error("VSQ other than 1 accepted")
	}
	if _, _, err := Decode(a, p, Control); err != nil {
		t.Error(err)
	}
}

// Covers: SIG-IPE-1411
// Covers: SIG-IPE-1700
func TestMessageLayouts(t *testing.T) {
	p := Params104
	d := DUI{Originator: 0x05, CA: 0x0201}
	cases := []struct {
		name string
		dir  Direction
		m    Message
		obj  string // information object after the DUI
	}{
		{"S_AQ_NA_1", Control, AssociationRequest{AIM: 0x1234, AIS: 0x5678, PRI: ConformingPRI, CertData: []byte{0xC1, 0xC2, 0xC3}},
			"3412" + "7856" + "1000" + "0300" + "c1c2c3"},
		{"S_AP_NA_1", Monitor, AssociationResponse{AIM: 1, AIS: 2, CertData: []byte{0xAA}, Random: []byte{1, 2, 3, 4}},
			"0100" + "0200" + "0100" + "04" + "aa" + "01020304"},
		{"S_UH_NA_1", Control, UpdateKeyChangeRequest{AIM: 1, AIS: 2, KWA: 3, MAL: 4, Random: []byte{9, 9}, MAC: []byte{0xEE, 0xEF}},
			"0100" + "0200" + "03" + "04" + "02" + "0909" + "eeef"},
		{"S_UP_NA_1", Monitor, UpdateKeyChangeResponse{AIM: 1, AIS: 2, MAC: []byte{0xAB}},
			"0100" + "0200" + "ab"},
		{"S_SI_NA_1", Monitor, SessionInitiationRequest{AIM: 1, AIS: 2, Random: []byte{1, 2, 3, 4}, MAC: []byte{0x77}},
			"0100" + "0200" + "04" + "01020304" + "77"},
		{"S_SQ_NA_1", Control, SessionRequest{AIM: 1, AIS: 2, PRI: ProtocolInfo{Major: 1, Broadcast: true}, Random: []byte{5, 6}},
			"0100" + "0200" + "1001" + "02" + "0506"},
		{"S_SP_NA_1", Monitor, SessionResponse{AIM: 1, AIS: 2, Random: []byte{5, 6, 7, 8}, MAC: []byte{0x66}},
			"0100" + "0200" + "04" + "05060708" + "66"},
		{"S_KH_NA_1", Control, SessionKeyChangeRequest{AIM: 1, AIS: 2, DPA: 7, Wrapped: []byte{0xD0, 0xD1}, MAC: []byte{0x55}},
			"0100" + "0200" + "07" + "0200" + "d0d1" + "55"},
		{"S_KP_NA_1", Monitor, SessionKeyChangeResponse{AIM: 1, AIS: 2, MAC: []byte{0x44}},
			"0100" + "0200" + "44"},
		{"S_SD_NA_1", Control, SecureData{AIM: 1, AIS: 2, DSQ: 0x01020304, Rest: []byte{0x02, 0x00, 0xAB, 0xCD}},
			"0100" + "0200" + "04030201" + "0200abcd"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			cause, _ := PermittedCause(c.m.TypeID(), c.dir)
			dd := d
			dd.Cause = cause
			got, err := Encode(dd, p, c.m)
			if err != nil {
				t.Fatal(err)
			}
			want := append([]byte{c.m.TypeID(), 0x01, cause, 0x05, 0x01, 0x02}, unhex(t, c.obj)...)
			if !bytes.Equal(got, want) {
				t.Fatalf("encode\n got %x\nwant %x", got, want)
			}
			gd, gm, err := Decode(got, p, c.dir)
			if err != nil {
				t.Fatal(err)
			}
			if gd.CA != 0x0201 || gd.Originator != 5 || gd.Cause != cause {
				t.Errorf("DUI %+v", gd)
			}
			if !reflect.DeepEqual(normalise(gm), normalise(c.m)) {
				t.Errorf("decode %+v, want %+v", gm, c.m)
			}
			// Messages ending in length-prefixed data refuse truncation (a
			// trailing MAC or payload has no length of its own).
			if id := c.m.TypeID(); id == SAQNA1 || id == SAPNA1 || id == SSQNA1 {
				if _, _, err := Decode(got[:len(got)-1], p, c.dir); err == nil {
					t.Error("truncated message accepted")
				}
				if _, _, err := Decode(append(bytes.Clone(got), 0), p, c.dir); err == nil {
					t.Error("trailing octet accepted")
				}
			}
		})
	}
	// Session Initiation Request limits (5.4.3.8.2 to 5.4.3.8.4).
	if _, err := Encode(DUI{}, p, SessionInitiationRequest{AIM: 1, AIS: 2, Random: []byte{1, 2, 3}}); err == nil {
		t.Error("3 octets of random data accepted")
	}
	if _, err := Encode(DUI{}, p, SessionInitiationRequest{AIM: 1, AIS: 2, Random: make([]byte, 65)}); err == nil {
		t.Error("65 octets of random data accepted")
	}
	if _, err := Encode(DUI{}, p, SessionInitiationRequest{AIM: 0, AIS: 2, Random: make([]byte, 4)}); err == nil {
		t.Error("AIM 0 accepted")
	}
	raw := append([]byte{SSINA1, 1, 15, 0, 1, 0}, unhex(t, "0100"+"0200"+"03"+"010203")...)
	if _, _, err := Decode(raw, p, Monitor); err == nil {
		t.Error("CGL 3 accepted on decode")
	}
	// The association request may carry AIS 0 (IEC 62351-5 8.3.5.2.3).
	aq, err := Encode(DUI{Cause: 16}, p, AssociationRequest{AIM: 7, PRI: ConformingPRI, CertData: []byte{1}})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := Decode(aq, p, Control); err != nil {
		t.Errorf("AIS 0: %v", err)
	}
	// Figure 7: association request PRI is version octet 0x10, reserved 0x00.
	pri, _ := ConformingPRI.encode(false)
	if pri != [2]byte{0x10, 0x00} {
		t.Errorf("PRI %x", pri)
	}
	// 1-octet cause and common address (IEC 101).
	p101 := Params{COTSize: 1, CASize: 1}
	b, _ := Encode(DUI{Cause: 15, CA: 9}, p101, SessionKeyChangeResponse{AIM: 1, AIS: 2, MAC: []byte{1}})
	if !bytes.Equal(b, unhex(t, "59010f09"+"0100"+"0200"+"01")) {
		t.Errorf("101 layout %x", b)
	}
}

func normalise(m Message) Message {
	// Treat nil and empty slices alike for comparison.
	v := reflect.ValueOf(m)
	c := reflect.New(v.Type()).Elem()
	c.Set(v)
	for i := 0; i < c.NumField(); i++ {
		f := c.Field(i)
		if f.Kind() == reflect.Slice && f.Len() == 0 {
			f.Set(reflect.Zero(f.Type()))
		}
	}
	return c.Interface().(Message)
}

// Covers: SIG-IPE-1412
func TestSegmentation(t *testing.T) {
	// Figure 2: FIN bit 8, FIR bit 7, ASN bits 1 to 6.
	if b := (ASC{FIN: true, FIR: true, ASN: 5}).Byte(); b != 0xC5 {
		t.Errorf("ASC %#x", b)
	}
	if a := ParseASC(0x7F); a.FIN || !a.FIR || a.ASN != 63 {
		t.Errorf("ASC %+v", a)
	}
	p := Params104
	dui := DUI{Type: SSDNA1, VSQ: 1, Cause: 14, CA: 3}.Encode(p)
	obj := make([]byte, 25)
	for i := range obj {
		obj[i] = byte(i)
	}
	asdu := append(bytes.Clone(dui), obj...)
	// Room of 10 octets per segment: 7 + ASC + 10 = 18.
	segs, next, err := Segment(asdu, p, 18, 62)
	if err != nil {
		t.Fatal(err)
	}
	if len(segs) != 3 || next != 1 {
		t.Fatalf("%d segments, next ASN %d", len(segs), next)
	}
	wantASC := []byte{0x40 | 62, 63, 0x80 | 0} // ASN 62, 63, then 0 (modulo 64)
	for i, s := range segs {
		if !bytes.Equal(s[:6], dui) {
			t.Errorf("segment %d DUI %x", i, s[:6])
		}
		if s[6] != wantASC[i] {
			t.Errorf("segment %d ASC %#x, want %#x", i, s[6], wantASC[i])
		}
		if len(s) > 18 {
			t.Errorf("segment %d is %d octets", i, len(s))
		}
	}
	r := NewReassembler(p)
	var whole []byte
	for _, s := range segs {
		w, _, err := r.Add(s)
		if err != nil {
			t.Fatal(err)
		}
		if w != nil {
			whole = w
		}
	}
	if !bytes.Equal(whole, asdu) {
		t.Errorf("reassembled %x", whole)
	}
	// Rule 6: a single segment has FIR and FIN.
	one, _, _ := Segment(asdu, p, 249, 0)
	if len(one) != 1 || one[0][6] != 0xC0 {
		t.Errorf("single segment %x", one)
	}
}

// Covers: SIG-IPE-1413
func TestReassemblyTable3(t *testing.T) {
	p := Params{COTSize: 1, CASize: 1}
	dui := []byte{SSDNA1, 1, 14, 5}
	seg := func(fir, fin bool, asn uint8, data ...byte) []byte {
		return append(append(bytes.Clone(dui), ASC{FIR: fir, FIN: fin, ASN: asn}.Byte()), data...)
	}
	type step struct {
		seg   []byte
		event SegmentEvent
		out   []byte
	}
	full := func(data ...byte) []byte { return append(bytes.Clone(dui), data...) }
	other := append([]byte{SSDNA1, 1, 14, 6}, ASC{ASN: 2}.Byte(), 9)
	runs := map[string][]step{
		"row 1 idle, not first":      {{seg(false, true, 4, 1), 1, nil}},
		"row 2 idle, single segment": {{seg(true, true, 9, 1, 2), 2, full(1, 2)}},
		"rows 3, 6, 7":               {{seg(true, false, 1, 1), 3, nil}, {seg(false, false, 2, 2), 6, nil}, {seg(false, true, 3, 3), 7, full(1, 2, 3)}},
		"row 4 duplicate":            {{seg(true, false, 1, 1), 3, nil}, {seg(false, false, 2, 2), 6, nil}, {seg(false, false, 2, 2), 4, nil}, {seg(false, true, 3, 3), 7, full(1, 2, 3)}},
		"row 5 same ASN, different":  {{seg(true, false, 1, 1), 3, nil}, {seg(false, false, 2, 2), 6, nil}, {seg(false, false, 2, 7), 5, nil}, {seg(false, true, 3, 3), 1, nil}},
		"row 8 out of order":         {{seg(true, false, 1, 1), 3, nil}, {seg(false, true, 5, 2), 8, nil}},
		"row 9 new first":            {{seg(true, false, 1, 1), 3, nil}, {seg(true, false, 40, 8), 9, nil}, {seg(false, true, 41, 9), 7, full(8, 9)}},
		"row 10 new single":          {{seg(true, false, 1, 1), 3, nil}, {seg(true, true, 40, 8), 10, full(8)}},
		"row 11 header differs":      {{seg(true, false, 1, 1), 3, nil}, {other, 11, nil}},
		"wrap 63 to 0":               {{seg(true, false, 63, 1), 3, nil}, {seg(false, true, 0, 2), 7, full(1, 2)}},
	}
	wantDiscards := map[string]int{"row 1 idle, not first": 1, "row 5 same ASN, different": 2, "row 8 out of order": 1, "row 9 new first": 1, "row 10 new single": 1, "row 11 header differs": 1}
	for name, steps := range runs {
		t.Run(name, func(t *testing.T) {
			r := NewReassembler(p)
			n := 0
			r.Discarded = func() { n++ }
			for i, s := range steps {
				out, ev, err := r.Add(s.seg)
				if err != nil {
					t.Fatal(err)
				}
				if ev != s.event || !bytes.Equal(out, s.out) {
					t.Fatalf("step %d: event %d out %x, want %d %x", i, ev, out, s.event, s.out)
				}
			}
			if n != wantDiscards[name] {
				t.Errorf("discarded %d, want %d", n, wantDiscards[name])
			}
		})
	}
}

// Covers: SIG-IPE-1411
func TestDecodeNeverPanics(t *testing.T) {
	seed := uint32(1)
	next := func() byte { seed = seed*1664525 + 1013904223; return byte(seed >> 24) }
	for _, p := range []Params{Params104, {COTSize: 1, CASize: 1}} {
		for i := 0; i < 20000; i++ {
			b := make([]byte, int(next())%40)
			for j := range b {
				b[j] = next()
			}
			if len(b) > 0 {
				b[0] = 81 + next()%11
			}
			if len(b) > 1 {
				b[1] = 1
			}
			Decode(b, p, Direction(i%2))
			r := NewReassembler(p)
			r.Add(b)
		}
	}
}
