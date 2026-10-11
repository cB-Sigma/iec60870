// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package statement_test

import (
	"bytes"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/cB-Sigma/iec60870"
	"github.com/cB-Sigma/iec60870/statement"
	"github.com/cB-Sigma/iec60870/station"
)

func demo() *station.Station {
	st := station.New(station.Config{CA: 1, CyclicPeriod: time.Second, Files: &iec60870.FileServer{}})
	st.Add(station.Point{Type: iec60870.MSpTa1, Object: iec60870.Object{IOA: 1}, Groups: []int{2}})
	st.Add(station.Point{Type: iec60870.MItNa1, Object: iec60870.Object{IOA: 2}, CounterGroup: 1})
	st.Add(station.Point{Type: iec60870.MEpTd1, Object: iec60870.Object{IOA: 3}})
	return st
}

// Covers: SIG-IPE-1338
func TestForStation(t *testing.T) {
	s := statement.ForStation(demo(), statement.IEC104, iec60870.Params{})
	if err := s.Validate(); err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		typ   iec60870.TypeID
		cause iec60870.Cause
		want  bool
	}{
		{iec60870.MSpTb1, iec60870.CauseSpontaneous, true}, // the CP24Time2a point goes out as CP56Time2a
		{iec60870.MSpTa1, iec60870.CauseSpontaneous, false},
		{iec60870.MSpNa1, iec60870.CauseInterrogated, true},
		{iec60870.MSpNa1, iec60870.CauseInterrogated + 2, true},
		{iec60870.MSpNa1, iec60870.CauseInterrogated + 3, false},
		{iec60870.MSpNa1, iec60870.CausePeriodic, true},
		{iec60870.MItNa1, iec60870.CauseCounterGen + 1, true},
		{iec60870.MEpTd1, iec60870.CauseInterrogated, false},
		{iec60870.CScTa1, iec60870.CauseActivation, true},
		{iec60870.CTsTa1, iec60870.CauseActivation, true},
		{iec60870.CTsNa1, iec60870.CauseActivation, false},
		{iec60870.FScNb1, iec60870.CauseFile, true},
	} {
		if got := s.Allows(&iec60870.ASDU{Type: c.typ, Cause: c.cause}); got != c.want {
			t.Errorf("%s cause %d: %v, want %v", c.typ, c.cause, got, c.want)
		}
	}
	for _, f := range []string{"group-interrogation", "counter-groups", "cyclic-data", "file-transfer-monitor"} {
		if !s.Offers(f) {
			t.Errorf("function %s not offered", f)
		}
	}
	if s.Offers("delay-acquisition") {
		t.Error("IEC 104 statement offers delay acquisition")
	}
	s101 := statement.ForStation(demo(), statement.IEC101, iec60870.Params{COTSize: 1, CASize: 1, IOASize: 2})
	s101.LinkAddressSize, s101.Transmission = 1, "unbalanced"
	if err := s101.Validate(); err != nil {
		t.Fatal(err)
	}
	if !s101.Allows(&iec60870.ASDU{Type: iec60870.MSpTa1, Cause: iec60870.CauseSpontaneous}) || !s101.Offers("delay-acquisition") {
		t.Error("IEC 101 statement lacks the CP24Time2a type or delay acquisition")
	}
}

// Covers: SIG-IPE-1338
func TestRoundTripAndValidation(t *testing.T) {
	s := statement.ForStation(demo(), statement.IEC104, iec60870.Params{})
	s.K, s.W, s.T1 = 12, 8, 15000
	var b bytes.Buffer
	if err := s.Write(&b); err != nil {
		t.Fatal(err)
	}
	back, err := statement.Read(&b)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(s, back) {
		t.Errorf("round trip changed the statement")
	}
	bad := back
	bad.Add(iec60870.MMeTc1, iec60870.CauseSpontaneous)
	if err := bad.Validate(); err == nil || !strings.Contains(err.Error(), "CP24Time2a") {
		t.Errorf("CP24Time2a type in an IEC 104 statement: %v", err)
	}
	bad = statement.Statement{Standard: statement.IEC101, Role: statement.Controlling, COTSize: 1, CASize: 1, IOASize: 2,
		Transmission: "unbalanced"}
	if err := bad.Validate(); err == nil {
		t.Error("an unbalanced line without link address was accepted")
	}
	bad.LinkAddressSize = 1
	bad.Functions = []string{"teleportation"}
	if err := bad.Validate(); err == nil {
		t.Error("an unknown function was accepted")
	}
	if _, err := statement.Read(strings.NewReader(`{"standard":"IEC 60870-5-104","role":"controlled","cotSize":2,"caSize":2,"ioaSize":3,"extra":1}`)); err == nil {
		t.Error("an unknown field was accepted")
	}
}
