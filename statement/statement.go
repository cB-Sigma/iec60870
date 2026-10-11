// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

// Package statement holds an interoperability statement (IEC 60870-5-101
// clause 8, IEC 60870-5-104 clause 9) as data: the type identifications a
// station uses with their causes of transmission, the basic application
// functions it offers, and its field sizes and link parameters. A
// statement is written to and read from JSON, filled in from a
// station.Station's configuration, and checks received ASDUs against what
// it declares (Allows), so a statement can also drive what a station or a
// controlling station accepts.
//
// The package models the statement; which types and causes the standards
// permit for each direction is in the standards themselves and is not
// reproduced here.
package statement

import (
	"encoding/json"
	"fmt"
	"io"
	"slices"
	"sort"

	"github.com/cB-Sigma/iec60870"
	"github.com/cB-Sigma/iec60870/station"
)

// Standards a statement is for.
const (
	IEC104 = "IEC 60870-5-104"
	IEC101 = "IEC 60870-5-101"
)

// Roles.
const (
	Controlled  = "controlled"
	Controlling = "controlling"
)

// Functions are the names of the basic application functions a statement
// lists (our names for the function groups of the statements).
var Functions = []string{
	"station-initialisation", "cyclic-data", "read", "spontaneous", "station-interrogation", "group-interrogation",
	"clock-synchronisation", "command-direct", "command-select-execute", "command-short-pulse", "command-long-pulse",
	"command-persistent", "command-max-delay", "counter-read", "counter-freeze", "counter-freeze-reset", "counter-reset",
	"counter-general", "counter-groups", "parameter-loading", "parameter-activation", "test", "file-transfer-monitor",
	"file-transfer-control", "background-scan", "delay-acquisition",
}

// TypeUse is one type identification with the causes it is used with.
type TypeUse struct {
	Type   iec60870.TypeID  `json:"type"`
	Name   string           `json:"name"`
	Causes []iec60870.Cause `json:"causes"`
}

// Statement is an interoperability statement.
type Statement struct {
	Standard string `json:"standard"`
	Role     string `json:"role"`
	// Field sizes: cause of transmission (1 or 2), common address (1 or
	// 2), information object address (1 to 3); IEC 101 also the link
	// address (0 to 2) and the transmission (balanced or unbalanced).
	COTSize         int    `json:"cotSize"`
	CASize          int    `json:"caSize"`
	IOASize         int    `json:"ioaSize"`
	LinkAddressSize int    `json:"linkAddressSize,omitempty"`
	Transmission    string `json:"transmission,omitempty"`
	// IEC 104 link parameters (milliseconds for the timeouts).
	K  int `json:"k,omitempty"`
	W  int `json:"w,omitempty"`
	T0 int `json:"t0,omitempty"`
	T1 int `json:"t1,omitempty"`
	T2 int `json:"t2,omitempty"`
	T3 int `json:"t3,omitempty"`
	// Types are the type identifications used, by number.
	Types []TypeUse `json:"types"`
	// Functions are the basic application functions offered (names from
	// Functions).
	Functions []string `json:"functions"`
}

// Add declares type t with causes (merged with those already declared).
func (s *Statement) Add(t iec60870.TypeID, causes ...iec60870.Cause) {
	for i := range s.Types {
		if s.Types[i].Type == t {
			for _, c := range causes {
				if !slices.Contains(s.Types[i].Causes, c) {
					s.Types[i].Causes = append(s.Types[i].Causes, c)
				}
			}
			slices.Sort(s.Types[i].Causes)
			return
		}
	}
	cs := append([]iec60870.Cause(nil), causes...)
	slices.Sort(cs)
	cs = slices.Compact(cs)
	s.Types = append(s.Types, TypeUse{Type: t, Name: t.String(), Causes: cs})
	sort.Slice(s.Types, func(i, j int) bool { return s.Types[i].Type < s.Types[j].Type })
}

// Offer declares basic application functions.
func (s *Statement) Offer(names ...string) {
	for _, n := range names {
		if !slices.Contains(s.Functions, n) {
			s.Functions = append(s.Functions, n)
		}
	}
	sort.Strings(s.Functions)
}

// Offers reports whether the statement lists function name.
func (s Statement) Offers(name string) bool { return slices.Contains(s.Functions, name) }

// Allows reports whether the statement declares a's type with a's cause.
func (s Statement) Allows(a *iec60870.ASDU) bool {
	for _, u := range s.Types {
		if u.Type == a.Type {
			return slices.Contains(u.Causes, a.Cause)
		}
	}
	return false
}

// Validate checks the sizes, role, standard and function names, and that
// an IEC 104 statement declares no CP24Time2a type.
func (s Statement) Validate() error {
	if s.Standard != IEC104 && s.Standard != IEC101 {
		return fmt.Errorf("standard %q is neither %q nor %q", s.Standard, IEC104, IEC101)
	}
	if s.Role != Controlled && s.Role != Controlling {
		return fmt.Errorf("role %q is neither %q nor %q", s.Role, Controlled, Controlling)
	}
	if err := (iec60870.Params{COTSize: s.COTSize, CASize: s.CASize, IOASize: s.IOASize}).Validate(); err != nil {
		return err
	}
	if s.Standard == IEC101 {
		if s.LinkAddressSize < 0 || s.LinkAddressSize > 2 {
			return fmt.Errorf("link address size %d is not 0 to 2", s.LinkAddressSize)
		}
		if s.Transmission != "balanced" && s.Transmission != "unbalanced" {
			return fmt.Errorf("transmission %q is neither balanced nor unbalanced", s.Transmission)
		}
		if s.LinkAddressSize == 0 && s.Transmission == "unbalanced" {
			return fmt.Errorf("an unbalanced line needs a link address")
		}
	}
	for _, u := range s.Types {
		if s.Standard == IEC104 && u.Type.CP24() {
			return fmt.Errorf("%s carries CP24Time2a, which IEC 104 does not use", u.Type)
		}
		if len(u.Causes) == 0 {
			return fmt.Errorf("%s has no cause of transmission", u.Type)
		}
	}
	for _, f := range s.Functions {
		if !slices.Contains(Functions, f) {
			return fmt.Errorf("unknown function %q", f)
		}
	}
	return nil
}

// Write writes the statement as indented JSON.
func (s Statement) Write(w io.Writer) error {
	e := json.NewEncoder(w)
	e.SetIndent("", "  ")
	return e.Encode(s)
}

// Read reads a statement written by Write and validates it.
func Read(r io.Reader) (Statement, error) {
	var s Statement
	d := json.NewDecoder(r)
	d.DisallowUnknownFields()
	if err := d.Decode(&s); err != nil {
		return Statement{}, err
	}
	for i := range s.Types {
		s.Types[i].Name = s.Types[i].Type.String()
	}
	return s, s.Validate()
}

// ForStation fills in a controlled station's statement from its
// configuration: the monitor types of its points with the causes it sends
// them with (spontaneous, interrogated by station and by its groups,
// request, return information, periodic and background when configured),
// its command types with activation, deactivation and their answers, and
// the system types it answers. prm are the session's field sizes.
func ForStation(st *station.Station, standard string, prm iec60870.Params) Statement {
	prm = prm.WithDefaults()
	s := Statement{Standard: standard, Role: Controlled, COTSize: prm.COTSize, CASize: prm.CASize, IOASize: prm.IOASize}
	cfg := st.Config()
	refusals := []iec60870.Cause{iec60870.CauseUnknownType, iec60870.CauseUnknownCause, iec60870.CauseUnknownCA, iec60870.CauseUnknownObject}
	conv := func(t iec60870.TypeID) iec60870.TypeID {
		if standard == IEC104 {
			return station.CP56(t)
		}
		return t
	}
	s.Offer("station-initialisation", "read", "spontaneous", "station-interrogation", "clock-synchronisation", "test",
		"counter-read", "counter-freeze", "counter-freeze-reset", "counter-reset", "counter-general", "parameter-loading",
		"parameter-activation", "command-direct", "command-select-execute")
	if cfg.MaxCommandDelay > 0 {
		s.Offer("command-max-delay")
	}
	if cfg.CyclicPeriod > 0 {
		s.Offer("cyclic-data")
	}
	if cfg.BackgroundPeriod > 0 {
		s.Offer("background-scan")
	}
	if standard == IEC101 {
		s.Offer("delay-acquisition")
	}
	for _, x := range st.Sectors() {
		for _, p := range x.Points() {
			t := conv(p.Type)
			counter := station.Untagged(p.Type) == iec60870.MItNa1
			event := t >= iec60870.MEpTa1 && t <= iec60870.MEpTc1 || t >= iec60870.MEpTd1 && t <= iec60870.MEpTf1
			s.Add(t, iec60870.CauseSpontaneous)
			switch {
			case counter:
				cs := []iec60870.Cause{iec60870.CauseCounterGen}
				if p.CounterGroup > 0 {
					cs = append(cs, iec60870.CauseCounterGen+iec60870.Cause(p.CounterGroup))
					s.Offer("counter-groups")
				}
				s.Add(t, cs...)
			case event:
			default:
				s.Add(t, iec60870.CauseRequest, iec60870.CauseReturnRemote, iec60870.CauseReturnLocal)
				u := station.Untagged(p.Type)
				gi := []iec60870.Cause{iec60870.CauseInterrogated}
				for _, g := range p.Groups {
					gi = append(gi, iec60870.CauseInterrogated+iec60870.Cause(g))
					s.Offer("group-interrogation")
				}
				if cfg.CyclicPeriod > 0 {
					gi = append(gi, iec60870.CausePeriodic)
				}
				if cfg.BackgroundPeriod > 0 {
					gi = append(gi, iec60870.CauseBackground)
				}
				s.Add(u, gi...)
			}
		}
	}
	answers := append([]iec60870.Cause{iec60870.CauseActivation, iec60870.CauseActCon, iec60870.CauseDeactivation,
		iec60870.CauseDeactCon, iec60870.CauseActTerm}, refusals...)
	for _, t := range []iec60870.TypeID{iec60870.CScNa1, iec60870.CDcNa1, iec60870.CRcNa1, iec60870.CSeNa1, iec60870.CSeNb1,
		iec60870.CSeNc1, iec60870.CBoNa1} {
		s.Add(t, answers...)
		if standard == IEC104 {
			s.Add(t+13, answers...) // the CP56Time2a twins, 58 to 64
		}
	}
	s.Add(iec60870.MEiNa1, iec60870.CauseInitialised)
	s.Add(iec60870.CIcNa1, answers...)
	s.Add(iec60870.CCiNa1, append([]iec60870.Cause{iec60870.CauseActivation, iec60870.CauseActCon, iec60870.CauseActTerm}, refusals...)...)
	s.Add(iec60870.CRdNa1, append([]iec60870.Cause{iec60870.CauseRequest}, refusals...)...)
	s.Add(iec60870.CCsNa1, append([]iec60870.Cause{iec60870.CauseActivation, iec60870.CauseActCon}, refusals...)...)
	s.Add(iec60870.CRpNa1, append([]iec60870.Cause{iec60870.CauseActivation, iec60870.CauseActCon}, refusals...)...)
	params := append([]iec60870.Cause{iec60870.CauseActivation, iec60870.CauseActCon}, refusals...)
	s.Add(iec60870.PMeNa1, params...)
	s.Add(iec60870.PMeNb1, params...)
	s.Add(iec60870.PMeNc1, params...)
	s.Add(iec60870.PAcNa1, append(params, iec60870.CauseDeactivation, iec60870.CauseDeactCon)...)
	if standard == IEC104 {
		s.Add(iec60870.CTsTa1, append([]iec60870.Cause{iec60870.CauseActivation, iec60870.CauseActCon}, refusals...)...)
	} else {
		s.Add(iec60870.CTsNa1, append([]iec60870.Cause{iec60870.CauseActivation, iec60870.CauseActCon}, refusals...)...)
		s.Add(iec60870.CCdNa1, append([]iec60870.Cause{iec60870.CauseActivation, iec60870.CauseActCon, iec60870.CauseSpontaneous}, refusals...)...)
	}
	if cfg.Files != nil {
		s.Offer("file-transfer-monitor", "file-transfer-control")
		for t := iec60870.FFrNa1; t <= iec60870.FDrTa1; t++ {
			s.Add(t, iec60870.CauseFile)
		}
		s.Add(iec60870.FScNa1, iec60870.CauseRequest)
		s.Add(iec60870.FDrTa1, iec60870.CauseRequest, iec60870.CauseSpontaneous)
		if standard == IEC104 {
			s.Add(iec60870.FScNb1, iec60870.CauseFile, iec60870.CauseRequest)
		}
	}
	return s
}
