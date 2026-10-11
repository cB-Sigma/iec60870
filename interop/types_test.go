// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package interop

import (
	"context"
	"encoding/hex"
	"fmt"
	"math"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/cB-Sigma/iec60870"
	"github.com/cB-Sigma/iec60870/cs104"
)

// stamp is the time tag the tests send: 2026-10-11 13:45:56.789 UTC, a
// Sunday.
var stamp = time.Date(2026, 10, 11, 13, 45, 56, 789e6, time.UTC)

// cp56Hex is a CP56Time2a in hex as the peer takes it (t=...), with the
// IV, SU and RES1 bits set as asked.
func cp56Hex(t time.Time, iv, su, sub bool) string {
	b := iec60870.CP56(t, iv, time.UTC)
	if su {
		b[3] |= 0x80
	}
	if sub {
		b[2] |= 0x40
	}
	return hex.EncodeToString(b)
}

// monitorCase is one information object the peer sends and what our
// decoder must make of it.
type monitorCase struct {
	typ  iec60870.TypeID
	args string // send arguments besides type, ioa and t
	want iec60870.Object
	iv   bool // time tag IV
	sub  bool // time tag RES1 (substituted)
}

// monitorCases covers every monitor type of IEC 60870-5-101 Tables 8 to
// 10 and 12 (1 to 21, 30 to 40) and M_EI_NA_1, with values, quality bits
// and time tag flags chosen to exercise each field.
var monitorCases = []monitorCase{
	{typ: iec60870.MSpNa1, args: "v=1 q=0xc0", want: iec60870.Object{Value: 1, Quality: 0xc0}},
	{typ: iec60870.MSpTa1, args: "v=0 q=0x20", want: iec60870.Object{Value: 0, Quality: 0x20}, iv: true},
	{typ: iec60870.MDpNa1, args: "v=2 q=0x10", want: iec60870.Object{Value: 2, Quality: 0x10}},
	{typ: iec60870.MDpTa1, args: "v=1 q=0", want: iec60870.Object{Value: 1}, sub: true},
	{typ: iec60870.MStNa1, args: "v=-5 tr=1 q=0x81", want: iec60870.Object{Value: -5, Transient: true, Quality: 0x81}},
	{typ: iec60870.MStTa1, args: "v=63 tr=0 q=0x20", want: iec60870.Object{Value: 63, Quality: 0x20}},
	{typ: iec60870.MBoNa1, args: "v=3735928559 q=0x10", want: iec60870.Object{Value: 0xdeadbeef, Quality: 0x10}},
	{typ: iec60870.MBoTa1, args: "v=1 q=0x01", want: iec60870.Object{Value: 1, Quality: 0x01}},
	{typ: iec60870.MMeNa1, args: "v=-0.5 q=0x01", want: iec60870.Object{Value: -0.5, Quality: 0x01}},
	{typ: iec60870.MMeTa1, args: "v=0.25 q=0x80", want: iec60870.Object{Value: 0.25, Quality: 0x80}, iv: true, sub: true},
	{typ: iec60870.MMeNb1, args: "v=-1234 q=0x40", want: iec60870.Object{Value: -1234, Quality: 0x40}},
	{typ: iec60870.MMeTb1, args: "v=32767 q=0", want: iec60870.Object{Value: 32767}},
	{typ: iec60870.MMeNc1, args: "v=-12.75 q=0x21", want: iec60870.Object{Value: -12.75, Quality: 0x21}},
	{typ: iec60870.MMeTc1, args: "v=1000000 q=0", want: iec60870.Object{Value: 1e6}},
	{typ: iec60870.MItNa1, args: "v=-100000 seq=7 q=0x86", want: iec60870.Object{Value: -100000, Seq: 7,
		Quality: iec60870.QCarry | iec60870.QAdjusted | iec60870.QInvalid}},
	{typ: iec60870.MItTa1, args: "v=42 seq=31 q=0", want: iec60870.Object{Value: 42, Seq: 31}},
	{typ: iec60870.MEpTa1, args: "v=2 q=0x88 el=12345", want: iec60870.Object{Value: 2, Quality: 0x88, Elapsed: 12345 * time.Millisecond}},
	{typ: iec60870.MEpTb1, args: "v=63 q=0x10 el=59999", want: iec60870.Object{Value: 63, Quality: 0x10, Elapsed: 59999 * time.Millisecond}},
	{typ: iec60870.MEpTc1, args: "v=15 q=0x40 el=0", want: iec60870.Object{Value: 15, Quality: 0x40}},
	{typ: iec60870.MPsNa1, args: "v=42330 cd=3855 q=0x10", want: iec60870.Object{Value: 0xa55a, Change: 0x0f0f, Quality: 0x10}},
	{typ: iec60870.MMeNd1, args: "v=0.125", want: iec60870.Object{Value: 0.125}},
	{typ: iec60870.MSpTb1, args: "v=1 q=0x10", want: iec60870.Object{Value: 1, Quality: 0x10}, sub: true},
	{typ: iec60870.MDpTb1, args: "v=3 q=0x80", want: iec60870.Object{Value: 3, Quality: 0x80}, iv: true},
	{typ: iec60870.MStTb1, args: "v=-64 tr=1 q=0", want: iec60870.Object{Value: -64, Transient: true}},
	{typ: iec60870.MBoTb1, args: "v=65535 q=0x20", want: iec60870.Object{Value: 65535, Quality: 0x20}},
	{typ: iec60870.MMeTd1, args: "v=-1 q=0x01", want: iec60870.Object{Value: -1, Quality: 0x01}},
	{typ: iec60870.MMeTe1, args: "v=-32768 q=0x40", want: iec60870.Object{Value: -32768, Quality: 0x40}},
	{typ: iec60870.MMeTf1, args: "v=230.5 q=0", want: iec60870.Object{Value: 230.5}, iv: true, sub: true},
	{typ: iec60870.MItTb1, args: "v=2147483647 seq=1 q=0x02", want: iec60870.Object{Value: math.MaxInt32, Seq: 1, Quality: iec60870.QCarry}},
	{typ: iec60870.MEpTd1, args: "v=1 q=0x08 el=1", want: iec60870.Object{Value: 1, Quality: 0x08, Elapsed: time.Millisecond}},
	{typ: iec60870.MEpTe1, args: "v=33 q=0xc0 el=500", want: iec60870.Object{Value: 33, Quality: 0xc0, Elapsed: 500 * time.Millisecond}},
	{typ: iec60870.MEpTf1, args: "v=9 q=0 el=60", want: iec60870.Object{Value: 9, Elapsed: 60 * time.Millisecond}},
}

// checkMonitor compares a decoded object with the case, field by field.
func checkMonitor(t *testing.T, c monitorCase, o iec60870.Object, sent time.Time) {
	t.Helper()
	w := c.want
	if o.Value != w.Value || o.Quality != w.Quality || o.Seq != w.Seq || o.Transient != w.Transient ||
		o.Elapsed != w.Elapsed || o.Change != w.Change {
		t.Errorf("%s: got value %v quality %#x seq %d transient %v elapsed %s change %#x; want %v %#x %d %v %s %#x",
			c.typ, o.Value, o.Quality, o.Seq, o.Transient, o.Elapsed, o.Change, w.Value, w.Quality, w.Seq, w.Transient, w.Elapsed, w.Change)
	}
	if !c.typ.TimeTagged() {
		return
	}
	if o.TimeInvalid != c.iv || o.TimeSubstituted != c.sub {
		t.Errorf("%s: time IV %v RES1 %v, want %v %v", c.typ, o.TimeInvalid, o.TimeSubstituted, c.iv, c.sub)
	}
	if c.typ.CP24() {
		// CP24Time2a carries the minute and milliseconds only.
		if o.Time.Minute() != sent.Minute() || o.Time.Second() != sent.Second() || o.Time.Nanosecond() != sent.Nanosecond() {
			t.Errorf("%s: time %s, sent minute/ms of %s", c.typ, o.Time, sent)
		}
		return
	}
	if !o.Time.Equal(sent) {
		t.Errorf("%s: time %s, sent %s", c.typ, o.Time.UTC(), sent)
	}
}

// startServer runs the peer as IEC 104 controlled station and connects a
// Client to it.
func startServer(t *testing.T, args ...string) (*peer, *cs104.Client, *collector) {
	t.Helper()
	return startServerLoc(t, time.UTC, args...)
}

// startServerLoc is startServer with the client's time zone.
func startServerLoc(t *testing.T, loc *time.Location, args ...string) (*peer, *cs104.Client, *collector) {
	t.Helper()
	port := freePort(t)
	p := startPeer(t, append([]string{"-p", fmt.Sprintf("127.0.0.1:%d:2404", port), image, "peer", "server104"}, args...)...)
	p.expect(60*time.Second, "READY")
	l := dialPeer(t, fmt.Sprintf("127.0.0.1:%d", port), cs104.LinkConfig{})
	got := &collector{}
	return p, cs104.NewClient(l, cs104.ClientConfig{CA: 1, Loc: loc, OnData: got.add}), got
}

// TestMonitorTypesFromLib60870: lib60870 encodes each monitor type
// (spontaneous, one object) and our decoder reads every field.
func TestMonitorTypesFromLib60870(t *testing.T) {
	needDocker(t)
	p, _, got := startServer(t)
	for i, c := range monitorCases {
		ioa := uint32(1000 + i)
		p.send(fmt.Sprintf("send type=%d ioa=%d %s t=%s", c.typ, ioa, c.args, cp56Hex(stamp, c.iv, false, c.sub)))
		o := got.find(t, c.typ, iec60870.CauseSpontaneous, ioa, 5*time.Second)
		checkMonitor(t, c, o, stamp)
	}
	t.Run("end of initialisation", func(t *testing.T) {
		p.send("send type=70 ioa=0 v=130 cot=4")
		if o := got.find(t, iec60870.MEiNa1, iec60870.CauseInitialised, 0, 5*time.Second); o.Value != 130 {
			t.Errorf("COI %v, want 130", o.Value)
		}
	})
	t.Run("sequences (SQ=1)", func(t *testing.T) {
		p.send("send type=1 ioa=3000 v=1 q=0x10 sq=1 n=5")
		for i := uint32(0); i < 5; i++ {
			if o := got.find(t, iec60870.MSpNa1, iec60870.CauseSpontaneous, 3000+i, 5*time.Second); o.Value != 1 || o.Quality != 0x10 {
				t.Errorf("element %d: %+v", i, o)
			}
		}
		p.send("send type=13 ioa=3100 v=1.5 sq=1 n=40")
		got.find(t, iec60870.MMeNc1, iec60870.CauseSpontaneous, 3139, 5*time.Second)
		// Packed single points: lib60870 numbers the objects of a sequence
		// one apart; Amendment 1 (our default) reads them 16 apart, and
		// Params.PackedStep 1 reads them as lib60870 means them.
		p.send("send type=20 ioa=3200 v=1 cd=1 sq=1 n=3")
		got.find(t, iec60870.MPsNa1, iec60870.CauseSpontaneous, 3232, 5*time.Second)
		raw, _ := (&iec60870.ASDU{Type: iec60870.MPsNa1, SQ: true, Cause: iec60870.CauseSpontaneous, CA: 1,
			Objects: []iec60870.Object{{IOA: 3200, Value: 1}, {Value: 1}, {Value: 1}}}).Encode(iec60870.Params{}.WithDefaults(), time.UTC)
		one := iec60870.Params{PackedStep: 1}.WithDefaults()
		if a, err := iec60870.DecodeASDU(raw, one, time.UTC); err != nil || a.Objects[2].IOA != 3202 {
			t.Errorf("PackedStep 1: %v %v", a, err)
		}
	})
	t.Run("summer time in a zone that observes it", func(t *testing.T) {
		// 12:00 wall time, SU set: 10:00 UTC in Berlin's summer; SU clear in
		// winter: 11:00 UTC.
		berlin, err := time.LoadLocation("Europe/Berlin")
		if err != nil {
			t.Skip(err)
		}
		summer := time.Date(2026, 7, 1, 12, 0, 0, 0, berlin)
		winter := time.Date(2026, 1, 1, 12, 0, 0, 0, berlin)
		raw := func(w time.Time, su bool) string {
			b := iec60870.CP56(time.Date(w.Year(), w.Month(), w.Day(), w.Hour(), 0, 0, 0, time.UTC), false, time.UTC)
			if su {
				b[3] |= 0x80
			}
			return hex.EncodeToString(b)
		}
		pb, _, gotB := startServerLoc(t, berlin)
		pb.send("send type=30 ioa=3300 v=1 t=" + raw(summer, true))
		pb.send("send type=30 ioa=3301 v=1 t=" + raw(winter, false))
		if o := gotB.find(t, iec60870.MSpTb1, iec60870.CauseSpontaneous, 3300, 5*time.Second); !o.Time.Equal(summer) {
			t.Errorf("summer: %s, want %s", o.Time, summer)
		}
		if o := gotB.find(t, iec60870.MSpTb1, iec60870.CauseSpontaneous, 3301, 5*time.Second); !o.Time.Equal(winter) {
			t.Errorf("winter: %s, want %s", o.Time, winter)
		}
	})
}

// cmdCase is a command we send and what the peer must read.
type cmdCase struct {
	typ   iec60870.TypeID
	obj   iec60870.Object
	value string // the peer's value= field
}

var commandCases = []cmdCase{
	{iec60870.CScNa1, iec60870.Object{IOA: 5100, Value: 1, Qualifier: iec60870.QUPersistent}, "1"},
	{iec60870.CDcNa1, iec60870.Object{IOA: 5101, Value: 2, Qualifier: iec60870.QUShortPulse}, "2"},
	{iec60870.CRcNa1, iec60870.Object{IOA: 5102, Value: 2, Qualifier: iec60870.QULongPulse}, "2"},
	{iec60870.CSeNa1, iec60870.Object{IOA: 5103, Value: -0.25, Qualifier: 5}, "-0.25"},
	{iec60870.CSeNb1, iec60870.Object{IOA: 5104, Value: -300}, "-300"},
	{iec60870.CSeNc1, iec60870.Object{IOA: 5105, Value: 12.5, Qualifier: 17}, "12.5"},
	{iec60870.CBoNa1, iec60870.Object{IOA: 5106, Value: 0x12345678}, "305419896"},
	{iec60870.CScTa1, iec60870.Object{IOA: 5107, Value: 0, Qualifier: iec60870.QUShortPulse}, "0"},
	{iec60870.CDcTa1, iec60870.Object{IOA: 5108, Value: 1}, "1"},
	{iec60870.CRcTa1, iec60870.Object{IOA: 5109, Value: 1, Qualifier: iec60870.QUPersistent}, "1"},
	{iec60870.CSeTa1, iec60870.Object{IOA: 5110, Value: 0.5, Qualifier: 1}, "0.5"},
	{iec60870.CSeTb1, iec60870.Object{IOA: 5111, Value: 32767}, "32767"},
	{iec60870.CSeTc1, iec60870.Object{IOA: 5112, Value: -1e-3}, "-0.001000000047"},
	{iec60870.CBoTa1, iec60870.Object{IOA: 5113, Value: 0xffffffff}, "4294967295"},
}

// tf is the peer's tf= field for t as we encode it (time.UTC).
func tf(t time.Time, iv, su, sub bool) string {
	b2i := func(b bool) int {
		if b {
			return 1
		}
		return 0
	}
	wd := int(t.Weekday())
	if wd == 0 {
		wd = 7
	}
	return fmt.Sprintf("%d,%d,%d,%d,%d,%d,%d,%d,%d,%d", t.Second()*1000+t.Nanosecond()/1e6, t.Minute(), t.Hour(), t.Day(), wd,
		int(t.Month()), t.Year()%100, b2i(iv), b2i(su), b2i(sub))
}

// checkCommandLine compares the peer's reading of a command.
func checkCommandLine(t *testing.T, c cmdCase, line string, sel bool) {
	t.Helper()
	f := kv(line)
	selWant := "0"
	if sel {
		selWant = "1"
	}
	quWant := strconv.Itoa(int(c.obj.Qualifier))
	switch c.typ {
	case iec60870.CBoNa1, iec60870.CBoTa1:
		selWant, quWant = "-1", "-1"
	}
	if f["value"] != c.value || f["select"] != selWant || f["qu"] != quWant {
		t.Errorf("%s: peer read value=%s select=%s qu=%s, want %s %s %s", c.typ, f["value"], f["select"], f["qu"], c.value, selWant, quWant)
	}
	if c.typ.TimeTagged() && f["tf"] != tf(stamp, false, false, false) {
		t.Errorf("%s: peer read time %s, want %s", c.typ, f["tf"], tf(stamp, false, false, false))
	}
}

// TestCommandsToLib60870: every command type, with and without
// CP56Time2a, as direct execute and select-before-operate, read field by
// field by lib60870 (which confirms and terminates them).
func TestCommandsToLib60870(t *testing.T) {
	needDocker(t)
	p, c, _ := startServer(t)
	ctx := context.Background()
	now := func() time.Time { return stamp }
	for _, x := range commandCases {
		t.Run(x.typ.String(), func(t *testing.T) {
			p.drain()
			sbo := x.typ != iec60870.CBoNa1 && x.typ != iec60870.CBoTa1
			_, err := c.Operate(ctx, iec60870.Operation{Type: x.typ, Object: x.obj, SelectBeforeOperate: sbo,
				TimeTag: x.typ.TimeTagged(), Now: now, Termination: 5 * time.Second})
			if err != nil {
				t.Fatal(err)
			}
			if sbo {
				checkCommandLine(t, x, p.expect(5*time.Second, fmt.Sprintf("type=%d ", x.typ), "cot=6 ", "select=1"), true)
			}
			checkCommandLine(t, x, p.expect(5*time.Second, fmt.Sprintf("type=%d ", x.typ), "cot=6 ", "select="), false)
		})
	}
	t.Run("deactivation of a select", func(t *testing.T) {
		sel, err := c.Operate(ctx, iec60870.Operation{Type: iec60870.CScNa1, Object: iec60870.Object{IOA: 5200, Value: 1}, SelectOnly: true})
		if err != nil {
			t.Fatal(err)
		}
		if err := c.Cancel(ctx, iec60870.CScNa1, sel, false); err != nil {
			t.Fatal(err)
		}
		p.expect(5*time.Second, "type=45 ", "cot=8 ", "ioa=5200", "select=1")
	})
	t.Run("unknown object is refused", func(t *testing.T) {
		if _, err := c.Operate(ctx, iec60870.Operation{Type: iec60870.CSeTc1, Object: iec60870.Object{IOA: 4999, Value: 1},
			TimeTag: true}); err == nil || !strings.Contains(err.Error(), "unknown information object address") {
			t.Errorf("refusal = %v", err)
		}
	})
}

// TestSystemCommandsToLib60870: interrogation of a group, counter
// interrogation, read, reset process, test with time tag, delay
// acquisition, parameter loading and activation, against lib60870's
// handlers.
func TestSystemCommandsToLib60870(t *testing.T) {
	needDocker(t)
	p, c, got := startServer(t)
	ctx := context.Background()
	t.Run("group interrogation", func(t *testing.T) {
		if err := c.Interrogate(ctx, iec60870.QOIGroup(1), 5*time.Second); err != nil {
			t.Fatal(err)
		}
		p.expect(5*time.Second, "GI qoi=21")
	})
	t.Run("counter interrogation", func(t *testing.T) {
		if err := c.CounterInterrogate(ctx, iec60870.QCC(iec60870.RQTGeneral, iec60870.FRZRead), 5*time.Second); err != nil {
			t.Fatal(err)
		}
		p.expect(5*time.Second, "CI qcc=5")
		o := got.find(t, iec60870.MItNa1, iec60870.CauseCounterGen, 400, time.Second)
		if o.Value != 123456 || o.Seq != 5 || o.Quality != iec60870.QAdjusted {
			t.Errorf("counter: %+v", o)
		}
	})
	t.Run("read", func(t *testing.T) {
		a, err := iec60870.Read(ctx, c, 100, 5*time.Second)
		if err != nil {
			t.Fatal(err)
		}
		if a.Type != iec60870.MSpNa1 || a.Objects[0].Value != 1 {
			t.Errorf("read answered %s %+v", a, a.Objects)
		}
		if _, err := iec60870.Read(ctx, c, 101, 5*time.Second); err == nil {
			t.Error("the read of an unknown object succeeded")
		}
	})
	t.Run("reset process", func(t *testing.T) {
		if err := c.ResetProcess(ctx, iec60870.QRPGeneral); err != nil {
			t.Fatal(err)
		}
		p.expect(5*time.Second, "RESET qrp=1")
		if err := c.ResetProcess(ctx, 9); err == nil {
			t.Error("a refused reset succeeded")
		}
	})
	t.Run("test command with time tag", func(t *testing.T) {
		if err := c.Test(ctx, 0x1234, time.Now()); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("delay acquisition", func(t *testing.T) {
		if _, err := iec60870.DelayAcquisition(ctx, c, 5*time.Second); err != nil {
			t.Fatal(err)
		}
		p.expect(5*time.Second, "DELAY cot=6")
		p.expect(5*time.Second, "DELAY cot=3")
	})
	t.Run("parameters", func(t *testing.T) {
		for _, x := range []struct {
			typ   iec60870.TypeID
			v     float64
			value string
		}{{iec60870.PMeNa1, 0.75, "0.75"}, {iec60870.PMeNb1, -77, "-77"}, {iec60870.PMeNc1, 2.5, "2.5"}} {
			if err := c.Request(ctx, iec60870.Request{Type: x.typ, Cause: iec60870.CauseActivation,
				Object: iec60870.Object{IOA: 6000, Value: x.v, Qualifier: iec60870.KPAThreshold}}); err != nil {
				t.Fatal(err)
			}
			f := kv(p.expect(5*time.Second, fmt.Sprintf("type=%d ", x.typ), "ioa=6000"))
			if f["value"] != x.value || f["qu"] != "1" {
				t.Errorf("%s: peer read value=%s qpm=%s", x.typ, f["value"], f["qu"])
			}
		}
		if err := c.Request(ctx, iec60870.Request{Type: iec60870.PAcNa1, Cause: iec60870.CauseActivation,
			Object: iec60870.Object{IOA: 6000, Qualifier: iec60870.QPACyclic}}); err != nil {
			t.Fatal(err)
		}
		if f := kv(p.expect(5*time.Second, "type=113 ", "ioa=6000")); f["qu"] != "3" {
			t.Errorf("QPA %s", f["qu"])
		}
	})
}

// TestClockSyncEdgesToLib60870: the CP56Time2a of clock synchronisation
// read by lib60870 field by field at year, month and millisecond
// boundaries, the day of week, and a negative confirmation.
func TestClockSyncEdgesToLib60870(t *testing.T) {
	needDocker(t)
	p, c, _ := startServer(t)
	ctx := context.Background()
	for _, x := range []time.Time{
		time.Date(2099, 12, 31, 23, 59, 59, 999e6, time.UTC), // last millisecond of the century
		time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC),          // first of the century (a Saturday)
		time.Date(2026, 2, 28, 23, 59, 59, 999e6, time.UTC),
		time.Date(2028, 2, 29, 12, 0, 0, 1e6, time.UTC), // leap day
		stamp, // a Sunday (day of week 7)
	} {
		t.Run(x.Format(time.RFC3339Nano), func(t *testing.T) {
			if err := c.ClockSync(ctx, x); err != nil {
				t.Fatal(err)
			}
			f := kv(p.expect(5*time.Second, "CLOCK"))
			if f["tf"] != tf(x, false, false, false) {
				t.Errorf("lib60870 read %s, want %s", f["tf"], tf(x, false, false, false))
			}
		})
	}
	t.Run("summer time bit is sent as zero", func(t *testing.T) {
		berlin, err := time.LoadLocation("Europe/Berlin")
		if err != nil {
			t.Skip(err)
		}
		// Encoded in Berlin's zone and sent on the client's link.
		x := time.Date(2026, 7, 1, 10, 0, 0, 0, time.UTC) // 12:00 summer time in Berlin
		b := iec60870.ASDU{Type: iec60870.CCsNa1, Cause: iec60870.CauseActivation, CA: 1, Objects: []iec60870.Object{{Time: x}}}
		raw, err := b.Encode(iec60870.Params{}.WithDefaults(), berlin)
		if err != nil {
			t.Fatal(err)
		}
		if err := c.Link().Send(ctx, raw); err != nil {
			t.Fatal(err)
		}
		f := kv(p.expect(5*time.Second, "CLOCK"))
		if want := "0,0,12,1,3,7,26,0,0,0"; f["tf"] != want {
			t.Errorf("lib60870 read %s, want %s", f["tf"], want)
		}
	})
	t.Run("negative confirmation", func(t *testing.T) {
		p.send("clockneg 1")
		p.expect(5*time.Second, "CLOCKNEG 1")
		if err := c.ClockSync(ctx, time.Now()); err == nil || !strings.Contains(err.Error(), "refused") {
			t.Errorf("clock sync = %v, want a refusal", err)
		}
		p.send("clockneg 0")
		p.expect(5*time.Second, "CLOCKNEG 0")
		if err := c.ClockSync(ctx, time.Now()); err != nil {
			t.Error(err)
		}
	})
}

// fileByte is the peer's offered file content.
func fileByte(i int) byte { return byte(i*7 + 3) }

// TestFileTransferWithLib60870: our controlling station downloads the file
// lib60870's file service offers (several sections) and uploads one to it.
func TestFileTransferWithLib60870(t *testing.T) {
	needDocker(t)
	p, c, _ := startServer(t, "filesize=1234")
	ctx := context.Background()
	t.Run("download (monitor direction)", func(t *testing.T) {
		data, err := iec60870.GetFile(ctx, c, 1000, 1, 5*time.Second)
		if err != nil {
			t.Fatal(err)
		}
		if len(data) != 1234 {
			t.Fatalf("%d octets, want 1234", len(data))
		}
		for i, b := range data {
			if b != fileByte(i) {
				t.Fatalf("octet %d is %#x, want %#x", i, b, fileByte(i))
			}
		}
		p.expect(5*time.Second, "FILE-SENT ok=1")
	})
	t.Run("unknown file", func(t *testing.T) {
		if _, err := iec60870.GetFile(ctx, c, 1001, 1, 5*time.Second); err == nil {
			t.Error("an unknown file was transferred")
		}
	})
	t.Run("upload (control direction)", func(t *testing.T) {
		data := make([]byte, 70000) // two sections of ours
		var h uint32
		for i := range data {
			data[i] = byte(i % 251)
			h = h*31 + uint32(data[i])
		}
		if err := iec60870.PutFile(ctx, c, 2000, 1, data, 5*time.Second); err != nil {
			t.Fatal(err)
		}
		f := kv(p.expect(10*time.Second, "FILE-RECEIVED"))
		if f["result"] != "0" || f["len"] != "70000" || f["hash"] != strconv.FormatUint(uint64(h), 10) {
			t.Errorf("peer received %v", f)
		}
	})
}
