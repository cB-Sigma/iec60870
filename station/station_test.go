// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package station_test

import (
	"context"
	"errors"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/cB-Sigma/iec60870"
	"github.com/cB-Sigma/iec60870/cs101"
	"github.com/cB-Sigma/iec60870/cs104"
	"github.com/cB-Sigma/iec60870/station"
)

// collector keeps what a controlling station received.
type collector struct {
	mu    sync.Mutex
	asdus []*iec60870.ASDU
}

func (c *collector) add(a *iec60870.ASDU) {
	c.mu.Lock()
	c.asdus = append(c.asdus, a)
	c.mu.Unlock()
}

func (c *collector) all() []*iec60870.ASDU {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]*iec60870.ASDU(nil), c.asdus...)
}

func (c *collector) reset() {
	c.mu.Lock()
	c.asdus = nil
	c.mu.Unlock()
}

// wait waits until match holds for some received ASDU and returns it.
func (c *collector) wait(t *testing.T, what string, match func(*iec60870.ASDU) bool) *iec60870.ASDU {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		for _, a := range c.all() {
			if match(a) {
				return a
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
	var got []string
	for _, a := range c.all() {
		got = append(got, a.String())
	}
	t.Fatalf("no %s; received %v", what, got)
	return nil
}

func is(ty iec60870.TypeID, cause iec60870.Cause, ioa uint32) func(*iec60870.ASDU) bool {
	return func(a *iec60870.ASDU) bool {
		if a.Type != ty || a.Cause != cause {
			return false
		}
		for _, o := range a.Objects {
			if o.IOA == ioa {
				return true
			}
		}
		return false
	}
}

// serve104 runs st on a cs104.Server with one redundancy group and
// returns a started client session.
func serve104(t *testing.T, st *station.Station, got *collector) *cs104.Client {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go func() { _ = (&cs104.Server{Groups: []*cs104.Group{st.Group(cs104.LinkConfig{})}}).Serve(ctx, ln) }()
	return dial104(t, ln.Addr().String(), 1, got)
}

func dial104(t *testing.T, addr string, ca uint16, got *collector) *cs104.Client {
	t.Helper()
	l, err := cs104.Dial(context.Background(), addr, cs104.LinkConfig{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(l.Close)
	return cs104.NewClient(l, cs104.ClientConfig{CA: ca, Timeout: 3 * time.Second, OnData: got.add})
}

func demo() *station.Station {
	st := station.New(station.Config{CA: 1})
	st.Add(station.Point{Type: iec60870.MSpTb1, Object: iec60870.Object{IOA: 100, Value: 1}, Groups: []int{1}})
	st.Add(station.Point{Type: iec60870.MDpNa1, Object: iec60870.Object{IOA: 101, Value: 1}})
	st.Add(station.Point{Type: iec60870.MMeNc1, Object: iec60870.Object{IOA: 200, Value: 230.5}, Groups: []int{2}})
	st.Add(station.Point{Type: iec60870.MItTb1, Object: iec60870.Object{IOA: 400, Value: 1000}, CounterGroup: 1})
	st.Add(station.Point{Type: iec60870.MEpTd1, Object: iec60870.Object{IOA: 500}})
	st.AddControl(station.Control{IOA: 2001, Type: iec60870.CDcNa1, Monitor: 101, SelectRequired: true})
	st.AddControl(station.Control{IOA: 2002, Type: iec60870.CSeNc1, Monitor: 200})
	return st
}

// Covers: SIG-IPE-898
func TestInterrogation(t *testing.T) {
	st := demo()
	var got collector
	c := serve104(t, st, &got)
	ctx := context.Background()
	if err := c.Interrogate(ctx, iec60870.QOIStation, 3*time.Second); err != nil {
		t.Fatal(err)
	}
	// The CP56Time2a type goes out untagged; totals and protection events
	// are not interrogated.
	if a := got.wait(t, "single point", is(iec60870.MSpNa1, iec60870.CauseInterrogated, 100)); a.Objects[0].Value != 1 {
		t.Errorf("single point %v", a)
	}
	got.wait(t, "double point", is(iec60870.MDpNa1, iec60870.CauseInterrogated, 101))
	got.wait(t, "measured value", is(iec60870.MMeNc1, iec60870.CauseInterrogated, 200))
	for _, a := range got.all() {
		if a.Type == iec60870.MItTb1 || a.Type == iec60870.MEpTd1 || a.Type == iec60870.MSpTb1 {
			t.Errorf("interrogation sent %v", a)
		}
	}
	got.reset()
	if err := c.Interrogate(ctx, iec60870.QOIGroup(2), 3*time.Second); err != nil {
		t.Fatal(err)
	}
	got.wait(t, "group 2", is(iec60870.MMeNc1, iec60870.Cause(22), 200))
	for _, a := range got.all() {
		if a.Type == iec60870.MSpNa1 {
			t.Errorf("group 2 answered with %v", a)
		}
	}
	if err := c.Interrogate(ctx, 50, time.Second); err == nil {
		t.Error("a reserved qualifier was confirmed")
	}
}

// Covers: SIG-IPE-1325
func TestInterrogationSplitsLongAnswers(t *testing.T) {
	st := station.New(station.Config{CA: 1})
	for i := range 120 {
		st.Add(station.Point{Type: iec60870.MMeNc1, Object: iec60870.Object{IOA: uint32(1000 + i), Value: float64(i)}})
	}
	var got collector
	c := serve104(t, st, &got)
	if err := c.Interrogate(context.Background(), iec60870.QOIStation, 3*time.Second); err != nil {
		t.Fatal(err)
	}
	n, asdus := 0, 0
	for _, a := range got.all() {
		if a.Type == iec60870.MMeNc1 {
			n += len(a.Objects)
			asdus++
		}
	}
	if n != 120 || asdus < 3 {
		t.Errorf("%d objects in %d ASDUs", n, asdus)
	}
}

// Covers: SIG-IPE-1326
func TestCounterInterrogation(t *testing.T) {
	st := demo()
	var got collector
	c := serve104(t, st, &got)
	ctx := context.Background()
	if err := c.CounterInterrogate(ctx, iec60870.QCC(iec60870.RQTGeneral, iec60870.FRZRead), 3*time.Second); err != nil {
		t.Fatal(err)
	}
	if a := got.wait(t, "total", is(iec60870.MItTb1, iec60870.CauseCounterGen, 400)); a.Objects[0].Value != 1000 {
		t.Errorf("total %v", a)
	}
	if err := c.CounterInterrogate(ctx, iec60870.QCC(1, iec60870.FRZFreezeReset), 0); err != nil {
		t.Fatal(err)
	}
	_ = st.Update(400, 1250, 0)
	got.reset()
	if err := c.CounterInterrogate(ctx, iec60870.QCC(1, iec60870.FRZRead), 3*time.Second); err != nil {
		t.Fatal(err)
	}
	if a := got.wait(t, "frozen total", is(iec60870.MItTb1, iec60870.CauseCounterGen+1, 400)); a.Objects[0].Value != 1000 {
		t.Errorf("frozen total %v, want 1000", a)
	}
	if err := c.CounterInterrogate(ctx, iec60870.QCC(1, iec60870.FRZFreeze), 0); err != nil {
		t.Fatal(err)
	}
	got.reset()
	if err := c.CounterInterrogate(ctx, iec60870.QCC(1, iec60870.FRZRead), 3*time.Second); err != nil {
		t.Fatal(err)
	}
	if a := got.wait(t, "total since reset", is(iec60870.MItTb1, iec60870.CauseCounterGen+1, 400)); a.Objects[0].Value != 250 {
		t.Errorf("total since the reset %v, want 250", a)
	}
}

// Covers: SIG-IPE-899
func TestSpontaneous(t *testing.T) {
	st := demo()
	st.Add(station.Point{Type: iec60870.MMeTc1, Object: iec60870.Object{IOA: 300, Value: 10}, Threshold: 1})
	var got collector
	c := serve104(t, st, &got)
	_ = c
	if err := st.Update(200, 231, 0); err != nil {
		t.Fatal(err)
	}
	got.wait(t, "spontaneous", is(iec60870.MMeNc1, iec60870.CauseSpontaneous, 200))
	// CP24Time2a types go out as their CP56Time2a twins over IEC 104; a
	// change within the threshold waits.
	_ = st.Update(300, 10.5, 0)
	_ = st.Update(300, 11.2, 0)
	a := got.wait(t, "threshold crossed", is(iec60870.MMeTf1, iec60870.CauseSpontaneous, 300))
	if a.Objects[0].Value != float64(float32(11.2)) || a.Objects[0].Time.IsZero() {
		t.Errorf("reported %v", a)
	}
	for _, x := range got.all() {
		if x.Type == iec60870.MMeTf1 && x.Objects[0].Value == 10.5 {
			t.Error("a change within the threshold was reported")
		}
	}
	if err := st.Event(iec60870.Object{IOA: 500, Value: 2, Elapsed: 40 * time.Millisecond}); err != nil {
		t.Fatal(err)
	}
	got.wait(t, "protection event", is(iec60870.MEpTd1, iec60870.CauseSpontaneous, 500))
	if err := st.Update(9999, 1, 0); !errors.Is(err, station.ErrUnknownPoint) {
		t.Errorf("unknown point: %v", err)
	}
}

// Covers: SIG-IPE-870
func TestCommands(t *testing.T) {
	st := demo()
	var executed []station.Command
	var mu sync.Mutex
	st.AddControl(station.Control{IOA: 3001, Type: iec60870.CScNa1, Execute: func(_ context.Context, c station.Command, confirm func()) error {
		mu.Lock()
		executed = append(executed, c)
		mu.Unlock()
		confirm()
		if c.Value == 0 {
			return errors.New("breaker stuck")
		}
		return nil
	}})
	var got collector
	c := serve104(t, st, &got)
	ctx := context.Background()

	// Select before operate: confirmation, return information (cause 11),
	// termination, in that order.
	if _, err := c.Operate(ctx, iec60870.Operation{Type: iec60870.CDcNa1, Object: iec60870.Object{IOA: 2001, Value: 2},
		SelectBeforeOperate: true, Termination: 3 * time.Second}); err != nil {
		t.Fatal(err)
	}
	ret := got.wait(t, "return information", is(iec60870.MDpNa1, iec60870.CauseReturnRemote, 101))
	if ret.Objects[0].Value != 2 {
		t.Errorf("return information %v", ret)
	}
	if p, _ := st.Get(101); p.Value != 2 {
		t.Errorf("double point is %v", p.Value)
	}
	// An execute without select is refused where a select is required.
	if _, err := c.Operate(ctx, iec60870.Operation{Type: iec60870.CDcNa1, Object: iec60870.Object{IOA: 2001, Value: 1}}); err == nil {
		t.Error("execute without select was confirmed")
	}
	// The time-tagged twin of the configured type is accepted; another
	// type is refused.
	if _, err := c.Operate(ctx, iec60870.Operation{Type: iec60870.CSeTc1, Object: iec60870.Object{IOA: 2002, Value: 12.5},
		TimeTag: true, Termination: 3 * time.Second}); err != nil {
		t.Fatal(err)
	}
	if p, _ := st.Get(200); p.Value != 12.5 {
		t.Errorf("set-point gave %v", p.Value)
	}
	if _, err := c.Operate(ctx, iec60870.Operation{Type: iec60870.CSeNb1, Object: iec60870.Object{IOA: 2002, Value: 1}}); err == nil {
		t.Error("a scaled set-point was taken at a float address")
	}
	if _, err := c.Operate(ctx, iec60870.Operation{Type: iec60870.CScNa1, Object: iec60870.Object{IOA: 4999, Value: 1}}); err == nil {
		t.Error("an unknown address was confirmed")
	}
	// The application's handler: a failure after the confirmation is a
	// negative termination.
	if _, err := c.Operate(ctx, iec60870.Operation{Type: iec60870.CScNa1, Object: iec60870.Object{IOA: 3001, Value: 1},
		Termination: 3 * time.Second}); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Operate(ctx, iec60870.Operation{Type: iec60870.CScNa1, Object: iec60870.Object{IOA: 3001, Value: 0},
		Termination: 3 * time.Second}); err == nil {
		t.Error("a failed execute terminated positively")
	}
	mu.Lock()
	n := len(executed)
	mu.Unlock()
	if n != 2 {
		t.Errorf("handler ran %d times", n)
	}
	// Deactivation of a select.
	sel, err := c.Operate(ctx, iec60870.Operation{Type: iec60870.CDcNa1, Object: iec60870.Object{IOA: 2001, Value: 1}, SelectOnly: true})
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Cancel(ctx, iec60870.CDcNa1, sel, false); err != nil {
		t.Errorf("cancel: %v", err)
	}
	if err := c.Cancel(ctx, iec60870.CDcNa1, sel, false); err == nil {
		t.Error("a second cancel was confirmed")
	}
}

// Covers: SIG-IPE-1324
func TestCommandTestBit(t *testing.T) {
	st := demo()
	var got collector
	c := serve104(t, st, &got)
	if err := c.Send(context.Background(), &iec60870.ASDU{Type: iec60870.CSeNc1, Cause: iec60870.CauseActivation, Test: true,
		Objects: []iec60870.Object{{IOA: 2002, Value: 99}}}); err != nil {
		t.Fatal(err)
	}
	a := got.wait(t, "termination", is(iec60870.CSeNc1, iec60870.CauseActTerm, 2002))
	if !a.Test {
		t.Error("the test bit was not mirrored")
	}
	if p, _ := st.Get(200); p.Value == 99 {
		t.Error("a command with the test bit was executed")
	}
}

// Covers: SIG-IPE-871
func TestRefusalsAndSystemCommands(t *testing.T) {
	st := station.New(station.Config{CA: 1, MaxCommandDelay: time.Second})
	st.Add(station.Point{Type: iec60870.MSpNa1, Object: iec60870.Object{IOA: 100, Value: 1}})
	st.AddControl(station.Control{IOA: 2001})
	var got collector
	c := serve104(t, st, &got)
	ctx := context.Background()
	send := func(a *iec60870.ASDU) {
		t.Helper()
		if err := c.Send(ctx, a); err != nil {
			t.Fatal(err)
		}
	}
	send(&iec60870.ASDU{Type: iec60870.CIcNa1, Cause: iec60870.CauseActivation, CA: 9, Objects: []iec60870.Object{{Value: 20}}})
	if a := got.wait(t, "unknown common address", is(iec60870.CIcNa1, iec60870.CauseUnknownCA, 0)); !a.Negative {
		t.Error("cause 46 not negative")
	}
	send(&iec60870.ASDU{Type: iec60870.CIcNa1, Cause: iec60870.CauseSpontaneous, Objects: []iec60870.Object{{Value: 20}}})
	got.wait(t, "unknown cause", is(iec60870.CIcNa1, iec60870.CauseUnknownCause, 0))
	send(&iec60870.ASDU{Type: iec60870.MSpNa1, Cause: iec60870.CauseSpontaneous, Objects: []iec60870.Object{{IOA: 5}}})
	got.wait(t, "unknown type", is(iec60870.MSpNa1, iec60870.CauseUnknownType, 5))
	// A time-tagged command older than the maximum delay: no answer.
	send(&iec60870.ASDU{Type: iec60870.CScTa1, Cause: iec60870.CauseActivation, Objects: []iec60870.Object{{IOA: 2001, Value: 1,
		Time: time.Now().Add(-time.Minute)}}})
	// Read.
	if a, err := iec60870.Read(ctx, c, 100, 3*time.Second); err != nil || a.Objects[0].Value != 1 {
		t.Errorf("read %v %v", a, err)
	}
	if _, err := iec60870.Read(ctx, c, 101, 3*time.Second); err == nil {
		t.Error("read of an unknown address succeeded")
	}
	// Clock synchronisation moves the station's clock.
	future := time.Now().Add(time.Hour).Truncate(time.Millisecond)
	if err := c.ClockSync(ctx, future); err != nil {
		t.Fatal(err)
	}
	if d := st.Now().Sub(future); d < 0 || d > time.Second {
		t.Errorf("station clock %s after synchronising to %s", st.Now(), future)
	}
	if err := c.Test(ctx, 0x1234, time.Now()); err != nil {
		t.Errorf("test command: %v", err)
	}
	// Reset process: confirmation, then the end of initialisation (COI 2).
	if err := c.ResetProcess(ctx, iec60870.QRPGeneral); err != nil {
		t.Fatal(err)
	}
	if a := got.wait(t, "end of initialisation", is(iec60870.MEiNa1, iec60870.CauseInitialised, 0)); a.Objects[0].Value != iec60870.COIRemote {
		t.Errorf("end of initialisation %v", a)
	}
	if err := c.ResetProcess(ctx, 7); err == nil {
		t.Error("a reserved reset qualifier was confirmed")
	}
	for _, a := range got.all() {
		if a.Type == iec60870.CScTa1 {
			t.Errorf("a late command was answered: %v", a)
		}
	}
	if st.Stats().Late != 1 {
		t.Errorf("late commands counted %d", st.Stats().Late)
	}
}

// Covers: SIG-IPE-1329
func TestParameters(t *testing.T) {
	st := station.New(station.Config{CA: 1, CyclicPeriod: 50 * time.Millisecond})
	st.Add(station.Point{Type: iec60870.MMeNc1, Object: iec60870.Object{IOA: 200, Value: 10}})
	var got collector
	c := serve104(t, st, &got)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go st.Run(ctx)
	if err := c.Request(ctx, iec60870.Request{Type: iec60870.PMeNc1, Cause: iec60870.CauseActivation,
		Object: iec60870.Object{IOA: 200, Value: 5, Qualifier: iec60870.KPAThreshold}}); err != nil {
		t.Fatal(err)
	}
	if v, ok := st.Parameter(200, iec60870.KPAThreshold); !ok || v != 5 {
		t.Errorf("threshold %v %v", v, ok)
	}
	_ = st.Update(200, 12, 0)
	_ = st.Update(200, 16, 0)
	got.wait(t, "value past the threshold", is(iec60870.MMeNc1, iec60870.CauseSpontaneous, 200))
	for _, a := range got.all() {
		if a.Cause == iec60870.CauseSpontaneous && a.Objects[0].Value == 12 {
			t.Error("a change within the loaded threshold was reported")
		}
	}
	if err := c.Request(ctx, iec60870.Request{Type: iec60870.PMeNc1, Cause: iec60870.CauseActivation,
		Object: iec60870.Object{IOA: 999, Value: 5, Qualifier: 1}}); err == nil {
		t.Error("a parameter of an unknown object was confirmed")
	}
	// QPA 3 starts cyclic transmission of the object.
	if err := c.Request(ctx, iec60870.Request{Type: iec60870.PAcNa1, Cause: iec60870.CauseActivation,
		Object: iec60870.Object{IOA: 200, Qualifier: iec60870.QPACyclic}}); err != nil {
		t.Fatal(err)
	}
	got.wait(t, "cyclic data", is(iec60870.MMeNc1, iec60870.CausePeriodic, 200))
}

// Covers: SIG-IPE-1332
func TestFiles(t *testing.T) {
	data := make([]byte, 700)
	for i := range data {
		data[i] = byte(i * 7)
	}
	st := station.New(station.Config{CA: 1, Files: &iec60870.FileServer{Store: files{data}, SectionSize: 300}})
	var got collector
	c := serve104(t, st, &got)
	b, err := iec60870.GetFile(context.Background(), c, 1000, 1, 3*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if len(b) != len(data) || b[699] != data[699] {
		t.Errorf("read %d octets", len(b))
	}
}

type files struct{ data []byte }

func (f files) Directory(context.Context) ([]iec60870.DirEntry, error) {
	return []iec60870.DirEntry{{IOA: 1000, Name: 1, Length: uint32(len(f.data))}}, nil
}

func (f files) Read(_ context.Context, ioa uint32, _ uint16) ([]byte, error) {
	if ioa != 1000 {
		return nil, iec60870.ErrNoFile
	}
	return f.data, nil
}

func (f files) Write(context.Context, uint32, uint16, []byte) error { return iec60870.ErrNoFile }

// Covers: SIG-IPE-898
func TestSectorsAndBroadcast(t *testing.T) {
	st := demo()
	other := st.SectorAt(2)
	other.Add(station.Point{Type: iec60870.MSpNa1, Object: iec60870.Object{IOA: 7}})
	var got collector
	c := serve104(t, st, &got)
	if err := c.Send(context.Background(), &iec60870.ASDU{Type: iec60870.CIcNa1, Cause: iec60870.CauseActivation, CA: 0xffff,
		Objects: []iec60870.Object{{Value: 20}}}); err != nil {
		t.Fatal(err)
	}
	a := got.wait(t, "sector 2", is(iec60870.MSpNa1, iec60870.CauseInterrogated, 7))
	if a.CA != 2 {
		t.Errorf("sector 2 answered with common address %d", a.CA)
	}
	if a := got.wait(t, "sector 1", is(iec60870.MSpNa1, iec60870.CauseInterrogated, 100)); a.CA != 1 {
		t.Errorf("sector 1 answered with common address %d", a.CA)
	}
}

// Several controlling stations on one IEC 101 line: the station answers a
// link address per controlling station (cs101.SharedLine), each with its
// own queue, so each sees every change.
func TestSharedLineTwoControllingStations(t *testing.T) {
	st := demo()
	a, b := net.Pipe()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	line := cs101.NewSharedLine(a, 1)
	defer line.Close()
	for _, addr := range []uint16{3, 4} {
		sec := cs101.NewSecondary(line.Port(addr), cs101.SecondaryConfig{LinkAddress: addr, AddrSize: 1, LinkTimeout: 5 * time.Second})
		go func() { _ = sec.Run(ctx) }()
		go st.ServeSecondary(ctx, sec, iec60870.Params{}, 1)
	}
	link := cs101.NewLink(cs101.NewPort(b), 1, false, 300*time.Millisecond, 2)
	defer link.Close()
	var got3, got4 collector
	for _, addr := range []uint16{3, 4} {
		if err := link.Start(ctx, addr); err != nil {
			t.Fatal(err)
		}
	}
	c3 := cs101.NewClient(link, cs101.ClientConfig{Address: 3, CA: 1, PollInterval: 20 * time.Millisecond, OnData: got3.add})
	defer c3.Close()
	c4 := cs101.NewClient(link, cs101.ClientConfig{Address: 4, CA: 1, PollInterval: 20 * time.Millisecond, OnData: got4.add})
	defer c4.Close()
	if err := c4.Interrogate(ctx, iec60870.QOIStation, 3*time.Second); err != nil {
		t.Fatal(err)
	}
	got4.wait(t, "interrogated value", is(iec60870.MMeNc1, iec60870.CauseInterrogated, 200))
	for _, x := range got3.all() {
		if x.Cause == iec60870.CauseInterrogated {
			t.Errorf("address 3 received the interrogation of address 4: %v", x)
		}
	}
	if err := st.Update(200, 42, 0); err != nil {
		t.Fatal(err)
	}
	got3.wait(t, "change at address 3", is(iec60870.MMeNc1, iec60870.CauseSpontaneous, 200))
	got4.wait(t, "change at address 4", is(iec60870.MMeNc1, iec60870.CauseSpontaneous, 200))
}

// Several controlling stations: two redundancy groups over IEC 104 and an
// IEC 101 line, each with its own queue, see every change.
func TestSeveralControllingStations(t *testing.T) {
	st := demo()
	var got1, got2, got3 collector
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	srv := &cs104.Server{PerConnection: st.PerConnection(cs104.LinkConfig{})}
	go func() { _ = srv.Serve(ctx, ln) }()
	dial104(t, ln.Addr().String(), 1, &got1)
	dial104(t, ln.Addr().String(), 1, &got2)

	a, b := net.Pipe()
	sec := cs101.NewSecondary(cs101.NewPort(a), cs101.SecondaryConfig{LinkAddress: 3, AddrSize: 1, LinkTimeout: 5 * time.Second})
	go func() { _ = sec.Run(ctx) }()
	go st.ServeSecondary(ctx, sec, iec60870.Params{}, 1)
	link := cs101.NewLink(cs101.NewPort(b), 1, false, 300*time.Millisecond, 2)
	defer link.Close()
	if err := link.Start(ctx, 3); err != nil {
		t.Fatal(err)
	}
	c101 := cs101.NewClient(link, cs101.ClientConfig{Address: 3, CA: 1, PollInterval: 20 * time.Millisecond, OnData: got3.add})
	defer c101.Close()
	deadline := time.Now().Add(3 * time.Second)
	for st.Stats().Sessions < 3 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if err := st.Update(200, 999, 0); err != nil {
		t.Fatal(err)
	}
	for i, g := range []*collector{&got1, &got2, &got3} {
		if a := g.wait(t, "change", is(iec60870.MMeNc1, iec60870.CauseSpontaneous, 200)); a.Objects[0].Value != 999 {
			t.Errorf("station %d got %v", i+1, a)
		}
	}
	// The IEC 101 controlling station runs a command with select over the
	// same database.
	if _, err := c101.Operate(ctx, iec60870.Operation{Type: iec60870.CDcNa1, Object: iec60870.Object{IOA: 2001, Value: 2},
		SelectBeforeOperate: true, Termination: 3 * time.Second}); err != nil {
		t.Fatal(err)
	}
	got1.wait(t, "return information on IEC 104", is(iec60870.MDpNa1, iec60870.CauseReturnRemote, 101))
}
