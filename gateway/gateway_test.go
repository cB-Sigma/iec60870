// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package gateway_test

import (
	"context"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cB-Sigma/iec60870"
	"github.com/cB-Sigma/iec60870/cs101"
	"github.com/cB-Sigma/iec60870/cs104"
	"github.com/cB-Sigma/iec60870/gateway"
	"github.com/cB-Sigma/iec60870/station"
)

type collector struct {
	mu    sync.Mutex
	asdus []*iec60870.ASDU
}

func (c *collector) add(a *iec60870.ASDU) {
	c.mu.Lock()
	c.asdus = append(c.asdus, a)
	c.mu.Unlock()
}

func (c *collector) wait(t *testing.T, what string, match func(*iec60870.ASDU) bool) *iec60870.ASDU {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		c.mu.Lock()
		for _, a := range c.asdus {
			if match(a) {
				c.mu.Unlock()
				return a
			}
		}
		c.mu.Unlock()
		time.Sleep(10 * time.Millisecond)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	var got []string
	for _, a := range c.asdus {
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

// line101 runs a downstream IEC 101 station (link address 3, common
// address 7) and returns the gateway's route to it, as sector 70 of g.
func line101(t *testing.T, ctx context.Context, g *gateway.Gateway, rtu *station.Station) *gateway.Route {
	t.Helper()
	a, b := net.Pipe()
	sec := cs101.NewSecondary(cs101.NewPort(a), cs101.SecondaryConfig{LinkAddress: 3, AddrSize: 1, LinkTimeout: 10 * time.Second})
	go func() { _ = sec.Run(ctx) }()
	go rtu.ServeSecondary(ctx, sec, iec60870.Params{}, 1)
	link := cs101.NewLink(cs101.NewPort(b), 1, false, 300*time.Millisecond, 2)
	t.Cleanup(link.Close)
	if err := link.Start(ctx, 3); err != nil {
		t.Fatal(err)
	}
	r := &gateway.Route{CA: 70, DownCA: 7, Timeout: 3 * time.Second, Termination: 3 * time.Second}
	g.Add(r)
	c := cs101.NewClient(link, cs101.ClientConfig{Address: 3, CA: 7, PollInterval: 10 * time.Millisecond, OnData: r.Receive})
	t.Cleanup(c.Close)
	r.Peer = c
	return r
}

func upstream(t *testing.T, ctx context.Context, g *gateway.Gateway, got *collector) *cs104.Client {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		_ = (&cs104.Server{Groups: []*cs104.Group{g.Station().Group(cs104.LinkConfig{})}}).Serve(ctx, ln)
	}()
	l, err := cs104.Dial(ctx, ln.Addr().String(), cs104.LinkConfig{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(l.Close)
	return cs104.NewClient(l, cs104.ClientConfig{CA: 70, Timeout: 5 * time.Second, OnData: got.add})
}

func rtu() *station.Station {
	st := station.New(station.Config{CA: 7, Params: iec60870.Params{COTSize: 1, CASize: 1, IOASize: 2}})
	st.Add(station.Point{Type: iec60870.MSpTa1, Object: iec60870.Object{IOA: 100, Value: 1}, Groups: []int{3}})
	st.Add(station.Point{Type: iec60870.MMeTc1, Object: iec60870.Object{IOA: 300, Value: 41.5}})
	st.Add(station.Point{Type: iec60870.MDpNa1, Object: iec60870.Object{IOA: 101, Value: 1}})
	st.Add(station.Point{Type: iec60870.MItNa1, Object: iec60870.Object{IOA: 400, Value: 77}})
	st.AddControl(station.Control{IOA: 200, Type: iec60870.CDcNa1, Monitor: 101, SelectRequired: true})
	return st
}

// The IEC 101 to IEC 104 gateway: interrogation from the mirror,
// spontaneous data with CP24Time2a types turned into CP56Time2a ones,
// commands with select-before-operate and return information, counter
// interrogation passed through, refusals passed back, a lost station
// marked invalid.
func TestGateway101To104(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	down := rtu()
	g := gateway.New(station.Config{CA: 1})
	r := line101(t, ctx, g, down)
	if err := r.Interrogate(ctx); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(3 * time.Second)
	for len(r.Sector().Points()) < 3 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	var got collector
	c := upstream(t, ctx, g, &got)

	if err := c.Interrogate(ctx, iec60870.QOIStation, 3*time.Second); err != nil {
		t.Fatal(err)
	}
	a := got.wait(t, "mirrored single point", is(iec60870.MSpNa1, iec60870.CauseInterrogated, 100))
	if a.CA != 70 || a.Objects[0].Value != 1 {
		t.Errorf("mirrored %v", a)
	}
	got.wait(t, "mirrored measured value", is(iec60870.MMeNc1, iec60870.CauseInterrogated, 300))

	// Spontaneous data with CP24Time2a below reaches IEC 104 with
	// CP56Time2a.
	if err := down.Update(300, 50.25, 0); err != nil {
		t.Fatal(err)
	}
	sp := got.wait(t, "spontaneous value", is(iec60870.MMeTf1, iec60870.CauseSpontaneous, 300))
	if sp.Objects[0].Value != 50.25 || sp.CA != 70 || sp.Objects[0].Time.IsZero() {
		t.Errorf("spontaneous %v", sp)
	}

	// A command with select-before-operate goes down and its return
	// information and termination come back.
	if _, err := c.Operate(ctx, iec60870.Operation{Type: iec60870.CDcNa1, Object: iec60870.Object{IOA: 200, Value: 2},
		SelectBeforeOperate: true, Termination: 5 * time.Second}); err != nil {
		t.Fatal(err)
	}
	got.wait(t, "return information", is(iec60870.MDpNa1, iec60870.CauseReturnRemote, 101))
	if p, _ := down.Get(101); p.Value != 2 {
		t.Errorf("downstream double point %v", p.Value)
	}
	// The downstream refusal (execute without select) comes back.
	if _, err := c.Operate(ctx, iec60870.Operation{Type: iec60870.CDcNa1, Object: iec60870.Object{IOA: 200, Value: 1}}); err == nil {
		t.Error("an execute the station refused was confirmed")
	}
	// The downstream station's cause 47 comes back as cause 47.
	if _, err := c.Operate(ctx, iec60870.Operation{Type: iec60870.CScNa1, Object: iec60870.Object{IOA: 999, Value: 1}}); err == nil ||
		!strings.Contains(err.Error(), iec60870.CauseUnknownObject.String()) {
		t.Errorf("an unknown downstream object: %v", err)
	}

	// Counter interrogation is passed through.
	if err := c.CounterInterrogate(ctx, iec60870.QCC(iec60870.RQTGeneral, iec60870.FRZRead), 5*time.Second); err != nil {
		t.Fatal(err)
	}
	got.wait(t, "counter", is(iec60870.MItNa1, iec60870.CauseCounterGen, 400))
	if down.Stats().CounterInterrogations != 1 {
		t.Errorf("the station saw %d counter interrogations", down.Stats().CounterInterrogations)
	}

	// The station is lost: its points turn invalid upward, commands are
	// refused; back again, it is interrogated.
	if err := r.SetOnline(ctx, false); err != nil {
		t.Fatal(err)
	}
	got.wait(t, "invalid point", func(a *iec60870.ASDU) bool {
		return a.Cause == iec60870.CauseSpontaneous && a.Objects[0].IOA == 100 && a.Objects[0].Quality&iec60870.QInvalid != 0
	})
	got.wait(t, "invalid measured value", func(a *iec60870.ASDU) bool {
		return a.Type == iec60870.MMeTf1 && a.Objects[0].IOA == 300 && a.Objects[0].Quality&iec60870.QInvalid != 0
	})
	if _, err := c.Operate(ctx, iec60870.Operation{Type: iec60870.CDcNa1, Object: iec60870.Object{IOA: 200, Value: 2}}); err == nil {
		t.Error("a command to an offline station was confirmed")
	}
	gi := down.Stats().Interrogations
	if err := r.SetOnline(ctx, true); err != nil {
		t.Fatal(err)
	}
	deadline = time.Now().Add(3 * time.Second)
	for down.Stats().Interrogations == gi && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if down.Stats().Interrogations == gi {
		t.Error("the station was not interrogated again")
	}
}

// Unknown common addresses on the gateway are refused; the gateway's own
// sector is served like any station's.
func TestGatewayOwnSector(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	g := gateway.New(station.Config{CA: 1})
	g.Station().Add(station.Point{Type: iec60870.MSpNa1, Object: iec60870.Object{IOA: 1, Value: 1}})
	line101(t, ctx, g, rtu())
	var got collector
	c := upstream(t, ctx, g, &got)
	if err := c.Send(ctx, &iec60870.ASDU{Type: iec60870.CIcNa1, Cause: iec60870.CauseActivation, CA: 1,
		Objects: []iec60870.Object{{Value: 20}}}); err != nil {
		t.Fatal(err)
	}
	got.wait(t, "the gateway's own point", is(iec60870.MSpNa1, iec60870.CauseInterrogated, 1))
	if err := c.Send(ctx, &iec60870.ASDU{Type: iec60870.CIcNa1, Cause: iec60870.CauseActivation, CA: 99,
		Objects: []iec60870.Object{{Value: 20}}}); err != nil {
		t.Fatal(err)
	}
	got.wait(t, "unknown common address", is(iec60870.CIcNa1, iec60870.CauseUnknownCA, 0))
}
