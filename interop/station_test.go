// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package interop

import (
	"context"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/cB-Sigma/iec60870"
	"github.com/cB-Sigma/iec60870/cs101"
	"github.com/cB-Sigma/iec60870/cs104"
	"github.com/cB-Sigma/iec60870/gateway"
	"github.com/cB-Sigma/iec60870/station"
)

// demoStation is the station package's controlled station the reference
// controlling stations run against: one point of each common kind, a
// counter, a double command with select-before-operate required and
// return information, a set-point.
func demoStation(ca uint16, prm iec60870.Params) *station.Station {
	st := station.New(station.Config{CA: ca, Params: prm, CyclicPeriod: 200 * time.Millisecond})
	st.Add(station.Point{Type: iec60870.MSpTb1, Object: iec60870.Object{IOA: 100, Value: 1}, Groups: []int{1}})
	st.Add(station.Point{Type: iec60870.MDpNa1, Object: iec60870.Object{IOA: 101, Value: 1}})
	st.Add(station.Point{Type: iec60870.MMeNc1, Object: iec60870.Object{IOA: 200, Value: 230.5}})
	st.Add(station.Point{Type: iec60870.MMeTc1, Object: iec60870.Object{IOA: 300, Value: 1}})
	st.Add(station.Point{Type: iec60870.MItTb1, Object: iec60870.Object{IOA: 400, Value: 1000}, CounterGroup: 2})
	st.AddControl(station.Control{IOA: 2001, Type: iec60870.CDcNa1, Monitor: 101, SelectRequired: true})
	st.AddControl(station.Control{IOA: 2002, Type: iec60870.CSeNc1, Monitor: 200})
	return st
}

// TestLib60870ClientAgainstStation: lib60870 as IEC 104 controlling
// station against the station package on cs104.Server: interrogation
// (station and group, the CP56Time2a type sent untagged), counter
// interrogation, read, select-before-operate with return information and
// termination, refusals, spontaneous data (a CP24Time2a type sent as its
// CP56Time2a twin), clock synchronisation, the test command, reset
// process with end of initialisation, parameter loading and activation
// with cyclic data, and an unknown common address.
func TestLib60870ClientAgainstStation(t *testing.T) {
	needDocker(t)
	st := demoStation(1, iec60870.Params{})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go st.Run(ctx)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = (&cs104.Server{Groups: []*cs104.Group{st.Group(cs104.LinkConfig{})}}).Serve(ctx, ln) }()
	p := startPeer(t, "--add-host=host.docker.internal:host-gateway", image, "peer", "client104", "host.docker.internal",
		port(t, ln.Addr().String()))
	p.expect(60*time.Second, "READY")
	p.send("startdt")
	p.expect(10*time.Second, "EVENT 2")

	t.Run("interrogation", func(t *testing.T) {
		p.send("gi")
		p.expect(5*time.Second, "type=100 ", "cot=7 ", "neg=0")
		p.expect(5*time.Second, "type=1 ", "cot=20 ", "ioa=100 ", "value=1 ", "time=0")
		p.expect(5*time.Second, "type=13 ", "cot=20 ", "ioa=200 ", "value=230.5 ")
		p.expect(5*time.Second, "type=100 ", "cot=10 ")
		p.send("send type=100 v=21")
		p.expect(5*time.Second, "type=1 ", "cot=21 ", "ioa=100 ")
		p.expect(5*time.Second, "type=100 ", "cot=10 ")
	})
	t.Run("counter interrogation and read", func(t *testing.T) {
		p.send("send type=101 v=2")
		p.expect(5*time.Second, "type=37 ", "cot=39 ", "ioa=400 ", "value=1000 ")
		p.expect(5*time.Second, "type=101 ", "cot=10 ")
		p.send("send type=102 ioa=200")
		p.expect(5*time.Second, "type=13 ", "cot=5 ", "ioa=200 ", "value=230.5 ")
		p.send("send type=102 ioa=999")
		p.expect(5*time.Second, "type=102 ", "cot=47 ", "neg=1")
	})
	t.Run("select before operate", func(t *testing.T) {
		p.send("send type=46 ioa=2001 v=2 sel=1")
		p.expect(5*time.Second, "type=46 ", "cot=7 ", "neg=0", "select=1")
		p.send("send type=46 ioa=2001 v=2")
		p.expect(5*time.Second, "type=46 ", "cot=7 ", "neg=0", "select=0")
		p.expect(5*time.Second, "type=3 ", "cot=11 ", "ioa=101 ", "value=2 ")
		p.expect(5*time.Second, "type=46 ", "cot=10 ", "neg=0")
		if pt, _ := st.Get(101); pt.Value != 2 {
			t.Errorf("double point %v", pt.Value)
		}
		// Without a select: refused; an unknown address: cause 47.
		p.send("send type=46 ioa=2001 v=1")
		p.expect(5*time.Second, "type=46 ", "cot=7 ", "neg=1")
		p.send("send type=45 ioa=4999 v=1")
		p.expect(5*time.Second, "type=45 ", "cot=47 ", "neg=1")
		p.send(fmt.Sprintf("send type=63 ioa=2002 v=17.5 t=%s", cp56Hex(time.Now(), false, false, false)))
		p.expect(5*time.Second, "type=63 ", "cot=7 ", "neg=0")
		p.expect(5*time.Second, "type=13 ", "cot=3 ", "ioa=200 ", "value=17.5 ")
		p.expect(5*time.Second, "type=63 ", "cot=10 ")
	})
	t.Run("spontaneous", func(t *testing.T) {
		if err := st.UpdateObject(iec60870.Object{IOA: 300, Value: 12.25, Time: stamp}); err != nil {
			t.Fatal(err)
		}
		f := kv(p.expect(5*time.Second, "type=36 ", "cot=3 ", "ioa=300 "))
		if f["value"] != "12.25" || f["tf"] != tf(stamp, false, false, false) {
			t.Errorf("lib60870 read %v", f)
		}
	})
	t.Run("system commands", func(t *testing.T) {
		p.send("clock")
		p.expect(5*time.Second, "type=103 ", "cot=7 ", "neg=0")
		p.send("send type=107 v=4660 t=" + cp56Hex(stamp, false, false, false))
		p.expect(5*time.Second, "type=107 ", "cot=7 ", "value=4660 ")
		p.send("send type=105 v=1")
		p.expect(5*time.Second, "type=105 ", "cot=7 ", "neg=0")
		p.expect(5*time.Second, "type=70 ", "cot=4 ", "value=2 ")
		p.send("send type=112 ioa=200 v=2.5 qu=1")
		p.expect(5*time.Second, "type=112 ", "cot=7 ", "neg=0", "value=2.5 ")
		if v, ok := st.Parameter(200, iec60870.KPAThreshold); !ok || v != 2.5 {
			t.Errorf("threshold %v %v", v, ok)
		}
		p.send("send type=113 ioa=200 qu=3")
		p.expect(5*time.Second, "type=113 ", "cot=7 ", "neg=0")
		p.expect(5*time.Second, "type=13 ", "cot=1 ", "ioa=200 ")
		p.send("send type=113 ioa=200 qu=3 cot=8")
		p.expect(5*time.Second, "type=113 ", "cot=9 ", "neg=0")
	})
	t.Run("unknown common address", func(t *testing.T) {
		p.send("ca 9")
		p.expect(5*time.Second, "CA 9")
		p.send("gi")
		p.expect(5*time.Second, "type=100 ", "cot=46 ", "neg=1")
	})
}

// TestLib60870MasterAgainstStation101: lib60870 as IEC 101 controlling
// station (unbalanced and balanced) against the station package on
// cs101.Secondary: interrogation, select-before-operate with return
// information, counter interrogation, a CP24Time2a type kept as such on
// IEC 101, the test command and delay acquisition.
func TestLib60870MasterAgainstStation101(t *testing.T) {
	needDocker(t)
	for _, cfg := range []line101{{false, 1, 1, 1, 2}, {true, 1, 2, 2, 3}} {
		t.Run(cfg.String(), func(t *testing.T) {
			prm := cfg.params()
			st := demoStation(1, prm)
			ln, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer ln.Close()
			p := startPeer(t, append([]string{"--add-host=host.docker.internal:host-gateway", image, "serial101.sh", "master",
				"host.docker.internal", port(t, ln.Addr().String()), "3"}, cfg.args()...)...)
			conn, err := ln.Accept()
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			sec := cs101.NewSecondary(cs101.NewPort(conn), cs101.SecondaryConfig{LinkAddress: 3, AddrSize: cfg.la, Balanced: cfg.balanced,
				LinkTimeout: 30 * time.Second, Timeout: 500 * time.Millisecond, Retries: 3, TestPeriod: 5 * time.Second})
			defer sec.Close()
			go func() { _ = sec.Run(ctx) }()
			go st.ServeSecondary(ctx, sec, prm, cfg.la)
			p.expect(60*time.Second, "READY")
			p.send("gi")
			p.expect(10*time.Second, "type=100 ", "cot=7 ")
			p.expect(10*time.Second, "type=1 ", "cot=20 ", "ioa=100 ")
			p.expect(10*time.Second, "type=100 ", "cot=10 ")
			p.send("send type=46 ioa=2001 v=1 sel=1")
			p.expect(10*time.Second, "type=46 ", "cot=7 ", "neg=0", "select=1")
			p.send("send type=46 ioa=2001 v=1")
			p.expect(10*time.Second, "type=3 ", "cot=11 ", "ioa=101 ", "value=1 ")
			p.expect(10*time.Second, "type=46 ", "cot=10 ", "neg=0")
			p.send("send type=101 v=5")
			p.expect(10*time.Second, "type=37 ", "cot=37 ", "ioa=400 ", "value=1000 ")
			p.expect(10*time.Second, "type=101 ", "cot=10 ")
			if err := st.UpdateObject(iec60870.Object{IOA: 300, Value: 7.5, Time: stamp}); err != nil {
				t.Fatal(err)
			}
			f := kv(p.expect(10*time.Second, "type=14 ", "cot=3 ", "ioa=300 "))
			if f["value"] != "7.5" || f["t24"] == "-" {
				t.Errorf("lib60870 read %v", f)
			}
			p.send("send type=104")
			p.expect(10*time.Second, "type=104 ", "cot=7 ", "neg=0")
			p.send("send type=106 el=1500")
			p.expect(10*time.Second, "type=106 ", "cot=7 ", "neg=0", "el=1500 ")
		})
	}
}

// TestLib60870ThroughGateway: a lib60870 IEC 101 station behind the
// gateway (our cs101.Link and Client below), a lib60870 IEC 104
// controlling station above: interrogation answered from the mirror under
// the gateway's common address, spontaneous data (a CP24Time2a type
// arriving as CP56Time2a), select-before-operate passed down and back, a
// refusal passed back with its cause, counter interrogation passed
// through, a read answered from the mirror.
func TestLib60870ThroughGateway(t *testing.T) {
	needDocker(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	lport := freePort(t)
	slave := startPeer(t, "-p", fmt.Sprintf("127.0.0.1:%d:2410", lport), image, "serial101.sh", "slave", "3")
	slave.expect(60*time.Second, "READY")
	link := cs101.NewLink(cs101.NewPort(dialTCP(t, fmt.Sprintf("127.0.0.1:%d", lport))), 1, false, time.Second, 3)
	defer link.Close()
	if err := link.Start(ctx, 3); err != nil {
		t.Fatal(err)
	}
	g := gateway.New(station.Config{CA: 1})
	r := &gateway.Route{CA: 70, DownCA: 1, Timeout: 5 * time.Second, Termination: 5 * time.Second}
	g.Add(r)
	c := cs101.NewClient(link, cs101.ClientConfig{Address: 3, CA: 1, PollInterval: 20 * time.Millisecond, OnData: r.Receive})
	defer c.Close()
	r.Peer = c
	if err := r.Interrogate(ctx); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(10 * time.Second)
	for len(r.Sector().Points()) < 2 && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		_ = (&cs104.Server{Groups: []*cs104.Group{g.Station().Group(cs104.LinkConfig{})}}).Serve(ctx, ln)
	}()
	p := startPeer(t, "--add-host=host.docker.internal:host-gateway", image, "peer", "client104", "host.docker.internal",
		port(t, ln.Addr().String()))
	p.expect(60*time.Second, "READY")
	p.send("ca 70")
	p.expect(5*time.Second, "CA 70")
	p.send("startdt")
	p.expect(10*time.Second, "EVENT 2")

	p.send("gi")
	p.expect(5*time.Second, "type=1 ", "cot=20 ", "ca=70 ", "ioa=100 ", "value=1 ")
	p.expect(5*time.Second, "type=13 ", "cot=20 ", "ca=70 ", "ioa=200 ", "value=230.5 ")
	p.expect(5*time.Second, "type=100 ", "cot=10 ", "ca=70 ")

	slave.send("spont 300 12.5")
	p.expect(10*time.Second, "type=13 ", "cot=3 ", "ca=70 ", "ioa=300 ", "value=12.5 ")
	slave.send(fmt.Sprintf("send type=14 ioa=301 v=7.5 t=%s", cp56Hex(stamp, false, false, false)))
	f := kv(p.expect(10*time.Second, "type=36 ", "cot=3 ", "ca=70 ", "ioa=301 "))
	if f["value"] != "7.5" || f["t56"] == "-" {
		t.Errorf("lib60870 read %v", f)
	}

	p.send("send type=45 ioa=5000 v=1 sel=1")
	slave.expect(10*time.Second, "type=45 ", "cot=6 ", "ioa=5000 ", "select=1")
	p.expect(10*time.Second, "type=45 ", "cot=7 ", "neg=0", "ca=70 ", "select=1")
	p.send("send type=45 ioa=5000 v=1")
	slave.expect(10*time.Second, "type=45 ", "cot=6 ", "ioa=5000 ", "select=0")
	p.expect(10*time.Second, "type=45 ", "cot=7 ", "neg=0", "ca=70 ", "select=0")
	p.expect(10*time.Second, "type=45 ", "cot=10 ", "ca=70 ")

	p.send("send type=45 ioa=4999 v=1")
	p.expect(10*time.Second, "type=45 ", "cot=47 ", "neg=1", "ca=70 ")

	p.send("send type=101 v=5")
	slave.expect(10*time.Second, "CI qcc=5")
	p.expect(10*time.Second, "type=101 ", "cot=7 ", "neg=0", "ca=70 ")
	p.expect(10*time.Second, "type=15 ", "cot=37 ", "ca=70 ", "ioa=400 ", "value=123456 ")
	p.expect(10*time.Second, "type=101 ", "cot=10 ", "ca=70 ")

	p.send("send type=102 ioa=100")
	p.expect(5*time.Second, "type=1 ", "cot=5 ", "ca=70 ", "ioa=100 ")
}
