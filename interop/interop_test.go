// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

// Package interop runs this module's controlling station (IEC 104 client
// and IEC 101 primary link) against lib60870-C v2.4.1
// (github.com/mz-automation/lib60870, GPLv3, used only as a test peer in a
// container built from ./peer). The tests are skipped unless
// SIGMA_IEC60870_INTEROP=1 is set and Docker is running.
package interop

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cB-Sigma/iec60870"
	"github.com/cB-Sigma/iec60870/cs101"
	"github.com/cB-Sigma/iec60870/cs104"
	"github.com/cB-Sigma/iotsec"
)

// collector keeps the ASDUs a client receives.
type collector struct {
	mu    sync.Mutex
	asdus []*iec60870.ASDU
}

func (c *collector) add(a *iec60870.ASDU) {
	c.mu.Lock()
	c.asdus = append(c.asdus, a)
	c.mu.Unlock()
}

// find waits for an ASDU of the type and cause with an object at ioa.
func (c *collector) find(t *testing.T, typ iec60870.TypeID, cause iec60870.Cause, ioa uint32, within time.Duration) iec60870.Object {
	t.Helper()
	deadline := time.Now().Add(within)
	for {
		c.mu.Lock()
		for _, a := range c.asdus {
			if a.Type == typ && a.Cause == cause {
				for _, o := range a.Objects {
					if o.IOA == ioa {
						c.mu.Unlock()
						return o
					}
				}
			}
		}
		c.mu.Unlock()
		if time.Now().After(deadline) {
			c.mu.Lock()
			defer c.mu.Unlock()
			var got []string
			for _, a := range c.asdus {
				got = append(got, a.String())
			}
			t.Fatalf("no %s cause %d IOA %d; received %v", typ, cause, ioa, got)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func dialPeer(t *testing.T, addr string, cfg cs104.LinkConfig) *cs104.Link {
	t.Helper()
	ctx := context.Background()
	var l *cs104.Link
	var err error
	for i := 0; i < 50; i++ {
		if l, err = cs104.Dial(ctx, addr, cfg); err == nil {
			t.Cleanup(l.Close)
			return l
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatal(err)
	return nil
}

// commands runs the command procedures against a peer that confirms
// and terminates commands and prints what it receives.
func commands(t *testing.T, c *cs104.Client, p *peer) {
	ctx := context.Background()
	t.Run("single command select before operate", func(t *testing.T) {
		p.drain()
		_, err := c.Operate(ctx, iec60870.Operation{Type: iec60870.CScNa1, Object: iec60870.Object{IOA: 5000, Value: 1},
			SelectBeforeOperate: true, Termination: 5 * time.Second})
		if err != nil {
			t.Fatal(err)
		}
		p.expect(5*time.Second, "type=45", "cot=6", "ioa=5000", "value=1", "select=1")
		p.expect(5*time.Second, "type=45", "cot=6", "ioa=5000", "value=1", "select=0")
	})
	t.Run("double command direct", func(t *testing.T) {
		_, err := c.Operate(ctx, iec60870.Operation{Type: iec60870.CDcNa1, Object: iec60870.Object{IOA: 5001, Value: 2},
			Termination: 5 * time.Second})
		if err != nil {
			t.Fatal(err)
		}
		p.expect(5*time.Second, "type=46", "ioa=5001", "value=2", "select=0")
	})
	t.Run("set-point select before operate", func(t *testing.T) {
		_, err := c.Operate(ctx, iec60870.Operation{Type: iec60870.CSeNc1, Object: iec60870.Object{IOA: 5002, Value: 12.5},
			SelectBeforeOperate: true, Termination: 5 * time.Second})
		if err != nil {
			t.Fatal(err)
		}
		p.expect(5*time.Second, "type=50", "ioa=5002", "value=12.5", "select=1")
		p.expect(5*time.Second, "type=50", "ioa=5002", "value=12.5", "select=0")
	})
}

func clockSync(t *testing.T, c *cs104.Client, p *peer) {
	now := time.Now().Truncate(time.Millisecond)
	if err := c.ClockSync(context.Background(), now); err != nil {
		t.Fatal(err)
	}
	line := p.expect(5*time.Second, "CLOCK")
	ms, _ := strconv.ParseInt(strings.Fields(line)[1], 10, 64)
	if !time.UnixMilli(ms).Equal(now) {
		t.Errorf("peer set %s, sent %s", time.UnixMilli(ms).UTC(), now.UTC())
	}
}

// TestClientAgainstLib60870Server: interrogation, spontaneous data, clock
// synchronisation and commands against a lib60870 controlled station.
func TestClientAgainstLib60870Server(t *testing.T) {
	needDocker(t)
	port := freePort(t)
	p := startPeer(t, "-p", fmt.Sprintf("127.0.0.1:%d:2404", port), image, "peer", "server104")
	p.expect(60*time.Second, "READY")
	l := dialPeer(t, fmt.Sprintf("127.0.0.1:%d", port), cs104.LinkConfig{})
	var got collector
	c := cs104.NewClient(l, cs104.ClientConfig{CA: 1, OnData: got.add})
	ctx := context.Background()

	t.Run("general interrogation", func(t *testing.T) {
		if err := c.Interrogate(ctx, iec60870.QOIStation, 5*time.Second); err != nil {
			t.Fatal(err)
		}
		if o := got.find(t, iec60870.MSpNa1, iec60870.CauseInterrogated, 100, time.Second); o.Value != 1 {
			t.Errorf("single point 100: %+v", o)
		}
		if o := got.find(t, iec60870.MMeNc1, iec60870.CauseInterrogated, 200, time.Second); o.Value != 230.5 {
			t.Errorf("measured value 200: %+v", o)
		}
	})
	t.Run("spontaneous", func(t *testing.T) {
		p.send("spont 300 12.5")
		if o := got.find(t, iec60870.MMeNc1, iec60870.CauseSpontaneous, 300, 5*time.Second); o.Value != 12.5 {
			t.Errorf("spontaneous 300: %+v", o)
		}
	})
	t.Run("clock synchronisation", func(t *testing.T) { clockSync(t, c, p) })
	commands(t, c, p)
}

// TestClientAgainstLib60870StockServer: lib60870's own cs104_server
// example (sequences of elements, scaled values, a bitstring, periodic
// data, a single command at IOA 5000 confirmed without termination).
func TestClientAgainstLib60870StockServer(t *testing.T) {
	needDocker(t)
	port := freePort(t)
	p := startPeer(t, "-p", fmt.Sprintf("127.0.0.1:%d:2404", port), image, "stdbuf", "-oL", "cs104_server")
	p.expect(60*time.Second, "w:")
	l := dialPeer(t, fmt.Sprintf("127.0.0.1:%d", port), cs104.LinkConfig{})
	var got collector
	c := cs104.NewClient(l, cs104.ClientConfig{CA: 1, OnData: got.add})
	ctx := context.Background()
	if err := c.Interrogate(ctx, iec60870.QOIStation, 5*time.Second); err != nil {
		t.Fatal(err)
	}
	if o := got.find(t, iec60870.MMeNb1, iec60870.CauseInterrogated, 102, time.Second); o.Value != 2300 {
		t.Errorf("scaled 102: %+v", o)
	}
	if o := got.find(t, iec60870.MSpNa1, iec60870.CauseInterrogated, 307, time.Second); o.Value != 0 {
		t.Errorf("sequence element 307: %+v", o)
	}
	if o := got.find(t, iec60870.MSpNa1, iec60870.CauseInterrogated, 306, time.Second); o.Value != 1 {
		t.Errorf("sequence element 306: %+v", o)
	}
	if o := got.find(t, iec60870.MBoNa1, iec60870.CauseInterrogated, 500, time.Second); o.Value != 0xaaaa {
		t.Errorf("bitstring 500: %+v", o)
	}
	got.find(t, iec60870.MMeNb1, iec60870.CausePeriodic, 110, 5*time.Second)
	if err := c.ClockSync(ctx, time.Now()); err != nil {
		t.Errorf("clock sync: %v", err)
	}
	p.expect(5*time.Second, "Process time sync command")
	if _, err := c.Operate(ctx, iec60870.Operation{Type: iec60870.CScNa1, Object: iec60870.Object{IOA: 5000, Value: 1},
		SelectBeforeOperate: true}); err != nil {
		t.Errorf("single command: %v", err)
	}
	p.expect(5*time.Second, "IOA: 5000 switch to 1")
	// Unknown object: the station answers with a negative confirmation.
	if _, err := c.Operate(ctx, iec60870.Operation{Type: iec60870.CScNa1, Object: iec60870.Object{IOA: 4999, Value: 1}}); err == nil {
		t.Error("a command to an unknown object succeeded")
	}
}

// TestClientTLS: the same procedures over TLS (crypto/tls through
// iotsec.StdTLS, mutual authentication) against lib60870 with mbedtls.
func TestClientTLS(t *testing.T) {
	needDocker(t)
	k := newPKI(t)
	for _, v := range []struct {
		name string
		max  uint16
	}{{"TLS 1.2", tls.VersionTLS12}, {"TLS 1.3", tls.VersionTLS13}} {
		t.Run(v.name, func(t *testing.T) {
			port := freePort(t)
			p := startPeer(t, "-p", fmt.Sprintf("127.0.0.1:%d:19998", port), "-v", k.dir+":/certs:ro", image, "peer", "server104", "tls")
			p.expect(60*time.Second, "READY")
			cfg := &tls.Config{RootCAs: k.pool, Certificates: []tls.Certificate{k.ours}, MinVersion: tls.VersionTLS12, MaxVersion: v.max}
			l := dialPeer(t, fmt.Sprintf("127.0.0.1:%d", port), cs104.LinkConfig{TLS: iotsec.StdTLS{Config: cfg}})
			var got collector
			c := cs104.NewClient(l, cs104.ClientConfig{CA: 1, OnData: got.add})
			if err := c.Interrogate(context.Background(), iec60870.QOIStation, 5*time.Second); err != nil {
				t.Fatal(err)
			}
			got.find(t, iec60870.MMeNc1, iec60870.CauseInterrogated, 200, time.Second)
			clockSync(t, c, p)
			commands(t, c, p)
		})
	}
}

// TestCS101LinkAgainstLib60870Slave: an unbalanced IEC 101 line to a
// lib60870 secondary on a pty, bridged to TCP by socat as a serial-to-IP
// converter would be.
func TestCS101LinkAgainstLib60870Slave(t *testing.T) {
	needDocker(t)
	port := freePort(t)
	p := startPeer(t, "-p", fmt.Sprintf("127.0.0.1:%d:2410", port), image, "serial101.sh", "slave", "3")
	p.expect(60*time.Second, "READY")
	var conn net.Conn
	var err error
	for i := 0; i < 50; i++ {
		if conn, err = net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", port)); err == nil {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if err != nil {
		t.Fatal(err)
	}
	link := cs101.NewLink(cs101.NewPort(conn), 1, false, time.Second, 3)
	defer link.Close()
	ctx := context.Background()
	if err := link.Start(ctx, 3); err != nil {
		t.Fatalf("link start: %v", err)
	}
	prm := iec60870.Params{COTSize: 1, CASize: 1, IOASize: 2}
	var got collector
	poll := func(until func() bool) {
		t.Helper()
		deadline := time.Now().Add(10 * time.Second)
		for !until() {
			if time.Now().After(deadline) {
				t.Fatal("timed out polling")
			}
			_ = link.Poll(ctx, 3, 16, func(b []byte) {
				a, err := iec60870.DecodeASDU(b, prm, time.UTC)
				if err != nil {
					t.Errorf("% X: %v", b, err)
					return
				}
				got.add(a)
			})
		}
	}
	has := func(typ iec60870.TypeID, cause iec60870.Cause) func() bool {
		return func() bool {
			got.mu.Lock()
			defer got.mu.Unlock()
			for _, a := range got.asdus {
				if a.Type == typ && a.Cause == cause {
					return true
				}
			}
			return false
		}
	}
	send := func(a *iec60870.ASDU) {
		t.Helper()
		b, err := a.Encode(prm, time.UTC)
		if err != nil {
			t.Fatal(err)
		}
		if err := link.Send(ctx, 3, b); err != nil {
			t.Fatal(err)
		}
	}

	t.Run("general interrogation", func(t *testing.T) {
		send(&iec60870.ASDU{Type: iec60870.CIcNa1, Cause: iec60870.CauseActivation, CA: 1, Objects: []iec60870.Object{{Value: iec60870.QOIStation}}})
		poll(has(iec60870.CIcNa1, iec60870.CauseActTerm))
		if o := got.find(t, iec60870.MMeNc1, iec60870.CauseInterrogated, 200, 0); o.Value != 230.5 {
			t.Errorf("measured value 200: %+v", o)
		}
		got.find(t, iec60870.MSpNa1, iec60870.CauseInterrogated, 100, 0)
	})
	t.Run("clock synchronisation", func(t *testing.T) {
		now := time.Now().Truncate(time.Millisecond)
		send(&iec60870.ASDU{Type: iec60870.CCsNa1, Cause: iec60870.CauseActivation, CA: 1, Objects: []iec60870.Object{{Time: now}}})
		poll(has(iec60870.CCsNa1, iec60870.CauseActCon))
		line := p.expect(5*time.Second, "CLOCK")
		ms, _ := strconv.ParseInt(strings.Fields(line)[1], 10, 64)
		if !time.UnixMilli(ms).Equal(now) {
			t.Errorf("peer set %s, sent %s", time.UnixMilli(ms).UTC(), now.UTC())
		}
	})
	t.Run("single command select before operate", func(t *testing.T) {
		send(&iec60870.ASDU{Type: iec60870.CScNa1, Cause: iec60870.CauseActivation, CA: 1, Objects: []iec60870.Object{{IOA: 5000, Value: 1, Select: true}}})
		poll(has(iec60870.CScNa1, iec60870.CauseActCon))
		p.expect(5*time.Second, "type=45", "ioa=5000", "select=1")
		send(&iec60870.ASDU{Type: iec60870.CScNa1, Cause: iec60870.CauseActivation, CA: 1, Objects: []iec60870.Object{{IOA: 5000, Value: 1}}})
		poll(has(iec60870.CScNa1, iec60870.CauseActTerm))
		p.expect(5*time.Second, "type=45", "ioa=5000", "select=0")
	})
	t.Run("spontaneous", func(t *testing.T) {
		p.send("spont 300 12.5")
		poll(has(iec60870.MMeNc1, iec60870.CauseSpontaneous))
		if o := got.find(t, iec60870.MMeNc1, iec60870.CauseSpontaneous, 300, 0); o.Value != 12.5 {
			t.Errorf("spontaneous 300: %+v", o)
		}
	})
}
