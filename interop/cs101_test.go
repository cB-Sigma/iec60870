// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package interop

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/cB-Sigma/iec60870"
	"github.com/cB-Sigma/iec60870/cs101"
)

// line101 is one IEC 101 configuration: link mode and field sizes.
type line101 struct {
	balanced         bool
	la, cot, ca, ioa int
}

func (c line101) String() string {
	m := "unbalanced"
	if c.balanced {
		m = "balanced"
	}
	return fmt.Sprintf("%s link address %d cot %d ca %d ioa %d", m, c.la, c.cot, c.ca, c.ioa)
}

// args are the peer's options for c.
func (c line101) args() []string {
	b := "0"
	if c.balanced {
		b = "1"
	}
	return []string{"bal=" + b, fmt.Sprintf("la=%d", c.la), fmt.Sprintf("cot=%d", c.cot), fmt.Sprintf("ca=%d", c.ca), fmt.Sprintf("ioa=%d", c.ioa)}
}

func (c line101) params() iec60870.Params {
	return iec60870.Params{COTSize: c.cot, CASize: c.ca, IOASize: c.ioa, Originator: 7}
}

// lines101 are the configurations run: the usual one, the widest, mixed
// sizes, and balanced lines with no, one and two link address octets.
var lines101 = []line101{
	{false, 1, 1, 1, 2},
	{false, 2, 2, 2, 3},
	{false, 1, 1, 2, 1},
	{true, 0, 2, 1, 2},
	{true, 1, 1, 1, 2},
	{true, 2, 2, 2, 3},
}

func dialTCP(t *testing.T, addr string) net.Conn {
	t.Helper()
	var conn net.Conn
	var err error
	for i := 0; i < 50; i++ {
		if conn, err = net.Dial("tcp", addr); err == nil {
			return conn
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatal(err)
	return nil
}

// TestCS101ClientAgainstLib60870: cs101.Client (unbalanced and balanced)
// against a lib60870 station: the procedures of the Client and file
// transfer in both directions through lib60870's file service.
func TestCS101ClientAgainstLib60870(t *testing.T) {
	needDocker(t)
	for _, bal := range []bool{false, true} {
		cfg := line101{bal, 1, 1, 1, 2}
		t.Run(cfg.String(), func(t *testing.T) {
			port := freePort(t)
			p := startPeer(t, append([]string{"-p", fmt.Sprintf("127.0.0.1:%d:2410", port), image, "serial101.sh", "slave", "3",
				"filesize=700"}, cfg.args()...)...)
			p.expect(60*time.Second, "READY")
			link := cs101.NewLink(cs101.NewPort(dialTCP(t, fmt.Sprintf("127.0.0.1:%d", port))), 1, bal, time.Second, 3)
			defer link.Close()
			ctx := context.Background()
			if err := link.Start(ctx, 3); err != nil {
				t.Fatal(err)
			}
			var got collector
			c := cs101.NewClient(link, cs101.ClientConfig{Address: 3, CA: 1, Timeout: 5 * time.Second, PollInterval: 20 * time.Millisecond, OnData: got.add})
			defer c.Close()
			if err := c.Interrogate(ctx, iec60870.QOIStation, 5*time.Second); err != nil {
				t.Fatal(err)
			}
			got.find(t, iec60870.MMeNc1, iec60870.CauseInterrogated, 200, time.Second)
			if _, err := c.Operate(ctx, iec60870.Operation{Type: iec60870.CSeTc1, Object: iec60870.Object{IOA: 5000, Value: 2.5},
				SelectBeforeOperate: true, TimeTag: true, Termination: 5 * time.Second}); err != nil {
				t.Fatal(err)
			}
			if err := c.ClockSync(ctx, time.Now()); err != nil {
				t.Error(err)
			}
			if err := c.CounterInterrogate(ctx, iec60870.QCC(iec60870.RQTGeneral, iec60870.FRZRead), 5*time.Second); err != nil {
				t.Error(err)
			}
			got.find(t, iec60870.MItNa1, iec60870.CauseCounterGen, 400, time.Second)
			if err := c.Test(ctx); err != nil {
				t.Errorf("test command: %v", err)
			}
			if err := c.ResetProcess(ctx, iec60870.QRPGeneral); err != nil {
				t.Error(err)
			}
			if a, err := iec60870.Read(ctx, c, 100, 5*time.Second); err != nil || a.Objects[0].Value != 1 {
				t.Errorf("read %v %v", a, err)
			}
			if _, err := iec60870.DelayAcquisition(ctx, c, 5*time.Second); err != nil {
				t.Errorf("delay acquisition: %v", err)
			}
			data, err := iec60870.GetFile(ctx, c, 1000, 1, 5*time.Second)
			if err != nil {
				t.Fatalf("file download: %v", err)
			}
			if len(data) != 700 || data[699] != fileByte(699) {
				t.Errorf("downloaded %d octets", len(data))
			}
			up := make([]byte, 1000)
			var h uint32
			for i := range up {
				up[i] = byte(i * 3)
				h = h*31 + uint32(up[i])
			}
			if err := iec60870.PutFile(ctx, c, 2000, 1, up, 5*time.Second); err != nil {
				t.Fatalf("file upload: %v", err)
			}
			f := kv(p.expect(10*time.Second, "FILE-RECEIVED"))
			if f["len"] != "1000" || f["hash"] != strconv.FormatUint(uint64(h), 10) {
				t.Errorf("peer received %v", f)
			}
		})
	}
}

// TestCS101LinkConfigurations: our controlling station's link (balanced
// and unbalanced) against a lib60870 station on a pty, for each field
// size: interrogation, clock synchronisation, select-before-operate,
// spontaneous and time-tagged data, originator address.
func TestCS101LinkConfigurations(t *testing.T) {
	needDocker(t)
	for _, cfg := range lines101 {
		t.Run(cfg.String(), func(t *testing.T) {
			port := freePort(t)
			p := startPeer(t, append([]string{"-p", fmt.Sprintf("127.0.0.1:%d:2410", port), image, "serial101.sh", "slave", "3"}, cfg.args()...)...)
			p.expect(60*time.Second, "READY")
			conn := dialTCP(t, fmt.Sprintf("127.0.0.1:%d", port))
			link := cs101.NewLink(cs101.NewPort(conn), cfg.la, cfg.balanced, time.Second, 3)
			defer link.Close()
			ctx := context.Background()
			if err := link.Start(ctx, 3); err != nil {
				t.Fatalf("link start: %v", err)
			}
			prm := cfg.params()
			cmdIOA, spIOA := uint32(5000), uint32(300)
			if cfg.ioa == 1 {
				cmdIOA, spIOA = 250, 30
			}
			var got collector
			decode := func(b []byte) {
				a, err := iec60870.DecodeASDU(b, prm, time.UTC)
				if err != nil {
					t.Errorf("% X: %v", b, err)
					return
				}
				got.add(a)
			}
			if cfg.balanced {
				go func() {
					for b := range link.ASDUs() {
						decode(b)
					}
				}()
			}
			// wait polls (unbalanced) or waits (balanced) until until holds.
			wait := func(until func() bool) {
				t.Helper()
				deadline := time.Now().Add(10 * time.Second)
				for !until() {
					if time.Now().After(deadline) {
						t.Fatal("timed out")
					}
					if cfg.balanced {
						time.Sleep(20 * time.Millisecond)
						continue
					}
					_ = link.Poll(ctx, 3, 16, decode)
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
				a.Orig = 7
				b, err := a.Encode(prm, time.UTC)
				if err != nil {
					t.Fatal(err)
				}
				if err := link.Send(ctx, 3, b); err != nil {
					t.Fatal(err)
				}
			}

			send(&iec60870.ASDU{Type: iec60870.CIcNa1, Cause: iec60870.CauseActivation, CA: 1, Objects: []iec60870.Object{{Value: iec60870.QOIStation}}})
			wait(has(iec60870.CIcNa1, iec60870.CauseActTerm))
			if o := got.find(t, iec60870.MMeNc1, iec60870.CauseInterrogated, 200, 0); o.Value != 230.5 {
				t.Errorf("measured value 200: %+v", o)
			}
			now := time.Now().Truncate(time.Millisecond)
			send(&iec60870.ASDU{Type: iec60870.CCsNa1, Cause: iec60870.CauseActivation, CA: 1, Objects: []iec60870.Object{{Time: now}}})
			wait(has(iec60870.CCsNa1, iec60870.CauseActCon))
			line := p.expect(5*time.Second, "CLOCK")
			if ms, _ := strconv.ParseInt(strings.Fields(line)[1], 10, 64); !time.UnixMilli(ms).Equal(now) {
				t.Errorf("peer set %s, sent %s", time.UnixMilli(ms).UTC(), now.UTC())
			}
			send(&iec60870.ASDU{Type: iec60870.CScNa1, Cause: iec60870.CauseActivation, CA: 1, Objects: []iec60870.Object{{IOA: cmdIOA, Value: 1, Select: true}}})
			wait(has(iec60870.CScNa1, iec60870.CauseActCon))
			f := kv(p.expect(5*time.Second, "type=45 ", fmt.Sprintf("ioa=%d ", cmdIOA), "select=1"))
			if cfg.cot == 2 && f["oa"] != "7" {
				t.Errorf("originator address read as %s", f["oa"])
			}
			send(&iec60870.ASDU{Type: iec60870.CScNa1, Cause: iec60870.CauseActivation, CA: 1, Objects: []iec60870.Object{{IOA: cmdIOA, Value: 1}}})
			wait(has(iec60870.CScNa1, iec60870.CauseActTerm))

			p.send(fmt.Sprintf("spont %d 12.5", spIOA))
			wait(has(iec60870.MMeNc1, iec60870.CauseSpontaneous))
			if o := got.find(t, iec60870.MMeNc1, iec60870.CauseSpontaneous, spIOA, 0); o.Value != 12.5 {
				t.Errorf("spontaneous 300: %+v", o)
			}
			// Every monitor type through this line's field sizes.
			for i, c := range monitorCases {
				ioa := uint32(150 + i)
				p.send(fmt.Sprintf("send type=%d ioa=%d %s t=%s oa=9", c.typ, ioa, c.args, cp56Hex(stamp, c.iv, false, c.sub)))
				wait(func() bool {
					got.mu.Lock()
					defer got.mu.Unlock()
					for _, a := range got.asdus {
						if a.Type == c.typ && len(a.Objects) > 0 && a.Objects[0].IOA == ioa {
							return true
						}
					}
					return false
				})
				checkMonitor(t, c, got.find(t, c.typ, iec60870.CauseSpontaneous, ioa, 0), stamp)
			}
		})
	}
}
