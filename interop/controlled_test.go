// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package interop

import (
	"context"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/cB-Sigma/iec60870"
	"github.com/cB-Sigma/iec60870/cs101"
	"github.com/cB-Sigma/iec60870/cs104"
)

// respond is a small controlled station: it confirms and terminates what
// a controlling station sends (a clock synchronisation with IV set is
// refused) and answers an interrogation with one point. It records what
// it received in got.
func respond(got *collector, a *iec60870.ASDU, reply func(*iec60870.ASDU)) {
	got.add(a)
	mirror := func(c iec60870.Cause, neg bool) {
		m := *a
		m.Cause, m.Negative = c, neg
		reply(&m)
	}
	switch {
	case a.Type == iec60870.CIcNa1:
		mirror(iec60870.CauseActCon, false)
		reply(&iec60870.ASDU{Type: iec60870.MMeNc1, Cause: iec60870.CauseInterrogated, CA: a.CA,
			Objects: []iec60870.Object{{IOA: 200, Value: 230.5}}})
		mirror(iec60870.CauseActTerm, false)
	case a.Type == iec60870.CCsNa1:
		mirror(iec60870.CauseActCon, a.Objects[0].TimeInvalid)
	case a.Type >= iec60870.CScNa1 && a.Type <= iec60870.CBoTa1:
		if a.Cause == iec60870.CauseDeactivation {
			mirror(iec60870.CauseDeactCon, false)
			return
		}
		mirror(iec60870.CauseActCon, false)
		if !a.Objects[0].Select {
			mirror(iec60870.CauseActTerm, false)
		}
	case a.Type == iec60870.CRdNa1:
		reply(&iec60870.ASDU{Type: iec60870.MSpNa1, Cause: iec60870.CauseRequest, CA: a.CA,
			Objects: []iec60870.Object{{IOA: a.Objects[0].IOA, Value: 1}}})
	case a.Type.Control():
		mirror(iec60870.CauseActCon, false)
	}
}

// encodeMonitor makes the ASDU of a monitor case as our station sends it.
func encodeMonitor(t *testing.T, c monitorCase, ioa uint32, prm iec60870.Params) []byte {
	t.Helper()
	o := c.want
	o.IOA, o.Time, o.TimeInvalid, o.TimeSubstituted = ioa, stamp, c.iv, c.sub
	b, err := (&iec60870.ASDU{Type: c.typ, Cause: iec60870.CauseSpontaneous, CA: 1, Objects: []iec60870.Object{o}}).Encode(prm, time.UTC)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// checkPeerMonitor compares lib60870's reading of a monitor case.
func checkPeerMonitor(t *testing.T, c monitorCase, line string) {
	t.Helper()
	f := kv(line)
	w := c.want
	want := map[string]string{"value": strconv.FormatFloat(w.Value, 'g', 10, 64), "quality": strconv.Itoa(int(w.Quality))}
	switch c.typ {
	case iec60870.MItNa1, iec60870.MItTa1, iec60870.MItTb1:
		want["seq"] = strconv.Itoa(int(w.Seq))
	case iec60870.MEpTa1, iec60870.MEpTb1, iec60870.MEpTc1, iec60870.MEpTd1, iec60870.MEpTe1, iec60870.MEpTf1:
		want["el"] = strconv.Itoa(int(w.Elapsed.Milliseconds()))
	case iec60870.MPsNa1:
		want["cd"] = strconv.Itoa(int(w.Change))
	case iec60870.MStNa1, iec60870.MStTa1, iec60870.MStTb1:
		want["tr"] = "0"
		if w.Transient {
			want["tr"] = "1"
		}
	}
	if c.typ.CP24() {
		b := iec60870.CP24(stamp, c.iv, time.UTC)
		if c.sub {
			b[2] |= 0x40
		}
		want["t24"] = hex.EncodeToString(b)
	} else if c.typ.TimeTagged() {
		want["tf"] = tf(stamp, c.iv, false, c.sub)
	}
	for k, v := range want {
		if f[k] != v {
			t.Errorf("%s: lib60870 read %s=%s, want %s", c.typ, k, f[k], v)
		}
	}
}

// peerCommands are commands (and a set-point with time tag) the peer
// sends to our controlled stations, with what we must decode.
var peerCommands = []struct {
	send string
	typ  iec60870.TypeID
	want iec60870.Object
}{
	{"type=45 ioa=61 v=1 sel=1 qu=3", iec60870.CScNa1, iec60870.Object{IOA: 61, Value: 1, Select: true, Qualifier: 3}},
	{"type=46 ioa=62 v=2 qu=1", iec60870.CDcNa1, iec60870.Object{IOA: 62, Value: 2, Qualifier: 1}},
	{"type=47 ioa=63 v=1 sel=1 qu=2", iec60870.CRcNa1, iec60870.Object{IOA: 63, Value: 1, Select: true, Qualifier: 2}},
	{"type=48 ioa=64 v=-0.75 qu=4", iec60870.CSeNa1, iec60870.Object{IOA: 64, Value: -0.75, Qualifier: 4}},
	{"type=49 ioa=65 v=-2000 sel=1", iec60870.CSeNb1, iec60870.Object{IOA: 65, Value: -2000, Select: true}},
	{"type=50 ioa=66 v=99.5 qu=9", iec60870.CSeNc1, iec60870.Object{IOA: 66, Value: 99.5, Qualifier: 9}},
	{"type=51 ioa=67 v=2864434397", iec60870.CBoNa1, iec60870.Object{IOA: 67, Value: 0xaabbccdd}},
	{"type=58 ioa=68 v=0 qu=1", iec60870.CScTa1, iec60870.Object{IOA: 68, Value: 0, Qualifier: 1}},
	{"type=59 ioa=69 v=1 sel=1", iec60870.CDcTa1, iec60870.Object{IOA: 69, Value: 1, Select: true}},
	{"type=60 ioa=70 v=2", iec60870.CRcTa1, iec60870.Object{IOA: 70, Value: 2}},
	{"type=61 ioa=71 v=0.5 qu=1", iec60870.CSeTa1, iec60870.Object{IOA: 71, Value: 0.5, Qualifier: 1}},
	{"type=62 ioa=72 v=123", iec60870.CSeTb1, iec60870.Object{IOA: 72, Value: 123}},
	{"type=63 ioa=73 v=-7.25 sel=1", iec60870.CSeTc1, iec60870.Object{IOA: 73, Value: -7.25, Select: true}},
	{"type=64 ioa=74 v=1", iec60870.CBoTa1, iec60870.Object{IOA: 74, Value: 1}},
	{"type=101 v=5", iec60870.CCiNa1, iec60870.Object{Value: 5}},
	{"type=102 ioa=100", iec60870.CRdNa1, iec60870.Object{IOA: 100}},
	{"type=105 v=1", iec60870.CRpNa1, iec60870.Object{Value: 1}},
	{"type=107 v=4660", iec60870.CTsTa1, iec60870.Object{Value: 0x1234}},
	{"type=112 ioa=75 v=2.5 qu=1", iec60870.PMeNc1, iec60870.Object{IOA: 75, Value: 2.5, Qualifier: 1}},
}

// causeOf is the cause the peer sends a request with.
func causeOf(typ iec60870.TypeID) iec60870.Cause {
	if typ == iec60870.CRdNa1 {
		return iec60870.CauseRequest
	}
	return iec60870.CauseActivation
}

// expectAnswer waits for our station's positive answer to a request: the
// object read for C_RD_NA_1, the activation confirmation otherwise.
func expectAnswer(p *peer, within time.Duration, typ iec60870.TypeID) {
	if typ == iec60870.CRdNa1 {
		p.expect(within, "type=1 ", "cot=5 ", "neg=0")
		return
	}
	p.expect(within, fmt.Sprintf("type=%d ", typ), "cot=7 ", "neg=0")
}

// checkReceived compares a command our station decoded with the case.
func checkReceived(t *testing.T, typ iec60870.TypeID, o, w iec60870.Object) {
	t.Helper()
	if o.Value != w.Value || o.Select != w.Select || o.Qualifier != w.Qualifier {
		t.Errorf("%s: decoded value %v select %v qualifier %d; want %v %v %d", typ, o.Value, o.Select, o.Qualifier, w.Value, w.Select, w.Qualifier)
	}
	if typ.TimeTagged() && !o.Time.Equal(stamp) {
		t.Errorf("%s: time %s, want %s", typ, o.Time, stamp)
	}
}

// clockEdges are CP56Time2a octets the peer sends in clock
// synchronisations, with the time and IV we must read: SU set (ignored
// for clock synchronisation), IV set, a wrong day of week, the last
// millisecond of a minute, century boundaries.
var clockEdges = []struct {
	name string
	raw  string
	want time.Time
	iv   bool
}{
	{"SU set", "e8030a8c0b0a1a", time.Date(2026, 10, 11, 12, 10, 1, 0, time.UTC), false},
	{"IV set", "00008a0c0b0a1a", time.Date(2026, 10, 11, 12, 10, 0, 0, time.UTC), true},
	{"day of week wrong", "000000002b011a", time.Date(2026, 1, 11, 0, 0, 0, 0, time.UTC), false}, // 11 Jan 2026, DOW 1
	{"59 999 ms", "5fea3b17df0c63", time.Date(2099, 12, 31, 23, 59, 59, 999e6, time.UTC), false},
	{"year 00", "00000000c10100", time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC), false},
}

// TestLib60870ClientAgainstOurServer: lib60870 as controlling station
// against a controlled station built on cs104.Server: interrogation, every
// command type, system commands, clock synchronisation edge cases, and
// every monitor type encoded by us and read by lib60870.
func TestLib60870ClientAgainstOurServer(t *testing.T) {
	needDocker(t)
	prm := iec60870.Params{}.WithDefaults()
	var got collector
	g := &cs104.Group{}
	g.OnASDU = func(l *cs104.Link, b []byte) {
		a, err := iec60870.DecodeASDU(b, prm, time.UTC)
		if err != nil {
			t.Errorf("% X: %v", b, err)
			return
		}
		respond(&got, a, func(r *iec60870.ASDU) {
			out, err := r.Encode(prm, time.UTC)
			if err == nil {
				_ = l.Send(context.Background(), out)
			}
		})
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = (&cs104.Server{Groups: []*cs104.Group{g}}).Serve(ctx, ln) }()
	p := startPeer(t, "--add-host=host.docker.internal:host-gateway", image, "peer", "client104", "host.docker.internal",
		port(t, ln.Addr().String()))
	p.expect(60*time.Second, "READY")
	p.send("startdt")
	p.expect(10*time.Second, "EVENT 2")

	t.Run("interrogation", func(t *testing.T) {
		p.send("gi")
		p.expect(5*time.Second, "type=100 ", "cot=7 ")
		p.expect(5*time.Second, "type=13 ", "cot=20 ", "value=230.5")
		p.expect(5*time.Second, "type=100 ", "cot=10 ")
	})
	t.Run("commands", func(t *testing.T) {
		for _, c := range peerCommands {
			p.send(fmt.Sprintf("send %s t=%s", c.send, cp56Hex(stamp, false, false, false)))
			expectAnswer(p, 5*time.Second, c.typ)
			checkReceived(t, c.typ, got.find(t, c.typ, causeOf(c.typ), c.want.IOA, time.Second), c.want)
		}
	})
	t.Run("clock synchronisation", func(t *testing.T) {
		for _, c := range clockEdges {
			p.send("send type=103 t=" + c.raw)
			neg := "neg=0"
			if c.iv {
				neg = "neg=1"
			}
			p.expect(5*time.Second, "type=103 ", "cot=7 ", neg)
			var o iec60870.Object
			got.mu.Lock()
			for _, a := range got.asdus {
				if a.Type == iec60870.CCsNa1 {
					o = a.Objects[0]
				}
			}
			got.asdus = nil
			got.mu.Unlock()
			if !o.Time.Equal(c.want) || o.TimeInvalid != c.iv {
				t.Errorf("%s: decoded %s IV %v, want %s IV %v", c.name, o.Time, o.TimeInvalid, c.want, c.iv)
			}
		}
	})
	t.Run("monitor types", func(t *testing.T) {
		for i, c := range monitorCases {
			ioa := uint32(7000 + i)
			if err := g.Enqueue(encodeMonitor(t, c, ioa, prm)); err != nil {
				t.Fatal(err)
			}
			checkPeerMonitor(t, c, p.expect(5*time.Second, fmt.Sprintf("type=%d ", c.typ), fmt.Sprintf("ioa=%d ", ioa)))
		}
	})
}

// TestLib60870TLSClientAgainstOurServer: lib60870 (mbedtls) as TLS
// controlling station against cs104.Server on a crypto/tls listener that
// requires client certificates; a client certificate from an untrusted CA
// is refused.
func TestLib60870TLSClientAgainstOurServer(t *testing.T) {
	needDocker(t)
	k := newPKI(t)
	prm := iec60870.Params{}.WithDefaults()
	for _, v := range []struct {
		name string
		max  uint16
	}{{"TLS 1.2", tls.VersionTLS12}, {"TLS 1.3", tls.VersionTLS13}} {
		t.Run(v.name, func(t *testing.T) {
			var got collector
			g := &cs104.Group{}
			g.OnASDU = func(l *cs104.Link, b []byte) {
				a, err := iec60870.DecodeASDU(b, prm, time.UTC)
				if err != nil {
					return
				}
				respond(&got, a, func(r *iec60870.ASDU) {
					if out, err := r.Encode(prm, time.UTC); err == nil {
						_ = l.Send(context.Background(), out)
					}
				})
			}
			ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{k.ours}, ClientCAs: k.pool,
				ClientAuth: tls.RequireAndVerifyClientCert, MinVersion: tls.VersionTLS12, MaxVersion: v.max})
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			go func() { _ = (&cs104.Server{Groups: []*cs104.Group{g}}).Serve(ctx, ln) }()
			p := startPeer(t, "--add-host=host.docker.internal:host-gateway", "-v", k.dir+":/certs:ro", image, "peer", "client104",
				"host.docker.internal", port(t, ln.Addr().String()), "tls")
			p.expect(60*time.Second, "READY")
			p.send("startdt")
			p.expect(10*time.Second, "EVENT 2")
			p.send("gi")
			p.expect(5*time.Second, "type=13 ", "cot=20 ", "value=230.5")
			p.expect(5*time.Second, "type=100 ", "cot=10 ")
			p.send("send type=58 ioa=61 v=1 t=" + cp56Hex(stamp, false, false, false))
			p.expect(5*time.Second, "type=58 ", "cot=10 ")
			if err := g.Enqueue(encodeMonitor(t, monitorCases[len(monitorCases)-1], 7001, prm)); err != nil {
				t.Fatal(err)
			}
			checkPeerMonitor(t, monitorCases[len(monitorCases)-1], p.expect(5*time.Second, "type=40 ", "ioa=7001 "))

			rogue := startPeer(t, "--add-host=host.docker.internal:host-gateway", "-v", k.rogueDir+":/certs:ro", image, "peer",
				"client104", "host.docker.internal", port(t, ln.Addr().String()), "tls")
			rogue.send("startdt")
			l := rogue.expectAny(30*time.Second, "CONNECT-FAILED", "EVENT 1", "EVENT 4", "EVENT 2")
			if strings.Contains(l, "EVENT 2") {
				t.Error("a client certificate from an untrusted CA was accepted")
			}
		})
	}
}

// TestLib60870MasterAgainstOurSecondary: lib60870 as IEC 101 controlling
// station (balanced and unbalanced, each field size) against cs101.Secondary.
func TestLib60870MasterAgainstOurSecondary(t *testing.T) {
	needDocker(t)
	for _, cfg := range lines101 {
		t.Run(cfg.String(), func(t *testing.T) {
			prm := cfg.params()
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
			s := cs101.NewSecondary(cs101.NewPort(conn), cs101.SecondaryConfig{LinkAddress: 3, AddrSize: cfg.la, Balanced: cfg.balanced,
				LinkTimeout: 30 * time.Second, Timeout: 500 * time.Millisecond, Retries: 3, TestPeriod: 5 * time.Second})
			defer s.Close()
			go func() { _ = s.Run(ctx) }()
			var got collector
			go func() {
				for b := range s.ASDUs() {
					a, err := iec60870.DecodeASDU(b, prm, time.UTC)
					if err != nil {
						t.Errorf("% X: %v", b, err)
						continue
					}
					respond(&got, a, func(r *iec60870.ASDU) {
						if out, err := r.Encode(prm, time.UTC); err == nil {
							_ = s.Send(ctx, out)
						}
					})
				}
			}()
			p.expect(60*time.Second, "READY")
			p.send("gi")
			p.expect(10*time.Second, "type=100", "cot=7 ")
			p.expect(10*time.Second, "type=13 ", "cot=20", "ioa=200", "value=230.5")
			p.expect(10*time.Second, "type=100", "cot=10")
			for _, c := range peerCommands {
				p.send(fmt.Sprintf("send %s t=%s", c.send, cp56Hex(stamp, false, false, false)))
				expectAnswer(p, 10*time.Second, c.typ)
				checkReceived(t, c.typ, got.find(t, c.typ, causeOf(c.typ), c.want.IOA, time.Second), c.want)
			}
			for i, c := range monitorCases {
				ioa := uint32(150 + i)
				if err := s.Send(ctx, encodeMonitor(t, c, ioa, prm)); err != nil {
					t.Fatal(err)
				}
				checkPeerMonitor(t, c, p.expect(10*time.Second, fmt.Sprintf("type=%d ", c.typ), fmt.Sprintf("ioa=%d ", ioa)))
			}
		})
	}
}

// port is the port of a listening address.
func port(t *testing.T, addr string) string {
	t.Helper()
	_, p, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatal(err)
	}
	return p
}
