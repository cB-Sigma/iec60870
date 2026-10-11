// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package interop

import (
	"context"
	"crypto/tls"
	"fmt"
	"testing"
	"time"

	"github.com/cB-Sigma/iec60870"
	"github.com/cB-Sigma/iec60870/cs104"
	"github.com/cB-Sigma/iotsec"
)

// dialStandby retries DialStandby until the peer listens.
func dialStandby(t *testing.T, addr string, cfg cs104.LinkConfig) *cs104.Link {
	t.Helper()
	var err error
	for i := 0; i < 50; i++ {
		var l *cs104.Link
		if l, err = cs104.DialStandby(context.Background(), addr, cfg); err == nil {
			t.Cleanup(l.Close)
			return l
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatal(err)
	return nil
}

// spontaneous asks the peer for a spontaneous M_ME_NC_1 at each address.
func spontaneous(p *peer, ioas ...int) {
	for _, ioa := range ioas {
		p.send(fmt.Sprintf("send type=13 ioa=%d v=%d", ioa, ioa))
		p.expect(5*time.Second, "QUEUED")
	}
}

// TestRedundancyAgainstLib60870: our DialStandby, StartDT and StopDT
// against lib60870's redundancy groups (one group, and several groups
// with a catch-all): starting the standby closes the started connection,
// what it sent without acknowledgement comes again on the standby, and
// what is queued while no connection is started arrives on the next one.
func TestRedundancyAgainstLib60870(t *testing.T) {
	needDocker(t)
	for _, mode := range []string{"mode=single", "mode=multi"} {
		t.Run(mode, func(t *testing.T) {
			port := freePort(t)
			p := startPeer(t, "-p", fmt.Sprintf("127.0.0.1:%d:2404", port), image, "peer", "server104", mode)
			p.expect(60*time.Second, "READY")
			addr := fmt.Sprintf("127.0.0.1:%d", port)
			// The first connection acknowledges nothing (w above what is
			// sent, t2 just under t1).
			a := dialPeer(t, addr, cs104.LinkConfig{W: 100, T1: 20 * time.Second, T2: 19 * time.Second})
			var gotA, gotB collector
			cs104.NewClient(a, cs104.ClientConfig{CA: 1, OnData: gotA.add})
			spontaneous(p, 101, 102, 103)
			gotA.find(t, iec60870.MMeNc1, iec60870.CauseSpontaneous, 103, 5*time.Second)

			b := dialStandby(t, addr, cs104.LinkConfig{})
			cs104.NewClient(b, cs104.ClientConfig{CA: 1, OnData: gotB.add})
			ctx := context.Background()
			if err := b.StartDT(ctx); err != nil {
				t.Fatal(err)
			}
			select {
			case <-a.Done():
			case <-time.After(5 * time.Second):
				t.Fatal("lib60870 kept the first connection open")
			}
			for _, ioa := range []uint32{101, 102, 103} {
				gotB.find(t, iec60870.MMeNc1, iec60870.CauseSpontaneous, ioa, 5*time.Second)
			}
			spontaneous(p, 104)
			gotB.find(t, iec60870.MMeNc1, iec60870.CauseSpontaneous, 104, 5*time.Second)

			if err := b.StopDT(ctx); err != nil {
				t.Fatal(err)
			}
			spontaneous(p, 105, 106)
			time.Sleep(300 * time.Millisecond)
			c := dialStandby(t, addr, cs104.LinkConfig{})
			var gotC collector
			cs104.NewClient(c, cs104.ClientConfig{CA: 1, OnData: gotC.add})
			if err := c.StartDT(ctx); err != nil {
				t.Fatal(err)
			}
			gotC.find(t, iec60870.MMeNc1, iec60870.CauseSpontaneous, 105, 5*time.Second)
			gotC.find(t, iec60870.MMeNc1, iec60870.CauseSpontaneous, 106, 5*time.Second)
			if !b.Stopped() {
				t.Error("the stopped standby is not stopped")
			}
		})
	}
	t.Run("each connection its own group", func(t *testing.T) {
		port := freePort(t)
		p := startPeer(t, "-p", fmt.Sprintf("127.0.0.1:%d:2404", port), image, "peer", "server104", "mode=conn")
		p.expect(60*time.Second, "READY")
		addr := fmt.Sprintf("127.0.0.1:%d", port)
		var gotA, gotB collector
		cs104.NewClient(dialPeer(t, addr, cs104.LinkConfig{}), cs104.ClientConfig{CA: 1, OnData: gotA.add})
		cs104.NewClient(dialPeer(t, addr, cs104.LinkConfig{}), cs104.ClientConfig{CA: 1, OnData: gotB.add})
		spontaneous(p, 201)
		gotA.find(t, iec60870.MMeNc1, iec60870.CauseSpontaneous, 201, 5*time.Second)
		gotB.find(t, iec60870.MMeNc1, iec60870.CauseSpontaneous, 201, 5*time.Second)
	})
}

// TestTLSRefusals: lib60870's TLS controlled station refuses a client
// without a certificate or with one from an untrusted CA, and our client
// refuses a station whose certificate it cannot verify.
func TestTLSRefusals(t *testing.T) {
	needDocker(t)
	k := newPKI(t)
	port := freePort(t)
	p := startPeer(t, "-p", fmt.Sprintf("127.0.0.1:%d:19998", port), "-v", k.dir+":/certs:ro", image, "peer", "server104", "tls")
	p.expect(60*time.Second, "READY")
	addr := fmt.Sprintf("127.0.0.1:%d", port)
	// The peer is up: a good client gets through.
	dialPeer(t, addr, cs104.LinkConfig{TLS: iotsec.StdTLS{Config: &tls.Config{RootCAs: k.pool, Certificates: []tls.Certificate{k.ours}}}})
	for _, x := range []struct {
		name string
		cfg  *tls.Config
	}{
		{"no client certificate", &tls.Config{RootCAs: k.pool}},
		{"client certificate from an untrusted CA", &tls.Config{RootCAs: k.pool, Certificates: []tls.Certificate{k.rogue}}},
		{"station certificate we do not trust", &tls.Config{RootCAs: k.roguePool, Certificates: []tls.Certificate{k.ours}}},
		{"TLS 1.3 without a client certificate", &tls.Config{RootCAs: k.pool, MinVersion: tls.VersionTLS13}},
	} {
		t.Run(x.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			l, err := cs104.Dial(ctx, addr, cs104.LinkConfig{T1: 3 * time.Second, T2: time.Second, TLS: iotsec.StdTLS{Config: x.cfg}})
			if err == nil {
				// TLS 1.3 reports a refused client certificate after the
				// handshake: the connection must not carry data.
				c := cs104.NewClient(l, cs104.ClientConfig{CA: 1, Timeout: 2 * time.Second})
				if err := c.Interrogate(ctx, iec60870.QOIStation, 2*time.Second); err == nil {
					t.Fatal("the connection was accepted and carried data")
				}
				l.Close()
			}
		})
	}
}
