// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package sec_test

import (
	"fmt"
	"time"

	"github.com/cB-Sigma/iec60870/sec"
)

// Two endpoints in memory: the Station Association with pinned
// self-signed certificates and the Session Key Change run as soon as the
// link is up, then an application ASDU travels as Secure Data.
func ExampleNewPair() {
	scada, _ := sec.NewIdentity(sec.Secp256r1, "scada", time.Hour)
	rtu, _ := sec.NewIdentity(sec.Secp256r1, "rtu", time.Hour)
	p, err := sec.NewPair(
		sec.Config{Link: sec.TCP, Params: sec.Params104, MaxASDU: 249, CA: 1, AIM: 5,
			Key: scada.Key, Certificate: scada.Certificate, Trust: rtu.Pin()},
		sec.Config{Link: sec.TCP, Params: sec.Params104, MaxASDU: 249, CA: 1, AIS: 7,
			Key: rtu.Key, Certificate: rtu.Certificate, Trust: scada.Pin()})
	if err != nil {
		panic(err)
	}
	p.Controlled.LinkUp()
	p.Controlling.LinkUp()
	p.Pump()
	fmt.Println("session keys:", p.Controlling.Status().SessionKeysValid, p.Controlled.Status().SessionKeysValid)

	// C_SC_NA_1, cause 6, CA 1, IOA 2001, SCO 1 (IEC 104 sizes).
	cmd := []byte{45, 1, 6, 0, 1, 0, 0xd1, 0x07, 0, 1}
	segs, err := p.Controlling.Wrap(cmd)
	if err != nil {
		panic(err)
	}
	in, err := sec.Deliver(p.Controlled, segs)
	fmt.Println(in.Kind == sec.Data, err, fmt.Sprintf("% x", in.ASDU))
	// Output:
	// session keys: true true
	// true <nil> 2d 01 06 00 01 00 d1 07 00 01
}
