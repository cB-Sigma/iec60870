// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package station_test

import (
	"context"
	"fmt"
	"time"

	"github.com/cB-Sigma/iec60870"
	"github.com/cB-Sigma/iec60870/station"
)

// A station with two points and a command answers a station
// interrogation. A real station is served with Group (IEC 104) or
// ServeSecondary (IEC 101); here a session prints what it would send.
func ExampleStation() {
	st := station.New(station.Config{CA: 1})
	st.Add(station.Point{Type: iec60870.MDpTb1, Object: iec60870.Object{IOA: 1001, Value: 2}})
	st.Add(station.Point{Type: iec60870.MMeNc1, Object: iec60870.Object{IOA: 3001, Value: 230.5}})
	st.AddControl(station.Control{IOA: 2001, Type: iec60870.CDcNa1, Monitor: 1001, SelectRequired: true})

	prm := iec60870.Params{}.WithDefaults()
	out := make(chan *iec60870.ASDU, 16)
	se := st.Attach(station.SessionConfig{Send: func(_ context.Context, b []byte) error {
		a, err := iec60870.DecodeASDU(b, prm, time.UTC)
		if err == nil {
			out <- a
		}
		return err
	}})
	defer se.Close()
	se.HandleASDU(&iec60870.ASDU{Type: iec60870.CIcNa1, Cause: iec60870.CauseActivation, CA: 1,
		Objects: []iec60870.Object{{Value: iec60870.QOIStation}}})
	for range 4 {
		a := <-out
		fmt.Println(a.Type, a.Cause, len(a.Objects))
	}
	// Output:
	// C_IC_NA_1 activation confirmation 1
	// M_DP_NA_1 station interrogation 1
	// M_ME_NC_1 station interrogation 1
	// C_IC_NA_1 activation termination 1
}
