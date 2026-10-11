// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package iec60870_test

import (
	"fmt"
	"time"

	"github.com/cB-Sigma/iec60870"
)

// Encode a measured value with a time tag and read it back, with the
// IEC 104 field sizes.
func ExampleASDU_Encode() {
	p := iec60870.Params{}.WithDefaults()
	at := time.Date(2026, 10, 6, 9, 30, 0, 0, time.UTC)
	a := &iec60870.ASDU{Type: iec60870.MMeTf1, Cause: iec60870.CauseSpontaneous, CA: 1,
		Objects: []iec60870.Object{{IOA: 3001, Value: 230.5, Time: at}}}
	b, err := a.Encode(p, time.UTC)
	if err != nil {
		panic(err)
	}
	back, err := iec60870.DecodeASDU(b, p, time.UTC)
	if err != nil {
		panic(err)
	}
	o := back.Objects[0]
	fmt.Println(back.Type, back.Cause, o.IOA, o.Value, o.Time.Format(time.RFC3339))
	// Output: M_ME_TF_1 spontaneous 3001 230.5 2026-10-06T09:30:00Z
}
