// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package cs104_test

import (
	"testing"
	"time"

	"github.com/cB-Sigma/iec60870"
)

// gi is an encoded station interrogation (C_IC_NA_1, QOI 20) for CA 1.
func gi(t *testing.T) []byte {
	b, err := (&iec60870.ASDU{Type: iec60870.CIcNa1, Cause: iec60870.CauseActivation, CA: 1, Objects: []iec60870.Object{{Value: 20}}}).Encode(iec60870.Params{}.WithDefaults(), time.UTC)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
