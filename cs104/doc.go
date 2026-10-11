// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

// Package cs104 is the IEC 60870-5-104 link: APDU framing (APCI, clause
// 5), I-frame numbering and acknowledgement with the k and w windows and
// the t0 to t3 timers, STARTDT, STOPDT and TESTFR, for both the
// controlling station (Dial, DialStandby, Start, Open) and the controlled
// station (Accept). A link can run under TLS (IEC 62351-3, through an
// iotsec.TLSClient) and under the IEC TS 60870-5-7 A-Profile (a
// sec.SecureLink). The ASDUs themselves are package iec60870's.
package cs104
