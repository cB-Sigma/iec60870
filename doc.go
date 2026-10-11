// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

// Package iec60870 is the application layer that IEC 60870-5-101 and
// IEC 60870-5-104 share: the ASDU and its information objects (IEC
// 60870-5-101 clause 7, every type of Tables 8 to 13 with the layout of
// its figure), the qualifiers and time tags, the station procedures of
// clause 7.4 (interrogation, read, clock synchronisation, delay
// acquisition, parameters, file transfer in both directions), a file
// server for controlled stations, and the command procedures of a
// controlling station: one request at a time per station, confirmation
// and termination waits, select-before-operate (Commander) and the
// handling of confirmations that arrive after their command timed out
// (LateConfirmations).
//
// The link layers are in the sub-packages: cs104 (APCI over TCP, with TLS
// through github.com/cB-Sigma/iotsec) and cs101 (FT1.2 frames, balanced
// and unbalanced links, serial or TCP). The IEC TS 60870-5-7 / IEC
// 62351-5 security extension is package sec. In-process simulators of
// controlled stations are the separate module
// github.com/cB-Sigma/iec60870-sim.
package iec60870
