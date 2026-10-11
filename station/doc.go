// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

// Package station is the controlled station (outstation) of IEC
// 60870-5-104 and IEC 60870-5-101 as a reusable package: a point database
// per common address (Sector) and the application functions that answer a
// controlling station from it.
//
// A Station answers station and group interrogation, counter
// interrogation with freeze and reset, read, clock synchronisation, the
// test commands, reset process, delay acquisition, parameter loading and
// activation, and file transfer (through iec60870.FileServer). It reports
// changes spontaneously (with a threshold for measured values), sends
// cyclic and background data, and runs commands with select-before-operate,
// return information and activation termination, calling the
// application's handlers. It sends to any number of sessions at once:
// cs104 redundancy groups (Group, PerConnection) and cs101 secondaries
// (ServeSecondary), each with its own queue, so several controlling
// stations, over IEC 104 and IEC 101 together, see the same database.
//
// The package does not open sockets or serial ports; cs104.Server and
// cs101.Secondary do, and the station rides on them.
package station
