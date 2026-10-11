// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

// Package sec is the security extension of IEC 60870-5-101 and
// IEC 60870-5-104 that IEC TS 60870-5-7:2025 (edition 2.0) describes, with
// the A-Profile of IEC 62351-5:2023: the security ASDUs and their
// segmentation, the Station Association from certificates (ECDH, then
// HKDF to the update keys), the Session Key Change, Secure Data, the
// state machines of both roles, the IEC 101 broadcast session key, the
// security statistics and events, and the roles of the TS (configured,
// or from an IEC 62351-8 access token through an
// iotsec.CertificateRoleAuthority).
//
// An Endpoint works on raw ASDU octets; SecureLink attaches one to the
// connections of an association (cs104.LinkConfig.Security,
// cs101.SecondaryConfig.Security). Certificate enrolment and revocation
// checks are the application's (Endpoint.SetEnrolment, Config.Revoked).
package sec
