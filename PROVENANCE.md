# Provenance

## How the code was written

Written for SigmaM2M, a oneM2M platform, in Go from the IEC 60870-5 and
IEC 62351 standards in the table, read in licensed copies, and the RFCs
named below. No code was ported or copied from another implementation.
Type and cause numbers, octet layouts, bit positions, timer defaults and
ranges, state machines and procedures are facts every implementation
must use; the code around them (Go types, goroutines and channels, the
Commander, error handling) is our own design. No text of the standards
is reproduced; comments cite clause, table and figure numbers in our own
words.

The code came with SigmaM2M's baseline (2026-09-27: its IEC 104, IEC 101
and A-Profile integrations) and was extended in later SigmaM2M work:
Release 4 security work (2026-09-27), the console round of 2026-09-28,
and on 2026-10-06 the command fixes from a review of real-device
behaviour (a confirmation that arrives after its command timed out is no
longer taken for the next command on the same object; a time-tagged
execute is stamped when it is sent, not when its select was; without a
configured termination wait an execute waits a default time and a
missing termination is reported as "confirmed, not terminated") and
serial-port work. It became a module of its own on 2026-10-06; the
command procedure (`command.go`, `Commander`), `cs104.Client` and
`cs101.Secondary` were written or lifted out of the integrations then.
On 2026-10-11 the simulators, their commands and the tests that drive
them moved to the separate module iec60870-sim, and the lib60870 interop
tests (interop/) were added. Later the same day (v0.2.0) the interop
tests were extended to every common type in both directions, file
transfer, redundancy, TLS refusals and the IEC 101 sizes and modes;
`cs104.Group` and `cs104.Server` (a controlled station's redundancy
groups), `cs101.Client`, the `cs104.Client` helpers for counter
interrogation, reset and test, and `Params.PackedStep` were written from
the standards named below, three defects those runs found were fixed,
and a data race on closing a serial port (reported from the dnp3
library, which uses the same serial package) was fixed (see
CHANGELOG.md). For v0.3.0 (the same day) the controlled station of the
simulators (point database, interrogation, commands with
select-before-operate and return information, the counter freeze and
reset arithmetic) was lifted into the package `station` and rewritten
as a library with sessions and handler callbacks, written from the same
clauses; `gateway` (the 101 to 104 gateway) and `cs101.SharedLine` were
written then from the standards named below, and the simulators now run
on `station`.

## Notes on open readings (F- numbers)

Where a standard leaves an encoding or a reading open, the choice made
was recorded in SigmaM2M's register of findings, and code comments cite
its numbers. Each is explained here in our words:

| Note | Where | Choice |
|---|---|---|
| F-189 | file service (fileserver.go, procedures.go) | a log query (F_SC_NB_1) is accepted with cause 13 or 5 and answered like a file selection; cause 44 stays for unknown type identifications |
| F-411 | sec/messages.go | the KWA, MAL and DPA values and the MAC rules come from IEC 62351-5:2023, which the TS refers to |
| F-414 | sec/messages.go | every random data length is one octet, as the field table defines it |
| F-417 | sec/keys.go, sec/endpoint.go | broadcast Secure Data has its own sequence number under the broadcast key, following IEC 62351-5 |
| F-419 | sec/stats.go | statistics without a default threshold are reported at every change; counters wrap at 2^31 with the carry set |
| F-420 | sec/rbac.go | our mapping of each control-direction type identification to a permission, since the TS leaves it to the implementer |
| F-423 | sec/crypto.go | the AES-GCM nonce is the sequence number, least significant octet first, padded with zeros; no standard test vectors exist |
| F-425 | sec/cert.go | a certificate fingerprint is its SHA-256 digest |
| F-426 | sec/endpoint.go | update keys can also be provisioned at commissioning, outside the ECDH Station Association |
| F-427 | sec/config.go | the session key usage count defaults to 1000, with the TS's wider range allowed |

## Sources

| Area (files) | Followed | Read for facts only (no code taken) |
|---|---|---|
| ASDU codec, information elements, qualifiers (asdu.go, qualifiers.go) | IEC 60870-5-101:2003 with Amendment 1:2015, clause 7 (7.1 to 7.3: structure, elements, the type figures of Tables 8 to 13); IEC 60870-5-4:1993 (data types, CP56Time2a, CP24Time2a, CP16Time2a); IEC 60870-5-104:2006 with Amendment 1:2016 clauses 6 and 8 (ASDU selection, time-tagged commands) | none |
| Station procedures and file transfer (procedures.go, fileserver.go) | IEC 60870-5-5:1995 clause 6 as IEC 60870-5-101 clause 7.4 selects it (interrogation, clock synchronisation, command transmission, integrated totals, parameter loading, test, file transfer, delay acquisition) | none |
| Commands (command.go, late.go) | IEC 60870-5-101 7.4.7 to 7.4.9 and 7.2.3 (mirrored confirmations and terminations, causes 44 to 47); IEC 60870-5-104 Amendment 1 (the maximum command delay of time-tagged commands) | none |
| IEC 104 link (cs104/apci.go, cs104/link.go, cs104/client.go) | IEC 60870-5-104:2006 clause 5 (APCI, Figures 4 to 18: I, S and U formats, sequence numbers, k and w, t0 to t3, STARTDT, STOPDT, TESTFR) and clause 9.6 (parameter ranges), clause 10 (redundant connections), Amendment 1 5.1 | none |
| IEC 101 link (cs101/ft12.go, cs101/link.go, cs101/secondary.go, cs101/serialport.go) | IEC 60870-5-1 (FT1.2 frames), IEC 60870-5-2 (link transmission procedures) as IEC 60870-5-101 clause 6 profiles them (Figures 3 to 9, the 6.2.2 time-out interval, broadcast address) | github.com/goburrow/serial is a dependency, not a source |
| TLS (cs104, through iotsec) | IEC 62351-3 for what a link must allow a profile to do (keepalive before a timed key update); the profile itself is the application's | none |
| Security extension (sec/) | IEC TS 60870-5-7:2025 (A-Profile message formats, types 81 to 89 and 91, causes 14 to 17, segmentation, Session Initiation Request, IEC 101 broadcast session key, statistics, RBAC permissions of clause 8, parameters of clause 9, T-Profile port); IEC 62351-5:2023 clause 8 (state machines, HKDF inputs, MAC inputs, AEAD parameters); IEC 62351-8 (roles, through iotsec.CertificateRoleAuthority); RFC 3394 (AES key wrap), RFC 5869 (HKDF), RFC 2104 and RFC 4231 (HMAC), RFC 7693 (BLAKE2s), RFC 7748 (X25519, X448), RFC 5639 and RFC 7027 (brainpool) | none |
| Interop peer (interop/peer) | lib60870-C v2.4.1's public API headers and example programs, read to write our peer program; on 2026-10-11 also its file service, IEC 104 controlled-station dispatch, FT1.2 link layer and mbedtls configuration sources, read to learn how the test peer behaves (no code taken) | the peer program is ours; lib60870 is built from its own sources in the test container |
| Redundancy groups (cs104/group.go) | IEC 60870-5-104 clause 10 (redundant connections, Figure 36, 10.6 and 10.7) | none |
| IEC 101 client (cs101/client.go) | IEC 60870-5-101 clause 7.4 and 6.2 (as for the link and the procedures) | none |
| Controlled station (station/) | IEC 60870-5-101 clause 7.4 (station initialisation, interrogation by groups, counter interrogation modes, command transmission with return information, parameter loading and activation, test, reset, delay acquisition, file transfer) and 7.2 (causes, qualifiers, the test bit); IEC 60870-5-104 clauses 7 to 9 (the types and causes allowed over IEC 104, which excludes the CP24Time2a types; the maximum command delay of Amendment 1); IEC 60870-5-5 clause 6 | none; lib60870's controlled-station handler interface was known from the interop peer program and is not followed |
| Gateway (gateway/) and shared line (cs101/shared.go) | the same clauses for the station side; IEC 60870-5-101 6.2.1.1 (unbalanced party lines, broadcast address) for the shared line. A gateway's behaviour (mirror for interrogation, data passed up with its cause, commands passed down) is no standard's; it is our design | none |

## Other IEC 60870-5 implementations

Open implementations include lib60870 (C, MZ Automation; GPLv3 or a
commercial licence), j60870 (Java, OpenMUC; GPLv3), go-iecp5 (Go,
LGPL-3.0) and part5 (Go, public domain). None of them was read for the
library code. On 2026-10-06 I searched the module, and the SigmaM2M
integrations it came from, for porting or attribution comments and for
characteristic identifiers of those projects (for example CS101_ASDU,
CS104_Connection, InformationObject_, T104Frame, AppLayerParameters,
APCIParameters, IMasterConnection, InfoObjAddr, ParamsWide, ParamsNarrow,
CauseOfTransmission, OrigAddr, CommonAddr, IeQualifier) and found none.
The package names cs104 and cs101 are the standard's own term (companion
standard 104, 101), as several projects use it. The owner decided on
2026-10-06 that no line-by-line comparison with those projects is
needed; these notes are the record.

On 2026-10-11 lib60870 was used as an independent test peer (interop/):
its public headers and examples were read to write the peer program,
after the library code existed. For v0.2.0 some of its source files were
read as well (named in the table above), to make the peer exercise its
file service, redundancy groups and link layer and to understand test
failures. The library changes of v0.2.0 come from those failures and
from the standards; `Params.PackedStep` exists because lib60870 numbers
packed single-point sequences differently, which the interop test
showed. go-iecp5 v1.2.1, wendy512/iec104 v1.0.4
and part5 were read for the comparison in README.md only.

## Test vectors and where they come from

| Test | Source |
|---|---|
| codec101_test.go, codec_test.go, cp24_test.go | the layouts of the IEC 60870-5-101 clause 7.3 figures and the IEC 60870-5-4 elements named in each test |
| cs104/codec_apci_test.go, cs104/apci_fig_test.go, cs104/server_link_test.go | the frame formats and the sequences of IEC 60870-5-104 Figures 9 to 18 and 36, and the clause 9.6 ranges |
| cs101/ft12_test.go | the FT1.2 frames of IEC 60870-5-1 and IEC 60870-5-101 clause 6 |
| sec/codec_test.go, sec/misc_test.go, sec/engine_test.go | the message figures and tables of IEC TS 60870-5-7 and IEC 62351-5 clause 8 named in each test; RFC 3394 section 4 |
| sec/crypto_test.go | RFC 3394, RFC 4231, RFC 5869 and RFC 7693 test vectors |
| sec/cert_test.go, sec/brainpool_test.go | RFC 7748 (X25519, X448) and RFC 7027 (brainpoolP256r1) |
| fuzz tests (cs104/fuzz_test.go, cs101/fuzz_test.go) | random input from hand-written seed frames |
| interop/ | lib60870-C v2.4.1 as controlled and as controlling station (IEC 104 with and without TLS, IEC 101 balanced and unbalanced with every field size), against our `station` and on both sides of our `gateway`; the expected values in the tests are our own choices, checked against what lib60870's getters and our decoder read |
| station/, gateway/ | our controlling stations (cs104.Client, cs101.Client, cs101.Link) against them in memory, with the expected answers taken from the clauses named above |
| sec/ (all) | own vectors from the TS 60870-5-7 and IEC 62351-5 message figures, plus RFC vectors for the primitives; no independent A-Profile implementation was available to test against (see README.md) |
| every other test and the examples | the links and endpoints of this module against each other, written from the same standards; not a real device |

All keys, certificates and addresses in the tests are made-up demo
values; the identities are generated when the tests run.
