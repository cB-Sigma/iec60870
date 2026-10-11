# iec60870

IEC 60870-5-104 and IEC 60870-5-101 telecontrol in pure Go, with IEC 62351-5 secure authentication.

[![Go Reference](https://pkg.go.dev/badge/github.com/cB-Sigma/iec60870.svg)](https://pkg.go.dev/github.com/cB-Sigma/iec60870) [![test](https://github.com/cB-Sigma/iec60870/actions/workflows/test.yml/badge.svg)](https://github.com/cB-Sigma/iec60870/actions/workflows/test.yml) [![Licence: Apache-2.0](https://img.shields.io/badge/licence-Apache--2.0-blue.svg)](LICENSE) [![Go](https://img.shields.io/badge/go-1.26.0-00ADD8.svg)](go.mod)

The module has the ASDU codec and station procedures both companion
standards share, the IEC 104 link (controlling and controlled station,
TCP or TLS), the IEC 101 link (balanced and unbalanced, serial or TCP,
both sides), select-before-operate commands that cope with late
confirmations, a controlled station with its point database and
handlers, a 101 to 104 gateway, and the IEC TS 60870-5-7 / IEC 62351-5
secure authentication (A-Profile). It is built on the standard library,
golang.org/x/crypto, cloudflare/circl, decred's secp256k1 and
goburrow/serial, without cgo. It was written for SigmaM2M, a oneM2M
platform, where it serves the IEC 104 and IEC 101 integrations.

## Features

| Feature | Status |
|---|---|
| ASDU codec: every type of IEC 60870-5-101 Tables 8 to 13, CP56Time2a/CP24Time2a/CP16Time2a, configurable cause, common address and object address sizes, originator address, test and negative bits | yes |
| IEC 104 APCI: I/S/U formats, modulo-32768 numbering with acknowledgement by N(R) of the frames below it (Amendment 1), k, w, t0 to t3, STARTDT/STOPDT/TESTFR, the start/stop procedure, parameter ranges of 9.6 | yes |
| IEC 104 controlled-station side of a connection | yes (`cs104.Accept`, `Group`, `Server`) |
| Controlled station: point database and application functions (`station`) | yes: sectors per common address; station and group interrogation, counter interrogation with freeze and reset, read, clock synchronisation, test, reset process with end of initialisation, delay acquisition, parameters (the threshold holds back spontaneous reports) and their activation, cyclic and background data, file service; spontaneous reporting; commands with select-before-operate (timeout, same value), return information, termination, deactivation, the test bit and a maximum command delay, through handler callbacks; IEC 104 and IEC 101 sessions at once |
| 101 to 104 gateway (`gateway`) | yes: each downstream station (any `iec60870.Peer`) is a sector; interrogation from the mirror, data passed up with its cause, CP24Time2a types sent to IEC 104 as their CP56Time2a twins, commands passed down and their answers and refusal causes back, counter interrogation and the other system commands passed through, a lost station's points marked invalid |
| Several controlling stations | yes: each session (IEC 104 redundancy group or IEC 101 line) has its own queue and sees every change; on one IEC 101 line, a link address per controlling station (`cs101.SharedLine`) |
| IEC 104 redundancy (edition 2): standby connections, switchover with STOPDT/STARTDT | controlling station: `DialStandby`, `StartDT`, `StopDT`, `Unacked`; controlled station: `cs104.Group` (one started connection, a shared queue kept across switchover, unacknowledged ASDUs sent again first) and `cs104.Server` (groups chosen by address, or one group per connection); other policies can drive `Accept` themselves |
| IEC 101 FT1.2, unbalanced polling of several secondaries, balanced operation, busy (DFC), FC14/FC15, FCB repeats, broadcast send/no reply, the 6.2.2 time-out interval (`T0`) | yes |
| IEC 101 controlled station (`cs101.Secondary`) | yes; several link addresses on one line with `cs101.SharedLine` |
| Commands: single, double, regulating step, set-points, bitstring, with or without CP56Time2a; select-before-operate, direct execute, cancel; termination wait; late confirmations dropped | yes |
| Station procedures: interrogation (station, groups), counter interrogation, read, clock synchronisation, test, reset process, delay acquisition, parameter loading and activation, file transfer in both directions | yes |
| TLS (IEC 62351-3) | through `iotsec`; the profile (renegotiation, certificate checks) is the application's |
| IEC 62351-5 A-Profile: Station Association, Session Key Change, Secure Data, both roles, statistics, broadcast session key (IEC 101), roles | yes |
| IEC 62351-5 Association Initiation Request | no (no standard defines its encoding) |
| IEC 62351-9 enrolment and revocation | hooks only (`SetEnrolment`, `Config.Revoked`) |
| A `Client` for IEC 101 like `cs104.Client` | yes (`cs101.Client`: polls an unbalanced station or reads a balanced one; commands, procedures, files) |
| Packed single points in sequences (M_PS_NA_1, SQ=1) | addresses 16 apart by default (Amendment 1); `Params.PackedStep` 1 reads them one apart, as lib60870 and some stations send them |
| Interoperability statements (IEC 60870-5-104 clause 9, -101 clause 8) | as data (`statement`): types with their causes, functions, sizes and link parameters; JSON in and out, validation, `Allows` to check an ASDU against it, `ForStation` to fill one in from a `station.Station`. The standards' tables of permitted type and cause pairs are not reproduced |

Security services come in through
[iotsec](https://github.com/cB-Sigma/iotsec): a TLS client or server
(`iotsec.TLSClient`, `TLSServer`; `iotsec.StdTLS` uses crypto/tls, an
IEC 62351-3 profile can renew keys and use the link's TESTFR as its
keepalive), a dialer, an auditor for the security events
(`sec.SetAuditor`) and an IEC 62351-8 role authority
(`iotsec.CertificateRoleAuthority`, `sec.Config.RBAC`). Each is optional;
without them the module uses the standard library, and the A-Profile
uses the roles configured in `sec.Config.Roles` (or none). Certificate
enrolment and revocation checks are the application's
(`sec.Endpoint.SetEnrolment`, `sec.Config.Revoked`).

## Choosing an IEC 60870-5 library

Compared from each project's source at the versions named, in October
2026. "Tested" means run against this module in the interop tests below.
Check the projects themselves before relying on a row.

| | this module | lib60870-C v2.4.1 | thinkgos/go-iecp5 v1.2.1 | wendy512/iec104 v1.0.4 | pascaldekloe/part5 (2024-08) |
|---|---|---|---|---|---|
| Language | Go, no cgo | C (C# version separate) | Go | Go | Go |
| Licence | Apache-2.0 | GPLv3 or commercial | LGPL-3.0 (some file headers say GPLv3) | Apache-2.0 (built on a fork of go-iecp5, LGPL-3.0) | public domain (CC0-style waiver) |
| IEC 104 controlling and controlled station | both (both tested against lib60870) | both | both | both, as wrappers over go-iecp5 | an IEC 104 session layer (`session.TCP`) and the iecat tool |
| IEC 101 link | both sides, balanced and unbalanced, 0 to 2 octet link addresses (all tested against lib60870) | both sides, balanced and unbalanced | frame helpers only | no | FT1.2 framing (`media`) |
| TLS | through iotsec, crypto/tls or an IEC 62351-3 profile (tested, TLS 1.2 and 1.3, refusals included) | mbedtls 2.28 or 3.6 | crypto/tls | crypto/tls | no |
| Secure authentication (IEC 62351-5 / TS 60870-5-7) | yes, both roles (own test vectors; no independent peer exists, see below) | an add-on module, not in the open source release | no | no | no |
| Commands with select-before-operate, termination wait, late confirmations | yes (`Commander`, `Operate`) | building blocks; the application sequences them | building blocks | a generic command send; the caller sequences select and execute | building blocks |
| Controlled station with a point database | yes (`station`: interrogation, counters, commands with select-before-operate and return information through handlers, procedures, files; tested against lib60870 over IEC 104 and 101) | handler callbacks per request; the database is the application's | handler callbacks | handler callbacks | no |
| Gateway (101 to 104, several stations as common addresses) | yes (`gateway`, tested with lib60870 on both sides) | no (example programs only) | no | no | no |
| File transfer | both directions, both roles (controlling station tested against lib60870's file service over IEC 104 and IEC 101) | a file service on the controlled station (no call of the directory); no controlling-station side | a stub | no | no |
| Redundancy groups | controlling side primitives; controlled side `cs104.Group` and `cs104.Server` (tested against lib60870 both ways) | yes, server redundancy groups | no | no | no |
| Simulated stations for tests | yes ([iec60870-sim](https://github.com/cB-Sigma/iec60870-sim)) | example programs | example programs | test programs | command-line tool |

Pick this module for a Go program that needs IEC 101 as well as 104,
secure authentication, file transfer, redundancy groups, a ready
controlled station or gateway, or a permissive licence. Pick lib60870 for C or an embedded target, and when you can
work with the GPL or buy its commercial licence. go-iecp5 and wendy512/iec104 are smaller IEC 104
only libraries; check the LGPL obligations of go-iecp5 (also under
wendy512/iec104) for a statically linked Go binary.

## Install

```
go get github.com/cB-Sigma/iec60870@latest
```

Requires Go 1.26.0 or later (the minimum its golang.org/x/crypto
version needs).

## Quick start

```go
import (
	"github.com/cB-Sigma/iec60870"
	"github.com/cB-Sigma/iec60870/cs104"
)

link, err := cs104.Dial(ctx, "10.0.0.9:2404", cs104.LinkConfig{})
c := cs104.NewClient(link, cs104.ClientConfig{CA: 1, OnData: func(a *iec60870.ASDU) {
	// monitor data: a.Type, a.Cause, a.Objects[i].IOA, .Value, .Quality, .Time
}})
err = c.Interrogate(ctx, iec60870.QOIStation, 30*time.Second)
_, err = c.Operate(ctx, iec60870.Operation{Type: iec60870.CDcNa1, Object: iec60870.Object{IOA: 2001, Value: 1},
	SelectBeforeOperate: true, Termination: 30 * time.Second})
if iec60870.NotTerminated(err) {
	// accepted (ACTCON) but not reported finished
}
```

Over TLS with crypto/tls, and with the A-Profile:

```go
sl, err := sec.SecureConfig(sec.Config{Controlling: true, Link: sec.TCP, Params: sec.Params104, MaxASDU: cs104.MaxASDU,
	CA: 1, AIM: 1, Key: id.Key, Certificate: id.Certificate, Trust: rtuTrust}, sec.NewEndpoint)
go sl.Run(ctx)
link, err := cs104.Dial(ctx, "rtu.example:19998", cs104.LinkConfig{TLS: iotsec.StdTLS{Config: tlsConfig}, Security: sl})
```

A controlled station on IEC 104, and a gateway putting an IEC 101
station behind it at common address 70:

```go
st := station.New(station.Config{CA: 1})
st.Add(station.Point{Type: iec60870.MDpTb1, Object: iec60870.Object{IOA: 1001, Value: 1}})
st.AddControl(station.Control{IOA: 2001, Type: iec60870.CDcNa1, Monitor: 1001, SelectRequired: true})
go (&cs104.Server{Groups: []*cs104.Group{st.Group(cs104.LinkConfig{})}}).Serve(ctx, ln)
_ = st.Update(1001, 2, 0) // reported spontaneously

g := gateway.New(station.Config{CA: 1})
r := &gateway.Route{CA: 70, DownCA: 7}
g.Add(r)
r.Peer = cs101.NewClient(link, cs101.ClientConfig{Address: 3, CA: 7, OnData: r.Receive})
_ = r.Interrogate(ctx)
go (&cs104.Server{Groups: []*cs104.Group{g.Station().Group(cs104.LinkConfig{})}}).Serve(ctx, ln2)
```

The runnable examples are `iec60870.ExampleASDU_Encode`,
`station.ExampleStation` and `sec.ExampleNewPair` (an association in
memory); iec60870-sim has a controlling station against the simulated
IEC 104 station and an unbalanced IEC 101 line.

## Documentation

API reference: https://pkg.go.dev/github.com/cB-Sigma/iec60870

| Package | What it does |
|---|---|
| `iec60870` (module root) | ASDUs and information objects (`ASDU`, `Object`, `Params`, `DecodeASDU`), qualifiers and time tags; station procedures (`Read`, `DelayAcquisition`, `CallDirectory`, `GetFile`, `QueryLog`, `PutFile` on a `Peer`); `FileServer` for controlled stations; `Commander` (one request at a time, confirmation and termination waits, `Operate` with select-before-operate, `Cancel`) and `LateConfirmations` |
| `cs104` | APCI framing, I-frame numbering and acknowledgement, k and w, t0 to t3, STARTDT/STOPDT/TESTFR; `Dial`, `DialStandby`, `Open`, `Start` (controlling station) and `Accept` (controlled station); `Client` (a controlling station's session: data, commands, procedures); `Group` and `Server` (a controlled station's redundancy groups) |
| `cs101` | FT1.2 frames; `Link` (controlling station: link start-up, polling of class 1 and 2, confirmed and unconfirmed user data, busy and FC14/FC15 handling, balanced or unbalanced); `Secondary` (controlled station: unbalanced secondary or balanced station B with class 1/2 queues); `SharedLine` (several link addresses of a controlled station on one line); `Client` (a controlling station's session with one station, like `cs104.Client`); `Port` over a serial port (`OpenSerial`) or a TCP connection to a converter |
| `station` | the controlled station: `Station` with `Sector`s of `Point`s and `Control`s, the application functions, sessions on cs104 groups (`Group`, `PerConnection`) and cs101 secondaries (`ServeSecondary`), cyclic and background data (`Run`) |
| `gateway` | `Gateway` and `Route`: downstream stations as sectors of one station (the IEC 101 to IEC 104 gateway) |
| `statement` | interoperability statements as data (`Statement`, `Read`, `Write`, `ForStation`) |
| `sec` | IEC TS 60870-5-7 with IEC 62351-5:2023: security ASDUs and segmentation, Station Association (ECDH on secp256r1, secp256k1, Curve25519, Curve448 or brainpoolP256r1; HKDF), Session Key Change (AES-256 key wrap), Secure Data (HMAC-SHA-256, HMAC-SHA3-256, BLAKE2s or AES-256-GCM), both roles' state machines, the IEC 101 broadcast session key, the 29 statistics and their events, TS roles and permissions; `Endpoint` on raw ASDUs, `SecureLink` on the connections of an association |
| `interop` (nested module, tests only) | this module's controlling and controlled stations against lib60870 in Docker |

## Testing

```
go vet ./...
go test -race ./...
```

Tests carry `// Covers: SIG-...` comments: these are requirement IDs of
the SigmaM2M project's compliance report and have no meaning outside it.
Code comments that cite `F-` numbers refer to SigmaM2M's register of
readings where a standard leaves a choice open; PROVENANCE.md explains
them. Error texts of package sec start with "iec60870sec:" (the name of
the package it came from). The tests that drive the simulators are in
[iec60870-sim](https://github.com/cB-Sigma/iec60870-sim), so this module
does not depend on them.

`interop/` is a nested module with its own go.mod. It builds lib60870-C
v2.4.1 with mbedtls 3.6.6 and a peer program of ours (`interop/peer`) in
a Debian container, used only as a test peer (lib60870 is GPLv3; none of
its code is in this repository), and runs this module against it. It is
skipped unless `SIGMA_IEC60870_INTEROP=1` is set and Docker is running:

```
cd interop && SIGMA_IEC60870_INTEROP=1 go test -v ./...
```

### Interop tested against

lib60870-C v2.4.1 (GPLv3, mbedtls 3.6.6), built from source in Docker.
v0.1.0 was tested on 2026-10-11; the rows marked v0.2.0 and v0.3.0 were
added and run on 2026-10-11 against the same build (v0.3.0 together
with every earlier row). All passed. Values, qualities
and time tags are compared field by field: lib60870's side prints what
its own getters read (the time tag field by field and as octets), ours
is what our decoder returns.

| Area | What ran | Version |
|---|---|---|
| IEC 104, our controlling station | `cs104.Client` against our lib60870 peer program: station and group interrogation, spontaneous data, clock synchronisation, C_SC_NA_1, C_DC_NA_1 and C_SE_NC_1 with and without select | v0.1.0 |
| | lib60870's own cs104_server example: sequences (SQ=1), scaled values, a bitstring, periodic data, a command confirmed without termination, a refusal for an unknown object | v0.1.0 |
| Monitor types, lib60870 to us | every type 1 to 21 and 30 to 40 plus M_EI_NA_1, one object each, with quality bits (IV, NT, SB, BL, OV; CY, CA, IV of counters; EI of protection events), CP24Time2a and CP56Time2a tags with IV and RES1, elapsed times, transient steps, counter sequence numbers, status change detection; sequences of 5 and 40 objects; SU in a zone with summer time (Europe/Berlin) | v0.2.0 |
| Monitor types, us to lib60870 | the same set encoded by us (from `cs104.Group` over IEC 104 and from `cs101.Secondary` over IEC 101) and read by lib60870 | v0.2.0 |
| Commands, us to lib60870 | C_SC, C_DC, C_RC, C_SE (normalised, scaled, float), C_BO, each with and without CP56Time2a (45 to 51, 58 to 64), select and execute, qualifier (QU/QL), deactivation of a select, refusal of an unknown object | v0.2.0 |
| Commands, lib60870 to us | the same types sent by lib60870 to `cs104.Server`/`cs104.Group` and to `cs101.Secondary`, decoded value, S/E, qualifier and time tag | v0.2.0 |
| System commands | C_IC (station, group), C_CI (read), C_RD (known and unknown object), C_RP (positive and negative), C_TS_TA_1 (counter and time mirrored), C_CD_NA_1 (activation and the delay loaded with cause 3), P_ME_NA/NB/NC, P_AC, both directions; C_TS_NA_1 over IEC 101 | v0.2.0 |
| Clock synchronisation | ours read by lib60870 field by field: 2099-12-31 23:59:59.999, 2000-01-01, 28 February and a leap day, day of week 7, SU sent as zero from a zone in summer time; a negative confirmation; lib60870's read by us: SU set (ignored), IV set, a wrong day of week, 59 999 ms, year 00 | v0.2.0 |
| File transfer | `GetFile` of a three-section file from lib60870's file service, an unknown file refused, `PutFile` of 70 000 octets (two sections) into it, over IEC 104; the same over IEC 101, balanced and unbalanced | v0.2.0 |
| Redundancy | against lib60870 in single-group and multiple-group (catch-all) modes: `DialStandby` plus `StartDT` closes the started connection, what it sent without acknowledgement arrives again on the standby, what was queued during `StopDT` arrives on the next start; one group per connection: both started connections receive the data | v0.2.0 |
| Our redundancy groups | lib60870 as controlling station against `cs104.Server` with one `cs104.Group` (interrogation, commands, clock, monitor types) | v0.2.0 |
| TLS | TLS 1.2 (ECDHE-ECDSA-AES-256-GCM) and 1.3 with mutual authentication | v0.1.0 |
| | refused: no client certificate (1.2 and 1.3), a client certificate from an untrusted CA, a station certificate we do not trust | v0.2.0 |
| | lib60870 (mbedtls) as TLS 1.2 and 1.3 client against `cs104.Server` on a crypto/tls listener requiring client certificates: interrogation, a time-tagged command, a monitor type; lib60870 with a certificate from an untrusted CA refused | v0.2.0 |
| IEC 101 | `cs101.Link` unbalanced against lib60870's secondary on a pty bridged by socat: start-up, polling, interrogation, clock, select-before-operate, spontaneous data | v0.1.0 |
| | `cs101.Link` and `cs101.Client`, unbalanced and balanced, link address 0, 1 and 2 octets, cause 1 and 2 octets (originator address checked), common address 1 and 2, object address 1, 2 and 3: interrogation, clock, commands, every monitor type | v0.2.0 |
| | lib60870's controlling station, unbalanced and balanced, the same sizes, against `cs101.Secondary` | v0.2.0 |
| Controlled station (`station`) | lib60870 as IEC 104 controlling station against `station.Station` on `cs104.Server`: station and group interrogation (a CP56Time2a point sent untagged), counter interrogation by group, read (known and unknown), select-before-operate with return information (cause 11) and termination, an execute without select refused, cause 47 for an unknown address, a time-tagged set-point with its spontaneous change, a CP24Time2a point read by lib60870 as its CP56Time2a twin, clock synchronisation, C_TS_TA_1, reset process with end of initialisation (COI 2), a threshold parameter, cyclic transmission started and stopped by P_AC_NA_1, an unknown common address (cause 46) | v0.3.0 |
| | lib60870 as IEC 101 controlling station (unbalanced; balanced with two-octet cause and common address and three-octet object address) against `station.Station` on `cs101.Secondary`: interrogation, select-before-operate with return information, counter interrogation, a CP24Time2a point kept as such, C_TS_NA_1, delay acquisition | v0.3.0 |
| Gateway (`gateway`) | a lib60870 IEC 101 station (on a pty) below, polled by our `cs101.Link` and `Client`; a lib60870 IEC 104 controlling station above, at common address 70: interrogation answered from the mirror, spontaneous data, a CP24Time2a value arriving as CP56Time2a, select-before-operate passed down (seen by lib60870 below) with confirmations and termination back, cause 47 of the station passed back, counter interrogation passed through, a read answered from the mirror | v0.3.0 |

Found and fixed by these runs (v0.2.0): `cs101.Secondary` ignored every
frame on a balanced line without a link address field (it compared the
missing address with its own); a 240-octet file segment failed over IEC
101 because `Encode` stops at the IEC 104 limit of 249 octets
(`EncodeMax` now takes the link's limit, used by `cs101.Client`); and IEC
101 frames now refuse user data longer than their length octet allows
instead of writing a wrapped length.

Differences to know, not defects of either side:

- lib60870 numbers the objects of an M_PS_NA_1 sequence one apart and
  refuses other steps; our decoder follows Amendment 1 (16 apart) unless
  `Params.PackedStep` is 1.
- lib60870's file service does not answer the call of the directory, so
  `CallDirectory` is not tested against it.
- lib60870 compares every certificate key's bit length with one minimum
  (1024 by default), so a P-256 certificate is refused unless the
  minimum is lowered (`TLSConfiguration_setMinimumKeyLength`).

Not tested against an independent implementation:

- The IEC 62351-5 / TS 60870-5-7 A-Profile. lib60870's secure
  authentication is a commercial add-on. On 2026-10-11 the web and
  GitHub (repositories naming 60870-5-7 or 62351-5) were searched for an
  open implementation under a usable licence; none was found, only
  commercial source libraries. Wireshark's IEC 104 dissector knows the
  type numbers of the 2013 edition, whose messages differ from TS
  60870-5-7:2025, so it cannot check ours either. The package is tested with our
  own vectors written from the message figures of TS 60870-5-7 and IEC
  62351-5 and RFC vectors for the primitives (`sec/`); those are own
  vectors, not independent.
- Our `FileServer` (the controlled station's file service, also behind
  `station`) and `CallDirectory`: lib60870 has no controlling-station
  file service.
- `cs101.SharedLine` with several link addresses: lib60870's master polls
  one station per line in our peer program; tested in-process only.
- The gateway with an IEC 104 station below, and the gateway's handling
  of a lost station: tested in-process only.
- Real serial hardware (the IEC 101 runs use a pty and socat).

## Related repositories

- [iec60870-sim](https://github.com/cB-Sigma/iec60870-sim): simulated
  IEC 104 and IEC 101 controlled stations, as Go packages and commands.
- [iotsec](https://github.com/cB-Sigma/iotsec): the security seams.
- [iotcrypto](https://github.com/cB-Sigma/iotcrypto): brainpool curves
  for the A-Profile.

## Status

v0.x: the API may change before v1.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

## Security

See [SECURITY.md](SECURITY.md) to report a vulnerability privately.

## Licence

Apache-2.0 (see [LICENSE](LICENSE) and [NOTICE](NOTICE)). Copyright 2026
Abhinav Gautam.
