# iec60870

IEC 60870-5-104 and IEC 60870-5-101 telecontrol in pure Go, with IEC 62351-5 secure authentication.

[![Go Reference](https://pkg.go.dev/badge/github.com/cB-Sigma/iec60870.svg)](https://pkg.go.dev/github.com/cB-Sigma/iec60870) [![test](https://github.com/cB-Sigma/iec60870/actions/workflows/test.yml/badge.svg)](https://github.com/cB-Sigma/iec60870/actions/workflows/test.yml) [![Licence: Apache-2.0](https://img.shields.io/badge/licence-Apache--2.0-blue.svg)](LICENSE) [![Go](https://img.shields.io/badge/go-1.26.0-00ADD8.svg)](go.mod)

The module has the ASDU codec and station procedures both companion
standards share, the IEC 104 link (controlling and controlled station,
TCP or TLS), the IEC 101 link (balanced and unbalanced, serial or TCP,
both sides), select-before-operate commands that cope with late
confirmations, and the IEC TS 60870-5-7 / IEC 62351-5 secure
authentication (A-Profile). It is built on the standard library,
golang.org/x/crypto, cloudflare/circl, decred's secp256k1 and
goburrow/serial, without cgo. It was written for SigmaM2M, a oneM2M
platform, where it serves the IEC 104 and IEC 101 integrations.

## Features

| Feature | Status |
|---|---|
| ASDU codec: every type of IEC 60870-5-101 Tables 8 to 13, CP56Time2a/CP24Time2a/CP16Time2a, configurable cause, common address and object address sizes, originator address, test and negative bits | yes |
| IEC 104 APCI: I/S/U formats, modulo-32768 numbering with acknowledgement by N(R) of the frames below it (Amendment 1), k, w, t0 to t3, STARTDT/STOPDT/TESTFR, the start/stop procedure, parameter ranges of 9.6 | yes |
| IEC 104 controlled-station side of a connection | yes (`cs104.Accept`); the point database and redundancy groups are the application's (see iec60870-sim) |
| IEC 104 redundancy (edition 2): standby connections, switchover with STOPDT/STARTDT | link primitives yes (`DialStandby`, `StartDT`, `StopDT`, `Unacked`); the group policy is the application's |
| IEC 101 FT1.2, unbalanced polling of several secondaries, balanced operation, busy (DFC), FC14/FC15, FCB repeats, broadcast send/no reply, the 6.2.2 time-out interval (`T0`) | yes |
| IEC 101 controlled station (`cs101.Secondary`) | yes; one controlling station per line |
| Commands: single, double, regulating step, set-points, bitstring, with or without CP56Time2a; select-before-operate, direct execute, cancel; termination wait; late confirmations dropped | yes |
| Station procedures: interrogation (station, groups), counter interrogation, read, clock synchronisation, test, reset process, delay acquisition, parameter loading and activation, file transfer in both directions | yes |
| TLS (IEC 62351-3) | through `iotsec`; the profile (renegotiation, certificate checks) is the application's |
| IEC 62351-5 A-Profile: Station Association, Session Key Change, Secure Data, both roles, statistics, broadcast session key (IEC 101), roles | yes |
| IEC 62351-5 Association Initiation Request | no (no standard defines its encoding) |
| IEC 62351-9 enrolment and revocation | hooks only (`SetEnrolment`, `Config.Revoked`) |
| A Go `Client` for IEC 101 like `cs104.Client` | no; use `cs101.Link` with `iec60870.Commander` |
| Interoperability statements (IEC 60870-5-104 clause 9, -101 clause 8) | no; they belong to an application |

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
| IEC 104 controlling and controlled station | both (tested against lib60870) | both | both | both, as wrappers over go-iecp5 | an IEC 104 session layer (`session.TCP`) and the iecat tool |
| IEC 101 link | both sides, balanced and unbalanced (unbalanced tested against lib60870) | both sides, balanced and unbalanced | frame helpers only | no | FT1.2 framing (`media`) |
| TLS | through iotsec, crypto/tls or an IEC 62351-3 profile (tested, TLS 1.2 and 1.3) | mbedtls 2.28 or 3.6 | crypto/tls | crypto/tls | no |
| Secure authentication (IEC 62351-5 / TS 60870-5-7) | yes, both roles | an add-on module, not in the open source release | no | no | no |
| Commands with select-before-operate, termination wait, late confirmations | yes (`Commander`, `Operate`) | building blocks; the application sequences them | building blocks | a generic command send; the caller sequences select and execute | building blocks |
| File transfer | both directions | a file service on the controlled station | a stub | no | no |
| Redundancy groups | link primitives; policy is the application's | yes, server redundancy groups | no | no | no |
| Simulated stations for tests | yes ([iec60870-sim](https://github.com/cB-Sigma/iec60870-sim)) | example programs | example programs | test programs | command-line tool |

Pick this module for a Go program that needs IEC 101 as well as 104,
secure authentication, file transfer, or a permissive licence. Pick
lib60870 for C, for an embedded target, or when you want server
redundancy groups ready-made, and can work with the GPL or buy its
commercial licence. go-iecp5 and wendy512/iec104 are smaller IEC 104
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

The runnable examples are `iec60870.ExampleASDU_Encode` and
`sec.ExampleNewPair` (an association in memory); iec60870-sim has a
controlling station against the simulated IEC 104 station and an
unbalanced IEC 101 line.

## Documentation

API reference: https://pkg.go.dev/github.com/cB-Sigma/iec60870

| Package | What it does |
|---|---|
| `iec60870` (module root) | ASDUs and information objects (`ASDU`, `Object`, `Params`, `DecodeASDU`), qualifiers and time tags; station procedures (`Read`, `DelayAcquisition`, `CallDirectory`, `GetFile`, `QueryLog`, `PutFile` on a `Peer`); `FileServer` for controlled stations; `Commander` (one request at a time, confirmation and termination waits, `Operate` with select-before-operate, `Cancel`) and `LateConfirmations` |
| `cs104` | APCI framing, I-frame numbering and acknowledgement, k and w, t0 to t3, STARTDT/STOPDT/TESTFR; `Dial`, `DialStandby`, `Open`, `Start` (controlling station) and `Accept` (controlled station); `Client` (a controlling station's session: data, commands, procedures) |
| `cs101` | FT1.2 frames; `Link` (controlling station: link start-up, polling of class 1 and 2, confirmed and unconfirmed user data, busy and FC14/FC15 handling, balanced or unbalanced); `Secondary` (controlled station: unbalanced secondary or balanced station B with class 1/2 queues); `Port` over a serial port (`OpenSerial`) or a TCP connection to a converter |
| `sec` | IEC TS 60870-5-7 with IEC 62351-5:2023: security ASDUs and segmentation, Station Association (ECDH on secp256r1, secp256k1, Curve25519, Curve448 or brainpoolP256r1; HKDF), Session Key Change (AES-256 key wrap), Secure Data (HMAC-SHA-256, HMAC-SHA3-256, BLAKE2s or AES-256-GCM), both roles' state machines, the IEC 101 broadcast session key, the 29 statistics and their events, TS roles and permissions; `Endpoint` on raw ASDUs, `SecureLink` on the connections of an association |
| `interop` (nested module, tests only) | this module's controlling station against lib60870 in Docker |

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

lib60870-C v2.4.1 (GPLv3, mbedtls 3.6.6), built from source in Docker,
on 2026-10-11. The other direction (lib60870 as controlling station
against our controlled stations) is in iec60870-sim.

- `cs104.Client` against a lib60870 controlled station (our peer
  program): station interrogation (M_SP_NA_1, M_ME_NC_1, activation
  confirmation and termination), spontaneous M_ME_NC_1, clock
  synchronisation (the station received the time to the millisecond),
  C_SC_NA_1 select-before-operate, C_DC_NA_1 direct execute and
  C_SE_NC_1 select-before-operate, each confirmed and terminated. Passed.
- The same over TLS 1.2 (ECDHE-ECDSA-AES-256-GCM) and TLS 1.3 with
  mutual certificate authentication, crypto/tls against mbedtls. Passed.
- lib60870's own cs104_server example: station interrogation with
  sequences of elements (SQ=1), scaled values and a bitstring, periodic
  data, clock synchronisation, a single command with select and execute
  confirmed without termination, and a negative confirmation for an
  unknown object. Passed.
- `cs101.Link` (unbalanced, one-octet link address, COT and CA,
  two-octet IOA) against a lib60870 unbalanced secondary on a pty bridged
  to TCP by socat: link start-up, station interrogation polled through
  class 1 and 2, clock synchronisation, C_SC_NA_1 select-before-operate
  with termination, a spontaneous value as class 1 data. Passed.
- Not tested against a reference: the A-Profile (lib60870's secure
  authentication is not in its open source release), IEC 101 balanced
  mode, file transfer, redundancy switchover, real serial hardware.

No interoperability defect was found in this module. One lib60870 note
for users: it compares every certificate key's bit length with one
minimum (1024 by default), so a P-256 certificate is refused unless the
minimum is lowered (`TLSConfiguration_setMinimumKeyLength`).

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
