# Changelog

## v0.3.0 (2026-10-11)

Added, all backwards compatible:

- Package `station`: the controlled station as a library (until now it
  lived only in iec60870-sim). `Station` holds `Sector`s, one per common
  address, of `Point`s and `Control`s and answers station and group
  interrogation, counter interrogation with freeze and reset, read, clock
  synchronisation (its clock, `Now`, follows), the test commands, reset
  process with end of initialisation, delay acquisition, parameters of
  measured values (the threshold holds back spontaneous reports) and
  their activation (QPA 3 switches cyclic transmission), and file
  transfer through a `FileServer`. `Update`, `UpdateObject`, `Event` and
  `ReturnInfo` report changes; `Run` sends cyclic and background data;
  `EndOfInit` the end of initialisation. Commands run with
  select-before-operate (a select is valid for `SelectTimeout` and only
  for the same type and value), return information, termination,
  deactivation of a select, the test bit and a maximum command delay,
  through `Control.Select`, `Execute` and `Cancel` handlers; a `Refusal`
  error answers with cause 44 to 47. Sessions: `Group` and
  `PerConnection` for `cs104.Server`, `ServeSecondary` for
  `cs101.Secondary`, `Attach` for anything else; each has its own queue,
  so several controlling stations see the same database. IEC 104
  sessions send CP24Time2a types as their CP56Time2a twins; answers that
  do not fit one ASDU are split.
- Package `gateway`: downstream stations, reached through any
  `iec60870.Peer` (`cs101.Client`, `cs104.Client`), as sectors of one
  station: the IEC 101 to IEC 104 gateway. Interrogation is answered from
  the mirror; data goes up with its cause; commands go down with their
  answers and refusal causes coming back; counter interrogation, reset
  process, the test commands, delay acquisition, parameters and
  (optionally) clock synchronisation are passed through; `SetOnline`
  marks a lost station's points invalid and interrogates it again when
  it returns.
- `cs101.SharedLine`: several link addresses of a controlled station on
  one line, each with its own `Secondary` (a link address per
  controlling station, or a gateway standing in for several stations).
- Package `statement`: interoperability statements (IEC 60870-5-101
  clause 8, IEC 60870-5-104 clause 9) as data: types with their causes,
  functions, sizes and link parameters; JSON `Read` and `Write`,
  `Validate` (an IEC 104 statement declares no CP24Time2a type),
  `Allows` for an ASDU, and `ForStation` from a `station.Station`.
- `cs104.Group.OnClose`: runs when a connection left the group.
- Interop tests against lib60870-C v2.4.1 for the new roles: lib60870's
  IEC 104 and IEC 101 controlling stations against `station`, and a
  lib60870 IEC 101 station below the gateway with a lib60870 IEC 104
  controlling station above it (see README.md).

## v0.2.0 (2026-10-11)

Added, all backwards compatible: existing functions and types keep their
signatures and behaviour, except the fixes below.

- `cs104.Group` and `cs104.Server`: redundancy groups of a controlled
  station (IEC 60870-5-104 clause 10). A group holds the connections of
  one controlling station, keeps one of them started (a STARTDT on
  another closes it), queues monitor-direction ASDUs while none is
  started, and sends what the closed connection never had acknowledged
  again, first, on the next one. `Server` places each connection in the
  first group whose `Allow` admits its address, or in a group of its own
  (`PerConnection`), up to `MaxConnections`; `ErrNoGroup`,
  `ErrGroupFull`, `ErrQueueFull`.
- `cs101.Client`: a controlling station's session with one IEC 101
  station, like `cs104.Client` (polling on an unbalanced line, reading
  on a balanced one; `Interrogate`, `CounterInterrogate`, `ClockSync`,
  `ResetProcess`, `Test` with C_TS_NA_1, `Operate`, `Cancel`, `Request`;
  an `iec60870.Peer`, so `Read`, `DelayAcquisition`, `GetFile`, `PutFile`
  run on it).
- `cs104.Client.CounterInterrogate`, `ResetProcess` and `Test` (C_TS_TA_1
  with the counter checked).
- `Params.PackedStep`: 1 reads the objects of an M_PS_NA_1 sequence one
  address apart, as lib60870 2.4.1 and some stations send them; the
  default stays Amendment 1's 16.
- `ASDU.EncodeMax`, `MaxFrameASDU` (254), `cs101.MaxASDU(asize)`,
  `cs101.ErrTooLong`.
- Interop tests against lib60870-C v2.4.1 for every common type in both
  directions, file transfer, redundancy, TLS refusals and the IEC 101
  modes and sizes (see README.md).

Fixed (the first three found by the new interop tests):

- `cs101.Secondary` ignored every frame on a balanced line without a link
  address field (0 octets).
- File transfer over IEC 101 failed with 240-octet segments: the
  procedures size segments for the link (up to 253 octets of ASDU with a
  one-octet address), but `ASDU.Encode` stops at 249, the IEC 104 limit.
  `ASDU.EncodeMax` takes the link's limit (up to `MaxFrameASDU`, 254);
  `cs101.Client` uses it. `Encode` is unchanged.
- `cs101.Link` and `cs101.Secondary` wrote a wrapped length octet for
  user data longer than a frame holds; they now refuse it with
  `ErrTooLong`.
- `cs101.OpenSerial`: closing the port while its reader ran was a data
  race inside goburrow/serial (Close changes the descriptor Read uses);
  the port returned now holds Close until the read in progress returns
  (bounded by the 100 ms read timeout). Found through the same package
  in the dnp3 library; reproduced here with the race detector.

## v0.1.0 (2026-10-11)

First release: ASDU codec and station procedures, IEC 104 and IEC 101
links (both sides), commands with select-before-operate, file transfer,
the IEC TS 60870-5-7 / IEC 62351-5 A-Profile, and interop tests of the
controlling station against lib60870-C v2.4.1.
