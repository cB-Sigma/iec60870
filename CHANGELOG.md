# Changelog

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
