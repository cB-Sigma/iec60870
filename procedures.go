package iec60870

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"
)

// Controlling-station procedures of more than one request and answer
// (IEC 60870-5-5 clause 6 as IEC 60870-5-101 clause 7.4 selects them),
// shared by IEC 60870-5-104 and -101. A procedure sends through a
// Peer and reads the answers it is waiting for from the peer's Taps.

// Taps hands received ASDUs to the procedures waiting for them.
type Taps struct {
	mu   sync.Mutex
	list []*tapEntry
}

type tapEntry struct {
	match   func(*ASDU) bool
	ch      chan *ASDU
	stopped chan struct{}
}

// Add registers a tap: ASDUs for which match returns true are delivered
// on the channel until stop is called. A full channel holds up the
// offering side (the link's flow control does the rest), so a long file
// transfer loses no segment.
func (t *Taps) Add(match func(*ASDU) bool) (<-chan *ASDU, func()) {
	e := &tapEntry{match: match, ch: make(chan *ASDU, 64), stopped: make(chan struct{})}
	t.mu.Lock()
	t.list = append(t.list, e)
	t.mu.Unlock()
	var once sync.Once
	return e.ch, func() {
		once.Do(func() {
			t.mu.Lock()
			for i, x := range t.list {
				if x == e {
					t.list = append(t.list[:i], t.list[i+1:]...)
					break
				}
			}
			t.mu.Unlock()
			close(e.stopped)
		})
	}
}

// Offer delivers a to every matching tap and reports whether one took it.
func (t *Taps) Offer(a *ASDU) bool {
	t.mu.Lock()
	var hit []*tapEntry
	for _, e := range t.list {
		if e.match(a) {
			hit = append(hit, e)
		}
	}
	t.mu.Unlock()
	for _, e := range hit {
		select {
		case e.ch <- a:
		case <-e.stopped:
		}
	}
	return len(hit) > 0
}

// Peer is one controlled station as the procedures see it.
type Peer interface {
	// Send transmits a to the station, filling in its common address and
	// our originator address.
	Send(ctx context.Context, a *ASDU) error
	// Taps are where received ASDUs are offered.
	Taps() *Taps
	// MaxASDU is the largest ASDU the link carries; Params its sizes.
	MaxASDU() int
	Params() Params
}

// ErrNoAnswer is wrapped when an awaited answer does not come in time.
var ErrNoAnswer = errors.New("no answer from the station")

func await(ctx context.Context, ch <-chan *ASDU, timeout time.Duration, what string) (*ASDU, error) {
	t := time.NewTimer(timeout)
	defer t.Stop()
	select {
	case a := <-ch:
		return a, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-t.C:
		return nil, fmt.Errorf("%w: no %s within %s", ErrNoAnswer, what, timeout)
	}
}

func refusal(a *ASDU) error {
	switch a.Cause {
	case CauseUnknownType, CauseUnknownCause, CauseUnknownCA, CauseUnknownObject:
		return fmt.Errorf("the station refused %s: %s", a.Type, a.Cause)
	}
	if a.Negative {
		return fmt.Errorf("the station refused %s (negative %s)", a.Type, a.Cause)
	}
	return nil
}

// Read runs the read procedure (IEC 60870-5-101 7.4.14): C_RD_NA_1 with
// cause 5 addresses one object; the station answers with it in its
// monitor type and cause 5, or mirrors the command with cause 44 to 47.
func Read(ctx context.Context, p Peer, ioa uint32, timeout time.Duration) (*ASDU, error) {
	ch, stop := p.Taps().Add(func(a *ASDU) bool {
		if len(a.Objects) == 0 || a.Objects[0].IOA != ioa {
			return false
		}
		return a.Type == CRdNa1 || a.Type.Monitor() && a.Cause == CauseRequest
	})
	defer stop()
	if err := p.Send(ctx, &ASDU{Type: CRdNa1, Cause: CauseRequest, Objects: []Object{{IOA: ioa}}}); err != nil {
		return nil, err
	}
	for {
		a, err := await(ctx, ch, timeout, fmt.Sprintf("answer to the read of object %d", ioa))
		if err != nil {
			return nil, err
		}
		if a.Type == CRdNa1 {
			if err := refusal(a); err != nil {
				return nil, err
			}
			continue // our own command echoed on a shared medium
		}
		return a, nil
	}
}

// DelayAcquisition runs the acquisition of transmission delay (IEC
// 60870-5-5 6.13, selected by IEC 60870-5-101 7.4.12): C_CD_NA_1 ACT
// carries our clock (SDT) as CP16Time2a; the station sets an auxiliary
// clock to it on receipt and confirms with that clock (SDT+tR) at the
// first bit of its answer, received at RDT. The delay tD is
// (RDT−(SDT+tR))/2; it is then loaded with C_CD_NA_1 cause 3
// (spontaneous) for the station's correction of later clock
// synchronisations. CP16Time2a counts milliseconds within the minute, so
// the arithmetic is modulo one minute.
func DelayAcquisition(ctx context.Context, p Peer, timeout time.Duration) (time.Duration, error) {
	ch, stop := p.Taps().Add(func(a *ASDU) bool {
		return a.Type == CCdNa1 && a.Cause != CauseActivation && a.Cause != CauseSpontaneous
	})
	defer stop()
	sdt := time.Now()
	sdtMs := int64(sdt.Second())*1000 + int64(sdt.Nanosecond()/1e6)
	if err := p.Send(ctx, &ASDU{Type: CCdNa1, Cause: CauseActivation, Objects: []Object{{Elapsed: time.Duration(sdtMs) * time.Millisecond}}}); err != nil {
		return 0, err
	}
	a, err := await(ctx, ch, timeout, "confirmation of the delay acquisition")
	if err != nil {
		return 0, err
	}
	rdt := time.Now()
	if err := refusal(a); err != nil {
		return 0, err
	}
	if a.Cause != CauseActCon || len(a.Objects) != 1 {
		return 0, fmt.Errorf("the delay acquisition was answered with %s", a)
	}
	ackMs := a.Objects[0].Elapsed.Milliseconds()
	tR := ((ackMs-sdtMs)%60000 + 60000) % 60000 // the station's reaction time
	total := rdt.Sub(sdt).Milliseconds()
	td := time.Duration(max(0, total-tR)/2) * time.Millisecond
	if td >= time.Minute {
		return 0, fmt.Errorf("the measured delay %s does not fit CP16Time2a", td)
	}
	if err := p.Send(ctx, &ASDU{Type: CCdNa1, Cause: CauseSpontaneous, Objects: []Object{{Elapsed: td}}}); err != nil {
		return 0, err
	}
	return td, nil
}

// DirEntry is one file of a directory (F_DR_TA_1, IEC 60870-5-101
// 7.3.6.7 and 7.4.11.1).
type DirEntry struct {
	IOA    uint32    `json:"ioa"`
	Name   uint16    `json:"name"`   // name of file (NOF)
	Length uint32    `json:"length"` // LOF, 0 when not known
	Status uint8     `json:"status"` // SOF
	Time   time.Time `json:"time"`   // creation, or last change of a subdirectory
}

// CallDirectory asks for the directory (F_SC_NA_1 with cause 5, object
// address 0) and collects the F_DR_TA_1 answers (cause 5) until the entry
// marked as the last file of the directory (LFD).
func CallDirectory(ctx context.Context, p Peer, timeout time.Duration) ([]DirEntry, error) {
	ch, stop := p.Taps().Add(func(a *ASDU) bool {
		return a.Type == FDrTa1 && a.Cause == CauseRequest || a.Type == FScNa1 && a.Cause != CauseRequest
	})
	defer stop()
	if err := p.Send(ctx, &ASDU{Type: FScNa1, Cause: CauseRequest, Objects: []Object{{Qualifier: SCQDefault}}}); err != nil {
		return nil, err
	}
	var out []DirEntry
	for {
		a, err := await(ctx, ch, timeout, "directory")
		if err != nil {
			return out, err
		}
		if a.Type == FScNa1 {
			if err := refusal(a); err != nil {
				return nil, err
			}
			continue
		}
		if len(a.Objects) == 0 {
			return out, nil // an empty directory (Amendment 1 7.1: no objects)
		}
		for _, o := range a.Objects {
			out = append(out, DirEntry{IOA: o.IOA, Name: o.File, Length: o.Length, Status: o.Status, Time: o.Time})
			if o.Status&SOFLastFile != 0 {
				return out, nil
			}
		}
	}
}

// MaxFile is the largest file the transfer procedures accept (LOF is
// three octets).
const MaxFile = 1<<24 - 1

// fileTap receives the file transfer ASDUs of object ioa.
func fileTap(p Peer, ioa uint32) (<-chan *ASDU, func()) {
	return p.Taps().Add(func(a *ASDU) bool {
		return a.Type.File() && a.Type != FDrTa1 && len(a.Objects) > 0 && a.Objects[0].IOA == ioa
	})
}

// awaitFile waits for one of the wanted file types (a refusal with cause
// 44 to 47 is an error; our own requests echoed back are skipped).
func awaitFile(ctx context.Context, ch <-chan *ASDU, timeout time.Duration, what string, want ...TypeID) (*ASDU, error) {
	for {
		a, err := await(ctx, ch, timeout, what)
		if err != nil {
			return nil, err
		}
		if a.Cause >= CauseUnknownType && a.Cause <= CauseUnknownObject {
			return nil, refusal(a)
		}
		for _, t := range want {
			if a.Type == t {
				return a, nil
			}
		}
		if a.Type == FLsNa1 && (a.Objects[0].Qualifier == LSQFileDeact || a.Objects[0].Qualifier == LSQSectionDeact) {
			return nil, errors.New("the station ended the file transfer (deactivation)")
		}
	}
}

func segmentMax(p Peer) int {
	pr := p.Params()
	return max(1, min(240, p.MaxASDU()-pr.Header()-pr.IOASize-4))
}

// GetFile transfers a file in monitor direction (IEC 60870-5-5 6.12.1,
// Figure 21; IEC 60870-5-101 7.4.11, Figure 104): select file, file
// ready, call file, then for each section: section ready, call section,
// segments, last segment with the section's checksum, acknowledge
// section; finally last section with the file's checksum and acknowledge
// file. A section whose checksum fails is acknowledged negatively and the
// station offers it again (at most twice). A failure deactivates the file
// (7.4.11.2.7).
func GetFile(ctx context.Context, p Peer, ioa uint32, name uint16, timeout time.Duration) ([]byte, error) {
	ch, stop := fileTap(p, ioa)
	defer stop()
	send := func(t TypeID, o Object) error {
		o.IOA, o.File = ioa, name
		return p.Send(ctx, &ASDU{Type: t, Cause: CauseFile, Objects: []Object{o}})
	}
	data, err := getFile(ctx, ch, send, func() error { return send(FScNa1, Object{Qualifier: SCQSelectFile}) }, timeout)
	if err != nil {
		_ = send(FScNa1, Object{Qualifier: SCQDeactivateFile})
	}
	return data, err
}

// QueryLog asks for the records of a log file between start and stop
// (F_SC_NB_1, IEC 60870-5-104 clause 8.9; a zero bound is open) and
// transfers the file the station prepares, as GetFile does after the
// selection (F-189: sent with cause 13, answered by file ready).
func QueryLog(ctx context.Context, p Peer, ioa uint32, name uint16, start, stop time.Time, timeout time.Duration) ([]byte, error) {
	ch, stop2 := fileTap(p, ioa)
	defer stop2()
	send := func(t TypeID, o Object) error {
		o.IOA, o.File = ioa, name
		return p.Send(ctx, &ASDU{Type: t, Cause: CauseFile, Objects: []Object{o}})
	}
	data, err := getFile(ctx, ch, send, func() error { return send(FScNb1, Object{Time: start, Stop: stop}) }, timeout)
	if err != nil {
		_ = send(FScNa1, Object{Qualifier: SCQDeactivateFile})
	}
	return data, err
}

func getFile(ctx context.Context, ch <-chan *ASDU, send func(TypeID, Object) error, sel func() error, timeout time.Duration) ([]byte, error) {
	if err := sel(); err != nil {
		return nil, err
	}
	a, err := awaitFile(ctx, ch, timeout, "file ready", FFrNa1)
	if err != nil {
		return nil, err
	}
	fr := a.Objects[0]
	if fr.Qualifier&FRQNegative != 0 || a.Negative {
		return nil, errors.New("the station refused the selection of the file")
	}
	if err := send(FScNa1, Object{Qualifier: SCQRequestFile}); err != nil {
		return nil, err
	}
	var file []byte
	retries := 0
	for {
		a, err := awaitFile(ctx, ch, timeout, "section ready or last section", FSrNa1, FLsNa1)
		if err != nil {
			return nil, err
		}
		o := a.Objects[0]
		if a.Type == FLsNa1 {
			if o.Qualifier != LSQFile {
				return nil, fmt.Errorf("the station ended the file with LSQ %d", o.Qualifier)
			}
			if Checksum(file) != o.Checksum || fr.Length != 0 && uint32(len(file)) != fr.Length {
				_ = send(FAfNa1, Object{Section: o.Section, Qualifier: AFQFileNegative | FileErrChecksum<<4})
				return nil, fmt.Errorf("the file's checksum or length does not match (%d octets, %d announced)", len(file), fr.Length)
			}
			return file, send(FAfNa1, Object{Section: o.Section, Qualifier: AFQFileOK})
		}
		if o.Qualifier&SRQNotReady != 0 {
			return nil, fmt.Errorf("section %d is not ready", o.Section)
		}
		nos := o.Section
		if err := send(FScNa1, Object{Section: nos, Qualifier: SCQRequestSection}); err != nil {
			return nil, err
		}
		var sec []byte
		for {
			a, err := awaitFile(ctx, ch, timeout, "segment", FSgNa1, FLsNa1)
			if err != nil {
				return nil, err
			}
			o := a.Objects[0]
			if a.Type == FSgNa1 {
				if o.Section != nos {
					return nil, fmt.Errorf("a segment of section %d arrived during section %d", o.Section, nos)
				}
				if len(file)+len(sec)+len(o.Segment) > MaxFile {
					return nil, errors.New("the file exceeds 16 MiB")
				}
				sec = append(sec, o.Segment...)
				continue
			}
			if o.Qualifier != LSQSection {
				return nil, fmt.Errorf("the station ended section %d with LSQ %d", nos, o.Qualifier)
			}
			if Checksum(sec) != o.Checksum {
				retries++
				if retries > 2 {
					return nil, fmt.Errorf("section %d failed its checksum three times", nos)
				}
				if err := send(FAfNa1, Object{Section: nos, Qualifier: AFQSectionNegative | FileErrChecksum<<4}); err != nil {
					return nil, err
				}
				break
			}
			file = append(file, sec...)
			if err := send(FAfNa1, Object{Section: nos, Qualifier: AFQSectionOK}); err != nil {
				return nil, err
			}
			break
		}
	}
}

// SectionSize is the largest section PutFile sends.
const SectionSize = 60000

// PutFile transfers a file in control direction (IEC 60870-5-5 6.12.2,
// Figure 22): file ready, the station calls the file; for each section:
// section ready, the station calls it, segments, last segment with the
// section's checksum, the station acknowledges; then last section with
// the file's checksum and the station's acknowledgement of the file.
func PutFile(ctx context.Context, p Peer, ioa uint32, name uint16, data []byte, timeout time.Duration) error {
	if len(data) == 0 || len(data) > MaxFile {
		return fmt.Errorf("a file of %d octets cannot be transferred (1 octet to 16 MiB)", len(data))
	}
	ch, stop := fileTap(p, ioa)
	defer stop()
	send := func(t TypeID, o Object) error {
		o.IOA, o.File = ioa, name
		return p.Send(ctx, &ASDU{Type: t, Cause: CauseFile, Objects: []Object{o}})
	}
	err := putFile(ctx, ch, send, data, segmentMax(p), timeout)
	if err != nil {
		_ = send(FLsNa1, Object{Qualifier: LSQFileDeact, Checksum: 0})
	}
	return err
}

func putFile(ctx context.Context, ch <-chan *ASDU, send func(TypeID, Object) error, data []byte, seg int, timeout time.Duration) error {
	if err := send(FFrNa1, Object{Length: uint32(len(data))}); err != nil {
		return err
	}
	a, err := awaitFile(ctx, ch, timeout, "call of the file", FScNa1, FAfNa1)
	if err != nil {
		return err
	}
	if a.Type != FScNa1 || a.Objects[0].Qualifier&0x0f != SCQRequestFile {
		return fmt.Errorf("the station did not call the file (%s, qualifier %d: %s)", a.Type, a.Objects[0].Qualifier, FileError(a.Objects[0].Qualifier))
	}
	nos := uint8(0)
	for off := 0; off < len(data); off += SectionSize {
		nos++
		sec := data[off:min(len(data), off+SectionSize)]
		for try := 0; ; try++ {
			if err := send(FSrNa1, Object{Section: nos, Length: uint32(len(sec))}); err != nil {
				return err
			}
			a, err := awaitFile(ctx, ch, timeout, "call of the section", FScNa1, FAfNa1)
			if err != nil {
				return err
			}
			if a.Type != FScNa1 || a.Objects[0].Qualifier&0x0f != SCQRequestSection || a.Objects[0].Section != nos {
				return fmt.Errorf("the station did not call section %d (%s, qualifier %d)", nos, a.Type, a.Objects[0].Qualifier)
			}
			for i := 0; i < len(sec); i += seg {
				if err := send(FSgNa1, Object{Section: nos, Segment: sec[i:min(len(sec), i+seg)]}); err != nil {
					return err
				}
			}
			if err := send(FLsNa1, Object{Section: nos, Qualifier: LSQSection, Checksum: Checksum(sec)}); err != nil {
				return err
			}
			a, err = awaitFile(ctx, ch, timeout, "acknowledgement of the section", FAfNa1)
			if err != nil {
				return err
			}
			q := a.Objects[0].Qualifier
			if q&0x0f == AFQSectionOK {
				break
			}
			if q&0x0f != AFQSectionNegative || try >= 2 {
				return fmt.Errorf("section %d was not accepted: %s", nos, FileError(q))
			}
		}
	}
	if err := send(FLsNa1, Object{Section: nos, Qualifier: LSQFile, Checksum: Checksum(data)}); err != nil {
		return err
	}
	a, err = awaitFile(ctx, ch, timeout, "acknowledgement of the file", FAfNa1)
	if err != nil {
		return err
	}
	if q := a.Objects[0].Qualifier; q&0x0f != AFQFileOK {
		return fmt.Errorf("the file was not accepted: %s", FileError(q))
	}
	return nil
}
