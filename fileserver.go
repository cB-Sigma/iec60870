package iec60870

import (
	"context"
	"errors"
	"sync"
	"time"
)

// FileStore holds a controlled station's files for FileServer.
type FileStore interface {
	// Directory lists the files offered in monitor direction.
	Directory(ctx context.Context) ([]DirEntry, error)
	// Read returns a file of the directory (ErrNoFile when unknown).
	Read(ctx context.Context, ioa uint32, name uint16) ([]byte, error)
	// Write keeps a file received in control direction (ErrNoFile when
	// the address or name is not accepted).
	Write(ctx context.Context, ioa uint32, name uint16, data []byte) error
}

// LogStore is a FileStore that also answers the query log (F_SC_NB_1,
// IEC 60870-5-104 clause 8.9): the records of a log file whose time
// stamps lie in [start, stop] (a zero bound is open), start and stop
// included.
type LogStore interface {
	ReadLog(ctx context.Context, ioa uint32, name uint16, start, stop time.Time) ([]byte, error)
}

// ErrNoFile is returned by a FileStore for an unknown file.
var ErrNoFile = errors.New("no such file")

// FileServer is the controlled station's side of file transfer (IEC
// 60870-5-5 6.12, IEC 60870-5-101 7.4.11): it answers the call of the
// directory, offers files section by section (monitor direction) and
// receives files (control direction). Controlled stations (IEC 104 and
// IEC 101) and the simulators use it.
type FileServer struct {
	Store       FileStore
	SectionSize int // default 60000 octets
	SegmentSize int // default 200 octets
	// Directory entries per F_DR_TA_1 ASDU (default 10).
	PerASDU int
	// CorruptChecksum, a test hook, makes the checksum of a section wrong
	// when it returns true.
	CorruptChecksum func(section uint8) bool
	// OnFileDone is called when the controlling station acknowledges a
	// whole file positively (IEC 60870-5-5 6.12.1.1: the directory may
	// then be sent).
	OnFileDone func()

	mu sync.Mutex
	tx *offer   // the file offered in monitor direction
	rx *receipt // the file being received in control direction
}

type offer struct {
	ioa      uint32
	name     uint16
	data     []byte
	sections [][]byte
	cur      int // index of the section offered
}

type receipt struct {
	ioa    uint32
	name   uint16
	length uint32
	data   []byte
	sec    []byte
	nos    uint8
}

// Handle serves one file transfer ASDU from the controlling station;
// reply sends an answer (with the request's common address). It reports
// whether a was a file transfer ASDU.
func (f *FileServer) Handle(ctx context.Context, a *ASDU, reply func(*ASDU)) bool {
	if !a.Type.File() {
		return false
	}
	answer := func(t TypeID, c Cause, o Object) {
		reply(&ASDU{Type: t, Cause: c, CA: a.CA, Orig: a.Orig, Test: a.Test, Objects: []Object{o}})
	}
	mirror := func(c Cause) {
		m := *a
		m.Cause, m.Negative = c, true
		reply(&m)
	}
	if f.Store == nil {
		mirror(CauseUnknownType)
		return true
	}
	if len(a.Objects) != 1 {
		mirror(CauseUnknownCause)
		return true
	}
	o := a.Objects[0]
	id := Object{IOA: o.IOA, File: o.File}
	with := func(x Object) Object { x.IOA, x.File = id.IOA, id.File; return x }
	f.mu.Lock()
	defer f.mu.Unlock()
	switch a.Type {
	case FScNb1:
		// F-189: clause 8.9 names cause 13 only; the 9.5 table also opens
		// cause 5, which is accepted. The query is answered like a select
		// file: file ready (negative when the log is unknown), after which
		// the transfer runs as for any file. Cause 44 is kept for unknown
		// type identifications (Amendment 1 9.5 NOTE).
		if a.Cause != CauseFile && a.Cause != CauseRequest {
			mirror(CauseUnknownCause)
			return true
		}
		ls, ok := f.Store.(LogStore)
		var data []byte
		err := ErrNoFile
		if ok {
			data, err = ls.ReadLog(ctx, o.IOA, o.File, o.Time, o.Stop)
		}
		if err != nil {
			f.tx = nil
			answer(FFrNa1, CauseFile, with(Object{Qualifier: FRQNegative}))
			return true
		}
		f.tx = &offer{ioa: o.IOA, name: o.File, data: data, sections: split(data, f.sectionSize())}
		answer(FFrNa1, CauseFile, with(Object{Length: uint32(len(data))}))
	case FScNa1:
		if a.Cause == CauseRequest {
			f.directory(ctx, a, reply)
			return true
		}
		if a.Cause != CauseFile {
			mirror(CauseUnknownCause)
			return true
		}
		switch o.Qualifier & 0x0f {
		case SCQSelectFile:
			data, err := f.Store.Read(ctx, o.IOA, o.File)
			if err != nil {
				f.tx = nil
				answer(FFrNa1, CauseFile, with(Object{Qualifier: FRQNegative}))
				return true
			}
			f.tx = &offer{ioa: o.IOA, name: o.File, data: data, sections: split(data, f.sectionSize())}
			answer(FFrNa1, CauseFile, with(Object{Length: uint32(len(data))}))
		case SCQRequestFile:
			if !f.offering(o) {
				answer(FLsNa1, CauseFile, with(Object{Qualifier: LSQFileDeact}))
				return true
			}
			f.tx.cur = 0
			f.readySection(answer, with)
		case SCQRequestSection:
			if !f.offering(o) || int(o.Section) != f.tx.cur+1 {
				answer(FLsNa1, CauseFile, with(Object{Section: o.Section, Qualifier: LSQSectionDeact}))
				return true
			}
			sec := f.tx.sections[f.tx.cur]
			seg := f.segmentSize()
			for i := 0; i < len(sec); i += seg {
				answer(FSgNa1, CauseFile, with(Object{Section: o.Section, Segment: sec[i:min(len(sec), i+seg)]}))
			}
			chs := Checksum(sec)
			if f.CorruptChecksum != nil && f.CorruptChecksum(o.Section) {
				chs++
			}
			answer(FLsNa1, CauseFile, with(Object{Section: o.Section, Qualifier: LSQSection, Checksum: chs}))
		case SCQDeactivateFile, SCQDeactivateSection:
			f.tx = nil
		default:
			answer(FFrNa1, CauseFile, with(Object{Qualifier: FRQNegative}))
		}
	case FAfNa1:
		if !f.offering(o) {
			return true
		}
		switch o.Qualifier & 0x0f {
		case AFQSectionOK:
			f.tx.cur++
			if f.tx.cur < len(f.tx.sections) {
				f.readySection(answer, with)
				return true
			}
			answer(FLsNa1, CauseFile, with(Object{Section: uint8(len(f.tx.sections)), Qualifier: LSQFile, Checksum: Checksum(f.tx.data)}))
		case AFQSectionNegative:
			f.readySection(answer, with) // the same section again
		default: // the file acknowledged, positively or not
			f.tx = nil
			if o.Qualifier&0x0f == AFQFileOK && f.OnFileDone != nil {
				go f.OnFileDone()
			}
		}
	case FFrNa1:
		// Control direction: the controlling station has a file ready.
		if o.Length == 0 || o.Length > MaxFile {
			answer(FAfNa1, CauseFile, with(Object{Qualifier: AFQFileNegative | FileErrMemory<<4}))
			return true
		}
		f.rx = &receipt{ioa: o.IOA, name: o.File, length: o.Length}
		answer(FScNa1, CauseFile, with(Object{Qualifier: SCQRequestFile}))
	case FSrNa1:
		if !f.receiving(o) {
			answer(FAfNa1, CauseFile, with(Object{Section: o.Section, Qualifier: AFQFileNegative | FileErrService<<4}))
			return true
		}
		f.rx.nos, f.rx.sec = o.Section, nil
		answer(FScNa1, CauseFile, with(Object{Section: o.Section, Qualifier: SCQRequestSection}))
	case FSgNa1:
		if f.receiving(o) && o.Section == f.rx.nos && len(f.rx.data)+len(f.rx.sec)+len(o.Segment) <= int(f.rx.length) {
			f.rx.sec = append(f.rx.sec, o.Segment...)
		}
	case FLsNa1:
		if !f.receiving(o) {
			return true
		}
		switch o.Qualifier {
		case LSQSection:
			if o.Section != f.rx.nos || Checksum(f.rx.sec) != o.Checksum {
				f.rx.sec = nil
				answer(FAfNa1, CauseFile, with(Object{Section: o.Section, Qualifier: AFQSectionNegative | FileErrChecksum<<4}))
				return true
			}
			f.rx.data = append(f.rx.data, f.rx.sec...)
			f.rx.sec = nil
			answer(FAfNa1, CauseFile, with(Object{Section: o.Section, Qualifier: AFQSectionOK}))
		case LSQFile:
			rx := f.rx
			f.rx = nil
			switch {
			case Checksum(rx.data) != o.Checksum || uint32(len(rx.data)) != rx.length:
				answer(FAfNa1, CauseFile, with(Object{Section: o.Section, Qualifier: AFQFileNegative | FileErrChecksum<<4}))
			case f.Store.Write(ctx, rx.ioa, rx.name, rx.data) != nil:
				answer(FAfNa1, CauseFile, with(Object{Section: o.Section, Qualifier: AFQFileNegative | FileErrMemory<<4}))
			default:
				answer(FAfNa1, CauseFile, with(Object{Section: o.Section, Qualifier: AFQFileOK}))
			}
		default: // transfer deactivated by the controlling station
			f.rx = nil
		}
	default:
		mirror(CauseUnknownType)
	}
	return true
}

func (f *FileServer) offering(o Object) bool {
	return f.tx != nil && f.tx.ioa == o.IOA && f.tx.name == o.File
}

func (f *FileServer) receiving(o Object) bool {
	return f.rx != nil && f.rx.ioa == o.IOA && f.rx.name == o.File
}

func (f *FileServer) readySection(answer func(TypeID, Cause, Object), with func(Object) Object) {
	sec := f.tx.sections[f.tx.cur]
	answer(FSrNa1, CauseFile, with(Object{Section: uint8(f.tx.cur + 1), Length: uint32(len(sec))}))
}

// directory answers the call of the directory with cause 5, the last
// entry marked LFD (an empty directory is an ASDU without objects).
func (f *FileServer) directory(ctx context.Context, a *ASDU, reply func(*ASDU)) {
	ents, err := f.Store.Directory(ctx)
	if err != nil {
		ents = nil
	}
	per := f.PerASDU
	if per <= 0 {
		per = 10
	}
	if len(ents) == 0 {
		reply(&ASDU{Type: FDrTa1, Cause: CauseRequest, CA: a.CA, Orig: a.Orig})
		return
	}
	for i := 0; i < len(ents); i += per {
		var objs []Object
		for j, e := range ents[i:min(len(ents), i+per)] {
			st := e.Status &^ SOFLastFile
			if i+j == len(ents)-1 {
				st |= SOFLastFile
			}
			objs = append(objs, Object{IOA: e.IOA, File: e.Name, Length: e.Length, Status: st, Time: e.Time})
		}
		reply(&ASDU{Type: FDrTa1, Cause: CauseRequest, CA: a.CA, Orig: a.Orig, Objects: objs})
	}
}

func (f *FileServer) sectionSize() int {
	if f.SectionSize > 0 {
		return f.SectionSize
	}
	return SectionSize
}

func (f *FileServer) segmentSize() int {
	if f.SegmentSize > 0 {
		return min(f.SegmentSize, 240)
	}
	return 200
}

func split(b []byte, n int) [][]byte {
	var out [][]byte
	for i := 0; i < len(b); i += n {
		out = append(out, b[i:min(len(b), i+n)])
	}
	if len(out) == 0 {
		out = [][]byte{{}}
	}
	return out
}
