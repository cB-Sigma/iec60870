// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package cs101

import (
	"errors"
	"io"
	"sync"
)

// SharedLine puts several controlled-station link addresses on one
// unbalanced line (a party line served by one device: a gateway standing
// in for several stations, or one station answering a separate link
// address per controlling station). Each Port it hands out carries the
// frames addressed to its link address, and the broadcast address, to a
// Secondary; what the Secondaries send goes out on the line one frame at a
// time.
type SharedLine struct {
	line  *Port
	asize int

	wmu    sync.Mutex
	mu     sync.Mutex
	ends   map[uint16]*lineEnd
	closed bool
}

// NewSharedLine reads frames from rw (asize octets of link address, 1 or
// 2) and hands them to the Ports of their addresses.
func NewSharedLine(rw io.ReadWriteCloser, asize int) *SharedLine {
	s := &SharedLine{line: NewPort(rw), asize: asize, ends: map[uint16]*lineEnd{}}
	go s.read()
	return s
}

// Port returns the end of link address addr, for NewSecondary with the
// same address size. A second call for an address replaces the first end.
func (s *SharedLine) Port(addr uint16) *Port {
	e := &lineEnd{s: s, addr: addr, in: make(chan []byte, 16), done: make(chan struct{})}
	s.mu.Lock()
	if old := s.ends[addr]; old != nil {
		old.close()
	}
	if s.closed {
		e.close()
	}
	s.ends[addr] = e
	s.mu.Unlock()
	return NewPort(e)
}

// Close closes the line and every end.
func (s *SharedLine) Close() error {
	s.mu.Lock()
	s.closed = true
	for _, e := range s.ends {
		e.close()
	}
	s.mu.Unlock()
	return s.line.Close()
}

// Err is why the line stopped.
func (s *SharedLine) Err() error { return s.line.Err() }

func (s *SharedLine) read() {
	bcast := BroadcastAddr(s.asize)
	for {
		f, err := ReadFrame(s.line, s.asize)
		if errors.Is(err, ErrFrame) {
			continue
		}
		if err != nil {
			s.mu.Lock()
			s.closed = true
			for _, e := range s.ends {
				e.close()
			}
			s.mu.Unlock()
			return
		}
		if f.Single || !f.PRM() {
			continue // only primary frames are addressed to us
		}
		b := f.Encode(s.asize)
		s.mu.Lock()
		var to []*lineEnd
		if f.Addr == bcast {
			for _, e := range s.ends {
				to = append(to, e)
			}
		} else if e := s.ends[f.Addr]; e != nil {
			to = append(to, e)
		}
		s.mu.Unlock()
		for _, e := range to {
			select {
			case e.in <- b:
			case <-e.done:
			}
		}
	}
}

// lineEnd is one link address's side of a SharedLine.
type lineEnd struct {
	s    *SharedLine
	addr uint16
	in   chan []byte
	buf  []byte
	done chan struct{}
	once sync.Once
}

func (e *lineEnd) close() { e.once.Do(func() { close(e.done) }) }

func (e *lineEnd) Read(b []byte) (int, error) {
	for len(e.buf) == 0 {
		select {
		case x := <-e.in:
			e.buf = x
		case <-e.done:
			return 0, io.EOF
		}
	}
	n := copy(b, e.buf)
	e.buf = e.buf[n:]
	return n, nil
}

func (e *lineEnd) Write(b []byte) (int, error) {
	select {
	case <-e.done:
		return 0, io.ErrClosedPipe
	default:
	}
	e.s.wmu.Lock()
	defer e.s.wmu.Unlock()
	return e.s.line.Write(b)
}

func (e *lineEnd) Close() error {
	e.close()
	e.s.mu.Lock()
	if e.s.ends[e.addr] == e {
		delete(e.s.ends, e.addr)
	}
	e.s.mu.Unlock()
	return nil
}
