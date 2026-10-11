// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package cs101

import (
	"errors"
	"testing"
	"time"

	"github.com/goburrow/serial"
)

// racyPort behaves like goburrow/serial's port: Read uses a descriptor
// that Close overwrites, without a lock, and Read returns on its own
// timeout.
type racyPort struct{ fd int }

func (r *racyPort) Read(b []byte) (int, error) {
	if r.fd < 0 {
		return 0, errors.New("closed")
	}
	time.Sleep(5 * time.Millisecond)
	return 0, serial.ErrTimeout
}

func (r *racyPort) Write(b []byte) (int, error) {
	if r.fd < 0 {
		return 0, errors.New("closed")
	}
	return len(b), nil
}

func (r *racyPort) Close() error { r.fd = -1; return nil }

// Closing a serial port while its reader runs must not race (go test
// -race): the guard holds Close until the read in progress returns (found
// with a pty in the dnp3 library, which uses the same serial package).
//
// Covers: SIG-IPE-1334
func TestSerialCloseWhileReading(t *testing.T) {
	p := NewPort(guard(&racyPort{fd: 3}))
	time.Sleep(20 * time.Millisecond)
	if _, err := p.Write([]byte{0x10}); err != nil {
		t.Fatal(err)
	}
	if err := p.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := p.Write([]byte{0x10}); err == nil {
		t.Error("a write after Close succeeded")
	}
}
