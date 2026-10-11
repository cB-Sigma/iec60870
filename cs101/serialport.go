package cs101

import (
	"errors"
	"io"
	"sync"
	"sync/atomic"
	"time"

	"github.com/goburrow/serial"
)

// OpenSerial opens a local serial port for FT1.2 with eight data bits, one
// stop bit and parity "E" (the FT1.2 default), "N" or "O".
func OpenSerial(dev string, baud int, parity string) (io.ReadWriteCloser, error) {
	p, err := serial.Open(&serial.Config{Address: dev, BaudRate: baud, DataBits: 8, StopBits: 1, Parity: parity, Timeout: 100 * time.Millisecond})
	if err != nil {
		return nil, err
	}
	return guard(p), nil
}

// guarded serialises Close with the reads and writes in progress: the
// serial package's Close changes the descriptor its Read uses without a
// lock. Read and Write share the lock; Close marks the port closed and
// waits for the read in progress, which its read timeout bounds.
type guarded struct {
	rw     io.ReadWriteCloser
	mu     sync.RWMutex
	closed atomic.Bool
}

func guard(rw io.ReadWriteCloser) io.ReadWriteCloser { return &guarded{rw: rw} }

var errPortClosed = errors.New("the serial port is closed")

func (g *guarded) Read(b []byte) (int, error) {
	if g.closed.Load() {
		return 0, errPortClosed
	}
	g.mu.RLock()
	defer g.mu.RUnlock()
	if g.closed.Load() {
		return 0, errPortClosed
	}
	return g.rw.Read(b)
}

func (g *guarded) Write(b []byte) (int, error) {
	if g.closed.Load() {
		return 0, errPortClosed
	}
	g.mu.RLock()
	defer g.mu.RUnlock()
	if g.closed.Load() {
		return 0, errPortClosed
	}
	return g.rw.Write(b)
}

func (g *guarded) Close() error {
	if g.closed.Swap(true) {
		return nil
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.rw.Close()
}

// Port turns a byte stream into ReadByte calls with a deadline. A reader
// goroutine feeds a channel, so serial read timeouts and TCP reads look
// the same.
type Port struct {
	rw       io.ReadWriteCloser
	in       chan []byte
	buf      []byte
	deadline time.Time
	done     chan struct{}
	once     sync.Once
	mu       sync.Mutex
	err      error
}

// ErrTimeout is ReadByte's error when nothing came before the deadline.
var ErrTimeout = errors.New("no answer within the timeout")

// NewPort reads rw (a serial port, a TCP connection to a converter) in a
// goroutine until it fails or is closed.
func NewPort(rw io.ReadWriteCloser) *Port {
	p := &Port{rw: rw, in: make(chan []byte, 64), done: make(chan struct{})}
	go p.read()
	return p
}

func (p *Port) read() {
	for {
		b := make([]byte, 256)
		n, err := p.rw.Read(b)
		if n > 0 {
			select {
			case p.in <- b[:n]:
			case <-p.done:
				return
			}
		}
		if err != nil {
			if errors.Is(err, serial.ErrTimeout) {
				continue
			}
			p.fail(err)
			return
		}
	}
}

func (p *Port) fail(err error) {
	p.mu.Lock()
	if p.err == nil {
		p.err = err
	}
	p.mu.Unlock()
	p.once.Do(func() { close(p.done) })
}

// Err is why the port stopped.
func (p *Port) Err() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.err
}

// Close ends the port.
func (p *Port) Close() error {
	p.fail(errors.New("closed"))
	return p.rw.Close()
}

// Write writes b to the line.
func (p *Port) Write(b []byte) (int, error) {
	select {
	case <-p.done:
		return 0, p.Err()
	default:
	}
	n, err := p.rw.Write(b)
	if err != nil {
		p.fail(err)
	}
	return n, err
}

// SetDeadline bounds the following ReadByte calls; zero waits forever.
func (p *Port) SetDeadline(t time.Time) { p.deadline = t }

// ReadByte returns the next byte, ErrTimeout after the deadline.
func (p *Port) ReadByte() (byte, error) {
	for len(p.buf) == 0 {
		var timer <-chan time.Time
		if !p.deadline.IsZero() {
			d := time.Until(p.deadline)
			if d <= 0 {
				select {
				case b := <-p.in:
					p.buf = b
					continue
				default:
					return 0, ErrTimeout
				}
			}
			t := time.NewTimer(d)
			defer t.Stop()
			timer = t.C
		}
		select {
		case b := <-p.in:
			p.buf = b
		case <-p.done:
			select {
			case b := <-p.in:
				p.buf = b
				continue
			default:
			}
			return 0, p.Err()
		case <-timer:
			return 0, ErrTimeout
		}
	}
	c := p.buf[0]
	p.buf = p.buf[1:]
	return c, nil
}
