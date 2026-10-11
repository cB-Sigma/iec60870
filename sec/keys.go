package sec

import (
	"bytes"
	"crypto/subtle"
	"errors"
	"fmt"
	"sync"
	"time"
)

// SessionKeys are one association's Control Direction and Monitor Direction
// Session Keys (IEC 62351-5:2023 Table 2), 32 octets each (8.4.2.4.6).
type SessionKeys struct {
	Control []byte
	Monitor []byte
}

// Available reports whether both keys are present.
func (k SessionKeys) Available() bool { return len(k.Control) == 32 && len(k.Monitor) == 32 }

// State is what a station keeps of one association over restarts
// (IEC 62351-5:2023 6.2.6.3, 8.3.8.1, 8.3.10, 9.2.7 Table 35; TS 60870-5-7
// 5.3.4.3.2/3 for the session keys). All of it is secret except the IDs and
// the certificate.
type State struct {
	AIM            uint16   `json:"aim"`
	AIS            uint16   `json:"ais"`
	MAL            uint8    `json:"mal"`
	KWA            uint8    `json:"kwa"`
	Encryption     []byte   `json:"enc,omitempty"`  // Encryption Update Key
	Authentication []byte   `json:"auth,omitempty"` // Authentication Update Key
	RemoteCert     []byte   `json:"cert,omitempty"`
	Control        []byte   `json:"cd,omitempty"` // session keys
	Monitor        []byte   `json:"md,omitempty"`
	DPA            uint8    `json:"dpa,omitempty"`
	Roles          []uint16 `json:"roles,omitempty"`
}

// KeyStore keeps one association's State. Implementations must keep it
// secret (encrypted at rest) and must not log it.
type KeyStore interface {
	Load() (State, bool, error)
	Save(State) error
}

// MemoryKeyStore is a KeyStore in memory, for tests and the simulator.
type MemoryKeyStore struct {
	mu sync.Mutex
	st *State
}

// Load implements KeyStore.
func (m *MemoryKeyStore) Load() (State, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.st == nil {
		return State{}, false, nil
	}
	return m.st.clone(), true, nil
}

// Save implements KeyStore.
func (m *MemoryKeyStore) Save(s State) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	c := s.clone()
	m.st = &c
	return nil
}

func (s State) clone() State {
	s.Encryption, s.Authentication = bytes.Clone(s.Encryption), bytes.Clone(s.Authentication)
	s.RemoteCert, s.Control, s.Monitor = bytes.Clone(s.RemoteCert), bytes.Clone(s.Control), bytes.Clone(s.Monitor)
	s.Roles = append([]uint16(nil), s.Roles...)
	return s
}

// KeyUsage is a session key's usage timer and counter against the Max
// Session Key Usage Time and Count (Table 9); zero disables a limit. The
// timer is the one kept running over a communication failure (5.3.2).
type KeyUsage struct {
	MaxTime  time.Duration
	MaxCount uint32
	since    time.Time
	count    uint32
}

// Start restarts the timer and counter for a new key.
func (u *KeyUsage) Start(now time.Time) { u.since, u.count = now, 0 }

// Use counts one use of the key.
func (u *KeyUsage) Use() { u.count++ }

// Count is the number of uses since Start.
func (u *KeyUsage) Count() uint32 { return u.count }

// TimeExpired reports whether the usage time has elapsed.
func (u *KeyUsage) TimeExpired(now time.Time) bool {
	return u.MaxTime > 0 && !u.since.IsZero() && now.Sub(u.since) >= u.MaxTime
}

// CountReached reports whether the usage count has reached its maximum.
func (u *KeyUsage) CountReached() bool { return u.MaxCount > 0 && u.count >= u.MaxCount }

// BroadcastKeyLen is the Broadcast Session Key length, 256 bits (5.3.4.2.1).
const BroadcastKeyLen = 32

// BroadcastKeyData is the plain content of the WKD field for a Broadcast
// Session Key change (5.4.3.11.2 Table 6): the current key followed by the
// new key, the new key all zero when there is none.
func BroadcastKeyData(current, next []byte) ([]byte, error) {
	if len(current) != BroadcastKeyLen {
		return nil, fmt.Errorf("iec60870sec: broadcast session key of %d octets, want %d", len(current), BroadcastKeyLen)
	}
	b := make([]byte, 2*BroadcastKeyLen)
	copy(b, current)
	if next != nil {
		if len(next) != BroadcastKeyLen {
			return nil, fmt.Errorf("iec60870sec: new broadcast session key of %d octets, want %d", len(next), BroadcastKeyLen)
		}
		copy(b[BroadcastKeyLen:], next)
	}
	return b, nil
}

// ParseBroadcastKeyData splits unwrapped Table 6 content into the current and
// new keys; next is nil when the new key is all zero.
func ParseBroadcastKeyData(b []byte) (current, next []byte, err error) {
	if len(b) != 2*BroadcastKeyLen {
		return nil, nil, fmt.Errorf("iec60870sec: broadcast key data of %d octets, want %d", len(b), 2*BroadcastKeyLen)
	}
	current, next = bytes.Clone(b[:BroadcastKeyLen]), bytes.Clone(b[BroadcastKeyLen:])
	if isZero(next) {
		next = nil
	}
	return current, next, nil
}

func isZero(b []byte) bool { return subtle.ConstantTimeCompare(b, make([]byte, len(b))) == 1 }

// BroadcastSender is the controlling station's Broadcast Session Key
// management of IEC 101 (5.3.4.2.2, 5.4.3.11.2).
type BroadcastSender struct {
	mu            sync.Mutex
	dsq           uint32 // DSQ of broadcast Secure Data under the current key (F-417)
	current, next []byte
	pending       map[uint16]bool // controlled stations (by CA) still to be served
	Usage         KeyUsage        // Broadcast Session Key Usage Timer and Counter
}

// ErrNoBroadcastKey is returned when no Broadcast Session Key exists yet.
var ErrNoBroadcastKey = errors.New("iec60870sec: no broadcast session key")

// Key is the key protecting broadcast Secure Data now: the current key,
// also during a distribution.
func (s *BroadcastSender) Key() ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.current == nil {
		return nil, ErrNoBroadcastKey
	}
	return s.current, nil
}

// pendingFor reports whether the distribution in progress still has to
// reach the station.
func (s *BroadcastSender) pendingFor(ca uint16) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.pending != nil && s.pending[ca]
}

// Use counts one use of the Broadcast Session Key.
func (s *BroadcastSender) Use() {
	s.mu.Lock()
	s.Usage.Use()
	s.mu.Unlock()
}

// Distributing reports whether a distribution is in progress.
func (s *BroadcastSender) Distributing() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.pending != nil
}

// Begin starts a distribution to the connected controlled stations. With no
// key yet, fresh becomes the current key and the new key is sent as zero;
// otherwise fresh is the new key. It returns the Table 6 content to wrap in
// each station's Session Key Change Request.
func (s *BroadcastSender) Begin(fresh []byte, stations []uint16) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(fresh) != BroadcastKeyLen || isZero(fresh) {
		return nil, fmt.Errorf("iec60870sec: fresh broadcast key must be %d non-zero octets", BroadcastKeyLen)
	}
	if s.current == nil {
		s.current, s.next = bytes.Clone(fresh), nil
	} else {
		s.next = bytes.Clone(fresh)
	}
	s.pending = map[uint16]bool{}
	for _, st := range stations {
		s.pending[st] = true
	}
	data, err := s.content()
	if err == nil && len(s.pending) == 0 {
		s.finish()
	}
	return data, err
}

// Content is the Table 6 content for the distribution in progress, or for a
// station that asks for keys with a Session Initiation Request afterwards
// (current key, new key zero).
func (s *BroadcastSender) Content() ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.content()
}

func (s *BroadcastSender) content() ([]byte, error) {
	if s.current == nil {
		return nil, ErrNoBroadcastKey
	}
	return BroadcastKeyData(s.current, s.next)
}

// StationDone records the end of a station's Session Key Change for the
// Broadcast Session Key, successful or failed: the distribution completes
// once every station has been tried (5.3.4.2.2). It reports whether the
// distribution completed.
func (s *BroadcastSender) StationDone(ca uint16, now time.Time) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.pending == nil {
		return false
	}
	delete(s.pending, ca)
	if len(s.pending) > 0 {
		return false
	}
	s.finish()
	s.Usage.Start(now)
	return true
}

// NextDSQ numbers a broadcast Secure Data: 1, 2, ... under each key.
func (s *BroadcastSender) NextDSQ() uint32 {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.dsq++
	return s.dsq
}

func (s *BroadcastSender) finish() {
	if s.next != nil {
		s.current, s.next = s.next, nil
		s.dsq = 0
	}
	s.pending = nil
}

// BroadcastReceiver is the controlled station's Broadcast Session Key
// management of IEC 101 (5.3.4.2.3, 5.4.3.11.2).
type BroadcastReceiver struct {
	lastDSQ       uint32
	current, next []byte
	Usage         KeyUsage
}

// Install takes the unwrapped Table 6 content of a successful Session Key
// Change for the Broadcast Session Key. Both keys are then valid; with a zero
// new key only the current key applies.
func (r *BroadcastReceiver) Install(content []byte, now time.Time) error {
	cur, next, err := ParseBroadcastKeyData(content)
	if err != nil {
		return err
	}
	if r.current == nil || !bytes.Equal(cur, r.current) {
		r.lastDSQ = 0
	}
	r.current, r.next = cur, next
	r.Usage.Start(now)
	return nil
}

// Keys returns the keys a broadcast Secure Data may be protected with, the
// new key first.
func (r *BroadcastReceiver) Keys() [][]byte {
	var ks [][]byte
	if r.next != nil {
		ks = append(ks, r.next)
	}
	if r.current != nil {
		ks = append(ks, r.current)
	}
	return ks
}

// Verified records which key verified a broadcast Secure Data: the first one
// protected with the new key makes it the only key (5.3.4.2.3).
func (r *BroadcastReceiver) Verified(key []byte) {
	if r.next != nil && bytes.Equal(key, r.next) {
		r.current, r.next = r.next, nil
		r.lastDSQ = 0
	}
}
