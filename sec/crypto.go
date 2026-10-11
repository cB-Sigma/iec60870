package sec

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha3"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"

	"golang.org/x/crypto/blake2s"
)

var randReader = rand.Reader

// MACAlgorithm is a truncated MAC of IEC 62351-5:2023 8.3.5.4.5 (MAL) and
// 8.4.2.4.4 (DPA), 9.2.2 and 9.3.2.
type MACAlgorithm struct {
	Name  string
	Code  uint8            // the MAL and DPA value
	Hash  func() hash.Hash // hash of the MAC, also used by HKDF (TS 60870-5-7 5.3.3)
	Len   int              // octets kept (the leftmost)
	keyed bool             // BLAKE2s keyed mode of RFC 7693 instead of HMAC
}

func blake2sHash() hash.Hash { h, _ := blake2s.New256(nil); return h }

// The MAC algorithms of the MAL/DPA enumeration. HMAC-SHA-256 is mandatory
// (8 octets on serial links, 16 on TCP/IP); HMAC-SHA3-256 and BLAKE2s-256
// (RFC 7693 keyed mode) are optional.
var (
	HMACSHA256Serial   = MACAlgorithm{"HMAC-SHA-256/8", 3, sha256.New, 8, false}
	HMACSHA256TCP      = MACAlgorithm{"HMAC-SHA-256/16", 4, sha256.New, 16, false}
	HMACSHA3_256Serial = MACAlgorithm{"HMAC-SHA3-256/8", 7, func() hash.Hash { return sha3.New256() }, 8, false}
	HMACSHA3_256TCP    = MACAlgorithm{"HMAC-SHA3-256/16", 8, func() hash.Hash { return sha3.New256() }, 16, false}
	BLAKE2sSerial      = MACAlgorithm{"BLAKE2s-256/8", 9, blake2sHash, 8, true}
	BLAKE2sTCP         = MACAlgorithm{"BLAKE2s-256/16", 10, blake2sHash, 16, true}
)

// Algorithm codes of IEC 62351-5:2023.
const (
	KWAAES256      uint8 = 2  // AES-256 Key Wrap (8.3.5.4.4)
	DPAAES256GCM   uint8 = 11 // AEAD-AES-256-GCM (8.4.2.4.4)
	MALHMACSHA256S uint8 = 3
	MALHMACSHA256N uint8 = 4
)

var macByCode = map[uint8]MACAlgorithm{3: HMACSHA256Serial, 4: HMACSHA256TCP, 7: HMACSHA3_256Serial, 8: HMACSHA3_256TCP, 9: BLAKE2sSerial, 10: BLAKE2sTCP}

// MACByCode returns the MAC algorithm of a MAL or DPA value.
func MACByCode(code uint8) (MACAlgorithm, bool) { m, ok := macByCode[code]; return m, ok }

// DataProtectionByCode returns the Secure Data algorithm of a DPA value.
func DataProtectionByCode(code uint8) (DataProtection, bool) {
	if code == DPAAES256GCM {
		return DataProtection{AEAD: true, Code: code}, true
	}
	m, ok := macByCode[code]
	if !ok {
		return DataProtection{}, false
	}
	return DataProtection{MAC: &m, Code: code}, true
}

// Sum returns the truncated MAC of the concatenated parts.
func (a MACAlgorithm) Sum(key []byte, parts ...[]byte) []byte {
	var m hash.Hash
	if a.keyed {
		m, _ = blake2s.New256(key)
	} else {
		m = hmac.New(a.Hash, key)
	}
	for _, p := range parts {
		m.Write(p)
	}
	return m.Sum(nil)[:a.Len]
}

// Verify compares a received MAC in constant time; a MAC of the wrong
// length never matches.
func (a MACAlgorithm) Verify(key, got []byte, parts ...[]byte) bool {
	return len(got) == a.Len && subtle.ConstantTimeCompare(a.Sum(key, parts...), got) == 1
}

// DeriveKeys runs HKDF (RFC 5869 extract and expand) with the algorithm's
// hash.
func (a MACAlgorithm) DeriveKeys(secret, salt []byte, info string, n int) ([]byte, error) {
	return hkdf.Key(a.Hash, secret, salt, info, n)
}

// DataProtection is the algorithm protecting Secure Data (DPA): a MAC or
// AEAD-AES-256-GCM.
type DataProtection struct {
	MAC  *MACAlgorithm
	AEAD bool
	Code uint8
}

// AESGCMTagLen is the AES-GCM tag length used for AEAD Secure Data.
const AESGCMTagLen = 16

// Nonce is the AES-GCM nonce of a Secure Data message: DSQ padded with
// zeroes to 12 octets (IEC 62351-5:2023 Table 32), DSQ in its transmitted
// order (least significant octet first, 8.2.1) followed by the zeroes
// (F-423).
func Nonce(dsq uint32) []byte {
	n := make([]byte, 12)
	binary.LittleEndian.PutUint32(n, dsq)
	return n
}

// KeyWrap is a key wrap algorithm of 9.2.3.
type KeyWrap struct {
	Name   string
	Code   uint8
	Wrap   func(kek, plain []byte) ([]byte, error)
	Unwrap func(kek, wrapped []byte) ([]byte, error)
}

// AES256KeyWrap is the mandatory AES-256 Key Wrap: RFC 3394 with the
// default initial value and the Encryption Update Key as KEK (9.2.3.2).
var AES256KeyWrap = KeyWrap{Name: "AES-256 Key Wrap", Code: KWAAES256, Wrap: aesKeyWrap256, Unwrap: aesKeyUnwrap256}

// KeyWrapByCode returns the key wrap algorithm of a KWA value.
func KeyWrapByCode(code uint8) (KeyWrap, bool) {
	if code == KWAAES256 {
		return AES256KeyWrap, true
	}
	return KeyWrap{}, false
}

var defaultIV = [8]byte{0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6}

var errUnwrap = errors.New("iec60870sec: key unwrap integrity check failed")

func aesKeyWrap256(kek, plain []byte) ([]byte, error) {
	if len(kek) != 32 {
		return nil, fmt.Errorf("iec60870sec: key wrap key of %d octets, want 32", len(kek))
	}
	return AESKeyWrap(kek, plain)
}

func aesKeyUnwrap256(kek, wrapped []byte) ([]byte, error) {
	if len(kek) != 32 {
		return nil, fmt.Errorf("iec60870sec: key wrap key of %d octets, want 32", len(kek))
	}
	return AESKeyUnwrap(kek, wrapped)
}

// AESKeyWrap is RFC 3394 key wrap (any AES key size).
func AESKeyWrap(kek, plain []byte) ([]byte, error) {
	if len(plain) < 16 || len(plain)%8 != 0 {
		return nil, fmt.Errorf("iec60870sec: key data of %d octets, want a multiple of 8 of at least 16", len(plain))
	}
	c, err := aes.NewCipher(kek)
	if err != nil {
		return nil, err
	}
	n := len(plain) / 8
	a := defaultIV
	r := make([]byte, len(plain))
	copy(r, plain)
	var b [16]byte
	for j := 0; j < 6; j++ {
		for i := 0; i < n; i++ {
			copy(b[:8], a[:])
			copy(b[8:], r[i*8:i*8+8])
			c.Encrypt(b[:], b[:])
			t := uint64(n*j + i + 1)
			binary.BigEndian.PutUint64(a[:], binary.BigEndian.Uint64(b[:8])^t)
			copy(r[i*8:], b[8:])
		}
	}
	return append(a[:], r...), nil
}

// AESKeyUnwrap is RFC 3394 key unwrap with the default initial value check.
func AESKeyUnwrap(kek, wrapped []byte) ([]byte, error) {
	if len(wrapped) < 24 || len(wrapped)%8 != 0 {
		return nil, fmt.Errorf("iec60870sec: wrapped key data of %d octets", len(wrapped))
	}
	c, err := aes.NewCipher(kek)
	if err != nil {
		return nil, err
	}
	n := len(wrapped)/8 - 1
	var a [8]byte
	copy(a[:], wrapped[:8])
	r := make([]byte, n*8)
	copy(r, wrapped[8:])
	var b [16]byte
	for j := 5; j >= 0; j-- {
		for i := n - 1; i >= 0; i-- {
			t := uint64(n*j + i + 1)
			binary.BigEndian.PutUint64(b[:8], binary.BigEndian.Uint64(a[:])^t)
			copy(b[8:], r[i*8:i*8+8])
			c.Decrypt(b[:], b[:])
			copy(a[:], b[:8])
			copy(r[i*8:], b[8:])
		}
	}
	if subtle.ConstantTimeCompare(a[:], defaultIV[:]) != 1 {
		return nil, errUnwrap
	}
	return r, nil
}

func newGCM(key []byte) (cipher.AEAD, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("iec60870sec: AES-256-GCM key of %d octets, want 32", len(key))
	}
	c, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(c)
}

func ecdsaFromECDH(k *PrivateKey) (*ecdsa.PrivateKey, error) {
	return ecdsa.ParseRawPrivateKey(elliptic.P256(), k.nist.Bytes())
}

func randomBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	_, err := rand.Read(b)
	return b, err
}
