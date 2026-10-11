package sec

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha3"
	"encoding/binary"
	"errors"
	"hash"
	"testing"
)

// Covers: SIG-IPE-1414
// Covers: SIG-IPE-1701
func TestMACAlgorithms(t *testing.T) {
	// MAL/DPA codes of IEC 62351-5:2023 8.3.5.4.5 and 8.4.2.4.4.
	for code, want := range map[uint8]struct {
		n   int
		mac bool
	}{3: {8, true}, 4: {16, true}, 7: {8, true}, 8: {16, true}, 9: {8, true}, 10: {16, true}, 11: {0, false}} {
		dp, ok := DataProtectionByCode(code)
		if !ok || (dp.MAC != nil) != want.mac || dp.MAC != nil && dp.MAC.Len != want.n || !want.mac && !dp.AEAD {
			t.Errorf("DPA %d: %+v", code, dp)
		}
	}
	for _, code := range []uint8{0, 1, 2, 5, 6, 12, 128} {
		if _, ok := DataProtectionByCode(code); ok {
			t.Errorf("DPA %d accepted", code)
		}
	}
	if _, ok := MACByCode(11); ok {
		t.Error("AEAD is not a MAL value")
	}
	if kw, ok := KeyWrapByCode(2); !ok || kw.Name != "AES-256 Key Wrap" {
		t.Error("KWA 2")
	}
	if _, ok := KeyWrapByCode(1); ok {
		t.Error("KWA 1 is obsolete")
	}
	// BLAKE2s-256 in the keyed mode of RFC 7693 (9.3.2.3): the BLAKE2
	// reference keyed test vector for an empty message and key 00..1f.
	k := make([]byte, 32)
	for i := range k {
		k[i] = byte(i)
	}
	full := unhex(t, "48a8997da407876b3d79c0d92325ad3b89cbb754d86ab71aee047ad345fd2c49")
	if got := BLAKE2sTCP.Sum(k); !bytes.Equal(got, full[:16]) {
		t.Errorf("BLAKE2s keyed %x", got)
	}
	// RFC 4231 test case 2 (HMAC-SHA-256), truncated per TS 9.3.2 and 9.3.3.
	full = unhex(t, "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843")
	key, data := []byte("Jefe"), []byte("what do ya want for nothing?")
	if got := HMACSHA256Serial.Sum(key, data); !bytes.Equal(got, full[:8]) {
		t.Errorf("serial %x", got)
	}
	if got := HMACSHA256TCP.Sum(key, data[:4], data[4:]); !bytes.Equal(got, full[:16]) {
		t.Errorf("tcp %x", got)
	}
	if !HMACSHA256TCP.Verify(key, full[:16], data) || HMACSHA256TCP.Verify(key, full[:8], data) || HMACSHA256TCP.Verify(key, full[1:17], data) {
		t.Error("verify")
	}
	m := hmac.New(func() hash.Hash { return sha3.New256() }, key)
	m.Write(data)
	if got := HMACSHA3_256Serial.Sum(key, data); !bytes.Equal(got, m.Sum(nil)[:8]) {
		t.Errorf("sha3 %x", got)
	}
	// 5.3.3: HKDF runs with the MAC algorithm's hash. RFC 5869 test case 1.
	okm, err := HMACSHA256TCP.DeriveKeys(unhex(t, "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b"),
		unhex(t, "000102030405060708090a0b0c"), string(unhex(t, "f0f1f2f3f4f5f6f7f8f9")), 42)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(okm, unhex(t, "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865")) {
		t.Errorf("HKDF %x", okm)
	}
}

// Covers: SIG-IPE-1415
func TestAESKeyWrap(t *testing.T) {
	// RFC 3394 4.1 (128-bit KEK) and 4.6 (256-bit KEK, 256-bit key data).
	got, err := AESKeyWrap(unhex(t, "000102030405060708090A0B0C0D0E0F"), unhex(t, "00112233445566778899AABBCCDDEEFF"))
	if err != nil || !bytes.Equal(got, unhex(t, "1FA68B0A8112B447AEF34BD8FB5A7B829D3E862371D2CFE5")) {
		t.Errorf("4.1: %x %v", got, err)
	}
	kek := unhex(t, "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F")
	plain := unhex(t, "00112233445566778899AABBCCDDEEFF000102030405060708090A0B0C0D0E0F")
	want := unhex(t, "28C9F404C4B810F4CBCCB35CFB87F8263F5786E2D80ED326CBC7F0E71A99F43BFB988B9B7A02DD21")
	got, err = AES256KeyWrap.Wrap(kek, plain)
	if err != nil || !bytes.Equal(got, want) {
		t.Errorf("4.6: %x %v", got, err)
	}
	back, err := AES256KeyWrap.Unwrap(kek, want)
	if err != nil || !bytes.Equal(back, plain) {
		t.Errorf("unwrap %x %v", back, err)
	}
	bad := bytes.Clone(want)
	bad[10] ^= 1
	if _, err := AES256KeyWrap.Unwrap(kek, bad); !errors.Is(err, errUnwrap) {
		t.Errorf("tampered unwrap: %v", err)
	}
	if _, err := AES256KeyWrap.Wrap(kek[:16], plain); err == nil {
		t.Error("128-bit KEK accepted for AES-256 Key Wrap")
	}
	// The Table 6 content of a broadcast key change (64 octets) wraps whole.
	content, _ := BroadcastKeyData(bytes.Repeat([]byte{1}, 32), bytes.Repeat([]byte{2}, 32))
	w, err := AES256KeyWrap.Wrap(kek, content)
	if err != nil || len(w) != 72 {
		t.Fatalf("broadcast wrap %d %v", len(w), err)
	}
	u, _ := AES256KeyWrap.Unwrap(kek, w)
	if !bytes.Equal(u, content) {
		t.Error("broadcast unwrap")
	}
}

// Covers: SIG-IPE-1416
// Covers: SIG-IPE-1704
func TestSecureDataProtection(t *testing.T) {
	p := Params104
	key := bytes.Repeat([]byte{0x42}, 32)
	inner := unhex(t, "2d01060001000a000081") // C_SC_NA_1 single command
	d := DUI{Originator: 0, CA: 1}
	mac := HMACSHA256TCP
	whole, err := ProtectSecureData(d, p, Control, 0x0102, 0x0304, 7, inner, DataProtection{MAC: &mac}, key)
	if err != nil {
		t.Fatal(err)
	}
	// Figure 20 layout: DUI, AIM, AIS, DSQ, ADL, ASDU, then the MAC (Figure 5).
	head := unhex(t, "5b010e000100"+"0201"+"0403"+"07000000"+"0a00")
	if !bytes.Equal(whole[:len(head)], head) {
		t.Fatalf("header %x", whole[:len(head)])
	}
	if !bytes.Equal(whole[len(head):len(head)+len(inner)], inner) {
		t.Fatal("ASDU not carried in clear")
	}
	// The MAC covers everything from the DUI on, without the ASC (Figure 5).
	wantMAC := mac.Sum(key, whole[:len(whole)-16])
	if !bytes.Equal(whole[len(whole)-16:], wantMAC) {
		t.Error("MAC is not over DUI..ASDU")
	}
	got, sd, err := OpenSecureData(whole, p, Control, DataProtection{MAC: &mac}, key)
	if err != nil || !bytes.Equal(got, inner) || sd.DSQ != 7 {
		t.Fatalf("open: %x %+v %v", got, sd, err)
	}
	// Any change, in the DUI too, fails.
	for _, i := range []int{0 + 3, 5, 8, len(head), len(whole) - 1} {
		bad := bytes.Clone(whole)
		bad[i] ^= 0x01
		if _, _, err := OpenSecureData(bad, p, Control, DataProtection{MAC: &mac}, key); err == nil {
			t.Errorf("octet %d changed and accepted", i)
		}
	}
	// AEAD (Figure 19): DUI, AIM and AIS are the additional data, DSQ feeds
	// the nonce and ADL with the ASDU is encrypted.
	dp, _ := DataProtectionByCode(11)
	// Table 32: DSQ padded with zeroes to 12 octets.
	if !bytes.Equal(Nonce(9), unhex(t, "090000000000000000000000")) {
		t.Errorf("nonce %x", Nonce(9))
	}
	whole, err = ProtectSecureData(d, p, Monitor, 1, 2, 9, inner, dp, key)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(whole, inner) {
		t.Error("ASDU visible with AEAD")
	}
	block, _ := aes.NewCipher(key)
	g, _ := cipher.NewGCM(block)
	aad := unhex(t, "5b010e000100"+"0100"+"0200")
	plain, err := g.Open(nil, Nonce(9), whole[len(aad)+4:], aad)
	if err != nil {
		t.Fatalf("independent AEAD open: %v", err)
	}
	if binary.LittleEndian.Uint16(plain) != uint16(len(inner)) || !bytes.Equal(plain[2:], inner) {
		t.Errorf("plaintext %x", plain)
	}
	if binary.LittleEndian.Uint32(whole[len(aad):]) != 9 {
		t.Error("DSQ not in clear")
	}
	got, _, err = OpenSecureData(whole, p, Monitor, dp, key)
	if err != nil || !bytes.Equal(got, inner) {
		t.Fatalf("AEAD open %v", err)
	}
	bad := bytes.Clone(whole)
	bad[7] ^= 1 // AIM
	if _, _, err := OpenSecureData(bad, p, Monitor, dp, key); !errors.Is(err, ErrDataAuthentication) {
		t.Errorf("AAD change: %v", err)
	}
	if _, err := ProtectSecureData(d, p, Monitor, 1, 2, 0, inner, dp, key); err == nil {
		t.Error("DSQ 0 accepted (8.5.2.2.4 f)")
	}
}
