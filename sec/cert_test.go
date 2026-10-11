package sec

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"testing"
	"time"
)

// Covers: SIG-IPE-1702
func TestECDHAndUpdateKeyDerivation(t *testing.T) {
	// RFC 7748 6.1 (X25519) test vector.
	a, err := ParsePrivateKey(Curve25519, unhex(t, "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(a.PublicKey(), unhex(t, "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a")) {
		t.Errorf("X25519 public %x", a.PublicKey())
	}
	k, err := a.ECDH(unhex(t, "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f"))
	if err != nil || !bytes.Equal(k, unhex(t, "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742")) {
		t.Errorf("X25519 shared %x %v", k, err)
	}
	// Every Table 8 mandatory curve agrees on the IKM from both sides.
	for _, c := range []Curve{Curve25519, Curve448, Secp256k1, Secp256r1} {
		x, _ := GenerateKey(c)
		y, _ := GenerateKey(c)
		k1, err1 := x.ECDH(y.PublicKey())
		k2, err2 := y.ECDH(x.PublicKey())
		if err1 != nil || err2 != nil || !bytes.Equal(k1, k2) || len(k1) < 32 {
			t.Errorf("%s: %v %v", c, err1, err2)
		}
		back, err := ParsePrivateKey(c, x.Bytes())
		if err != nil || !bytes.Equal(back.PublicKey(), x.PublicKey()) {
			t.Errorf("%s private key round trip", c)
		}
	}
	// 8.3.10: salt = controlling random || controlled random, info empty,
	// L = 64, T[0:32] encryption, T[32:64] authentication; the hash of the MAL.
	ikm, r1, r2 := bytes.Repeat([]byte{7}, 32), []byte{1, 2, 3, 4}, []byte{5, 6, 7, 8, 9}
	uk, err := DeriveUpdateKeys(HMACSHA256TCP, ikm, r1, r2)
	if err != nil {
		t.Fatal(err)
	}
	prk := hmacSHA256(append(append([]byte(nil), r1...), r2...), ikm)
	t1 := hmacSHA256(prk, []byte{1})
	t2 := hmacSHA256(prk, append(append([]byte(nil), t1...), 2))
	if !bytes.Equal(uk.Encryption, t1) || !bytes.Equal(uk.Authentication, t2) {
		t.Error("update keys are not HKDF T(1) and T(2)")
	}
	uk3, _ := DeriveUpdateKeys(HMACSHA3_256TCP, ikm, r1, r2)
	if uk3.Equal(uk) {
		t.Error("the MAL hash is not used")
	}
}

func hmacSHA256(key, data []byte) []byte {
	m := HMACSHA256TCP
	m.Len = 32
	return m.Sum(key, data)
}

// Covers: SIG-IPE-1703
func TestCertificateVerification(t *testing.T) {
	now := time.Now()
	for _, c := range []Curve{Secp256r1, Secp256k1} {
		id, err := NewIdentity(c, "rtu-1", 24*time.Hour)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := VerifyRemote(id.Certificate, c, id.Pin(), now, false); err != nil {
			t.Errorf("%s self-signed: %v", c, err)
		}
		fp, _ := ParseCertificate(id.Certificate)
		if _, err := VerifyRemote(id.Certificate, c, Trust{Fingerprints: [][32]byte{fp.Fingerprint()}}, now, false); err != nil {
			t.Errorf("%s by fingerprint: %v", c, err)
		}
		var ce *CertError
		if _, err := VerifyRemote(id.Certificate, c, Trust{}, now, false); !errors.As(err, &ce) || !ce.NotAuthorized {
			t.Errorf("%s unpinned: %v", c, err)
		}
		bad := bytes.Clone(id.Certificate)
		bad[len(bad)-3] ^= 1
		if _, err := VerifyRemote(bad, c, id.Pin(), now, false); !errors.As(err, &ce) || ce.NotAuthorized {
			t.Errorf("%s bad signature: %v", c, err)
		}
		if _, err := VerifyRemote(id.Certificate, c, id.Pin(), now.Add(48*time.Hour), false); err == nil {
			t.Errorf("%s expired accepted", c)
		}
		if _, err := VerifyRemote(id.Certificate, c, id.Pin(), now.Add(48*time.Hour), true); err != nil {
			t.Errorf("%s validity ignored (TS Annex B): %v", c, err)
		}
		other := Secp256r1
		if c == Secp256r1 {
			other = Secp256k1
		}
		if _, err := VerifyRemote(id.Certificate, other, id.Pin(), now, false); err == nil {
			t.Errorf("%s: curve mismatch accepted", c)
		}
	}
	// A Montgomery key cannot sign, so it needs a CA: X25519 and X448 keys
	// signed by a P-256 CA of our builder, and an X25519 key signed by an RSA
	// CA made with crypto/x509 (independent encoder).
	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	caTmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Central Authority"}, NotBefore: now.Add(-time.Hour),
		NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	ca, err := ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []Curve{Curve25519, Curve448} {
		k, _ := GenerateKey(c)
		der, err := BuildCertificate(CertTemplate{Subject: pkix.Name{CommonName: "scada"}, Issuer: ca, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour)},
			k.PublicKey(), c, ECDSASigner{caKey})
		if err != nil {
			t.Fatal(err)
		}
		got, err := VerifyRemote(der, c, Trust{CAs: [][]byte{caDER}}, now, false)
		if err != nil || !bytes.Equal(got.PublicKey, k.PublicKey()) {
			t.Errorf("%s CA-signed: %v", c, err)
		}
		if _, err := VerifyRemote(der, c, Trust{CAs: [][]byte{caDER}, DNs: [][]byte{ca.SubjectDN}}, now, false); err == nil {
			t.Errorf("%s: DN not in the list accepted", c)
		}
	}
	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	rsaTmpl := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "RSA CA"}, NotBefore: now.Add(-time.Hour),
		NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	rsaDER, _ := x509.CreateCertificate(rand.Reader, rsaTmpl, rsaTmpl, &rsaKey.PublicKey, rsaKey)
	xk, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	leaf := &x509.Certificate{SerialNumber: big.NewInt(3), Subject: pkix.Name{CommonName: "rtu-x"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour)}
	leafDER, err := x509.CreateCertificate(rand.Reader, leaf, rsaTmpl, &xk.PublicKey, rsaKey)
	if err != nil {
		t.Fatal(err)
	}
	xpub, _ := xk.PublicKey.ECDH()
	if got, err := VerifyRemote(leafDER, Secp256r1, Trust{CAs: [][]byte{rsaDER}}, now, false); err != nil || !bytes.Equal(got.PublicKey, xpub.Bytes()) {
		t.Errorf("RSA CA signed P-256 certificate: %v", err)
	}
	if _, err := VerifyRemote(leafDER, Secp256r1, Trust{}, now, false); err == nil {
		t.Error("CA not provisioned accepted")
	}
}
