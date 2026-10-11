package sec

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"time"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	k1ecdsa "github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"

	"github.com/cB-Sigma/iotcrypto/brainpool"
)

// Device certificates (IEC 62351-5:2023 8.3.2): X.509 in DER, an ECDH
// public key of at least 256 bits on a Table 8 curve, self-signed with
// ECDSA-with-SHA256 on secp256k1 or secp256r1, or signed by the Central
// Authority with ECDSA or RSA (SHA-256 or better). The Go x509 package
// does not parse secp256k1 or Curve448 keys, so certificates are read here
// with encoding/asn1.

// MaxCertificateSize is the certificate size every implementation must
// accept (8.3.2.1).
const MaxCertificateSize = 8192

var (
	oidX25519          = asn1.ObjectIdentifier{1, 3, 101, 110}
	oidX448            = asn1.ObjectIdentifier{1, 3, 101, 111}
	oidECPublicKey     = asn1.ObjectIdentifier{1, 2, 840, 10045, 2, 1}
	oidP256            = asn1.ObjectIdentifier{1, 2, 840, 10045, 3, 1, 7}
	oidSecp256k1       = asn1.ObjectIdentifier{1, 3, 132, 0, 10}
	oidBrainpoolP256r1 = asn1.ObjectIdentifier{1, 3, 36, 3, 3, 2, 8, 1, 1, 7}
	oidRSA             = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 1}
	oidECDSAWithSHA256 = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 2}
	oidSHA256WithRSA   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 11}
	oidSHA384WithRSA   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 12}
	oidSHA512WithRSA   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 13}
)

type algID struct {
	Algorithm  asn1.ObjectIdentifier
	Parameters asn1.RawValue `asn1:"optional"`
}

type spki struct {
	Raw       asn1.RawContent
	Algorithm algID
	PublicKey asn1.BitString
}

type validity struct {
	NotBefore, NotAfter time.Time
}

type tbsCert struct {
	Raw        asn1.RawContent
	Version    int `asn1:"optional,explicit,default:0,tag:0"`
	Serial     *big.Int
	Signature  algID
	Issuer     asn1.RawValue
	Validity   validity
	Subject    asn1.RawValue
	PublicKey  spki
	IssuerUID  asn1.BitString   `asn1:"optional,tag:1"`
	SubjectUID asn1.BitString   `asn1:"optional,tag:2"`
	Extensions []pkix.Extension `asn1:"optional,explicit,tag:3"`
}

type certificate struct {
	Raw       asn1.RawContent
	TBS       tbsCert
	Algorithm algID
	Signature asn1.BitString
}

// Certificate is a parsed device or Central Authority certificate.
type Certificate struct {
	Raw        []byte
	Curve      Curve  // CurveUnknown for an RSA key
	PublicKey  []byte // subjectPublicKey octets
	SubjectDN  []byte // DER of the subject Name
	IssuerDN   []byte
	Subject    string
	Serial     *big.Int // the serial number
	NotBefore  time.Time
	NotAfter   time.Time
	Extensions []pkix.Extension
	spki       []byte
	tbs        []byte
	sigAlg     asn1.ObjectIdentifier
	sig        []byte
}

// ParseCertificate reads a DER certificate.
func ParseCertificate(der []byte) (*Certificate, error) {
	if len(der) > MaxCertificateSize*8 {
		return nil, errors.New("iec60870sec: certificate too large")
	}
	var c certificate
	rest, err := asn1.Unmarshal(der, &c)
	if err != nil {
		return nil, fmt.Errorf("iec60870sec: certificate: %w", err)
	}
	if len(rest) != 0 {
		return nil, errors.New("iec60870sec: certificate has trailing data")
	}
	out := &Certificate{
		Raw: der, PublicKey: c.TBS.PublicKey.PublicKey.RightAlign(), SubjectDN: c.TBS.Subject.FullBytes,
		IssuerDN: c.TBS.Issuer.FullBytes, Serial: c.TBS.Serial, NotBefore: c.TBS.Validity.NotBefore, NotAfter: c.TBS.Validity.NotAfter,
		Extensions: c.TBS.Extensions, tbs: c.TBS.Raw, sigAlg: c.Algorithm.Algorithm, sig: c.Signature.RightAlign(),
	}
	out.spki = c.TBS.PublicKey.Raw
	var name pkix.RDNSequence
	if _, err := asn1.Unmarshal(out.SubjectDN, &name); err == nil {
		var n pkix.Name
		n.FillFromRDNSequence(&name)
		out.Subject = n.String()
	}
	alg := c.TBS.PublicKey.Algorithm
	switch {
	case alg.Algorithm.Equal(oidX25519):
		out.Curve = Curve25519
	case alg.Algorithm.Equal(oidX448):
		out.Curve = Curve448
	case alg.Algorithm.Equal(oidECPublicKey):
		var curve asn1.ObjectIdentifier
		if _, err := asn1.Unmarshal(alg.Parameters.FullBytes, &curve); err != nil {
			return nil, errors.New("iec60870sec: EC public key without a named curve")
		}
		switch {
		case curve.Equal(oidP256):
			out.Curve = Secp256r1
		case curve.Equal(oidSecp256k1):
			out.Curve = Secp256k1
		case curve.Equal(oidBrainpoolP256r1):
			out.Curve = BrainpoolP256r1
		default:
			return nil, fmt.Errorf("iec60870sec: EC curve %s not permitted (IEC 62351-5 Table 8)", curve)
		}
	case alg.Algorithm.Equal(oidRSA):
	default:
		return nil, fmt.Errorf("iec60870sec: public key algorithm %s not permitted", alg.Algorithm)
	}
	return out, nil
}

// Fingerprint is the SHA-256 digest of the certificate (F-425).
func (c *Certificate) Fingerprint() [32]byte { return sha256.Sum256(c.Raw) }

// SelfSigned reports whether issuer and subject are the same name.
func (c *Certificate) SelfSigned() bool { return bytes.Equal(c.IssuerDN, c.SubjectDN) }

// CheckSignature verifies the certificate's signature with the issuer's
// key: ECDSA with SHA-256 on secp256r1 or secp256k1, or RSA (PKCS #1 v1.5,
// SHA-256 or better, 2048 bits or more) (8.3.2.3, 8.3.2.4).
func (c *Certificate) CheckSignature(issuer *Certificate) error {
	switch {
	case c.sigAlg.Equal(oidECDSAWithSHA256):
		h := sha256.Sum256(c.tbs)
		switch issuer.Curve {
		case Secp256r1:
			pub, err := x509.ParsePKIXPublicKey(issuer.spki)
			if err != nil {
				return err
			}
			ek, ok := pub.(*ecdsa.PublicKey)
			if !ok || !ecdsa.VerifyASN1(ek, h[:], c.sig) {
				return errors.New("iec60870sec: certificate signature not valid")
			}
			return nil
		case Secp256k1:
			pub, err := secp256k1.ParsePubKey(issuer.PublicKey)
			if err != nil {
				return err
			}
			sig, err := k1ecdsa.ParseDERSignature(c.sig)
			if err != nil || !sig.Verify(h[:], pub) {
				return errors.New("iec60870sec: certificate signature not valid")
			}
			return nil
		case BrainpoolP256r1:
			if len(issuer.PublicKey) != 65 || issuer.PublicKey[0] != 4 {
				return errors.New("iec60870sec: brainpoolP256r1 key not an uncompressed point")
			}
			pub := &ecdsa.PublicKey{Curve: brainpool.P256r1(), X: new(big.Int).SetBytes(issuer.PublicKey[1:33]), Y: new(big.Int).SetBytes(issuer.PublicKey[33:])}
			if !brainpool.Verify(pub, h[:], c.sig) {
				return errors.New("iec60870sec: certificate signature not valid")
			}
			return nil
		}
		return fmt.Errorf("iec60870sec: a %s key cannot sign certificates", issuer.Curve)
	case c.sigAlg.Equal(oidSHA256WithRSA), c.sigAlg.Equal(oidSHA384WithRSA), c.sigAlg.Equal(oidSHA512WithRSA):
		pub, err := x509.ParsePKIXPublicKey(issuer.spki)
		if err != nil {
			return err
		}
		rk, ok := pub.(*rsa.PublicKey)
		if !ok {
			return errors.New("iec60870sec: RSA signature by a non-RSA key")
		}
		if rk.N.BitLen() < 2048 {
			return errors.New("iec60870sec: RSA key shorter than 2048 bits")
		}
		alg := x509.SHA256WithRSA
		if c.sigAlg.Equal(oidSHA384WithRSA) {
			alg = x509.SHA384WithRSA
		} else if c.sigAlg.Equal(oidSHA512WithRSA) {
			alg = x509.SHA512WithRSA
		}
		cert := &x509.Certificate{PublicKey: rk, PublicKeyAlgorithm: x509.RSA}
		return cert.CheckSignature(alg, c.tbs, c.sig)
	}
	return fmt.Errorf("iec60870sec: signature algorithm %s not permitted", c.sigAlg)
}

// Trust is what a station knows about the remote stations it may associate
// with (8.3.3, 8.3.4, 9.2.6.2, 9.2.6.9).
type Trust struct {
	// PublicKeys are the pinned public keys of authorized remote stations
	// (subjectPublicKey octets); Fingerprints their certificate SHA-256
	// digests. Either admits a self-signed certificate.
	PublicKeys   [][]byte
	Fingerprints [][32]byte
	// CAs are the Central Authority certificates (DER) that may sign remote
	// station certificates.
	CAs [][]byte
	// DNs, when set, lists the subject names (DER) authorized to
	// communicate (checked for CA-signed certificates).
	DNs [][]byte
}

// CertError says which Table 15/16 row a refused certificate falls under.
type CertError struct {
	NotAuthorized bool // "not authorized to communicate" rows; else "not valid"
	Err           error
}

// Error is the underlying error's text.
func (e *CertError) Error() string { return e.Err.Error() }

// VerifyRemote checks a remote station's certificate as 8.3.8 requires:
// its curve matches ours, the key is 256 bits or more, the validity period
// covers now (unless ignoreValidity, TS 60870-5-7 Annex B), the signature
// verifies, and it is authorized (a pinned key or fingerprint for a
// self-signed certificate, a configured CA and optional DN list otherwise).
func VerifyRemote(der []byte, own Curve, trust Trust, now time.Time, ignoreValidity bool) (*Certificate, error) {
	notValid := func(err error) (*Certificate, error) { return nil, &CertError{Err: err} }
	notAuth := func(err error) (*Certificate, error) { return nil, &CertError{NotAuthorized: true, Err: err} }
	if len(der) == 0 || len(der) > 0xFFFF {
		return notValid(errors.New("iec60870sec: certificate length not permitted"))
	}
	c, err := ParseCertificate(der)
	if err != nil {
		return notValid(err)
	}
	if c.Curve == CurveUnknown || c.Curve != own {
		return notValid(fmt.Errorf("iec60870sec: remote key on %s, ours on %s", c.Curve, own))
	}
	if len(c.PublicKey) < 32 {
		return notValid(errors.New("iec60870sec: public key shorter than 256 bits"))
	}
	if !ignoreValidity && (now.Before(c.NotBefore) || now.After(c.NotAfter)) {
		return notValid(errors.New("iec60870sec: certificate outside its validity period"))
	}
	if c.SelfSigned() {
		if !c.Curve.CanSign() {
			return notValid(fmt.Errorf("iec60870sec: a self-signed certificate cannot carry a %s key", c.Curve))
		}
		if err := c.CheckSignature(c); err != nil {
			return notValid(err)
		}
		fp := c.Fingerprint()
		for _, k := range trust.PublicKeys {
			if bytes.Equal(k, c.PublicKey) {
				return c, nil
			}
		}
		for _, f := range trust.Fingerprints {
			if f == fp {
				return c, nil
			}
		}
		return notAuth(errors.New("iec60870sec: self-signed certificate of a station not provisioned"))
	}
	for _, caDER := range trust.CAs {
		ca, err := ParseCertificate(caDER)
		if err != nil || !bytes.Equal(ca.SubjectDN, c.IssuerDN) {
			continue
		}
		if err := c.CheckSignature(ca); err != nil {
			return notValid(err)
		}
		if len(trust.DNs) > 0 {
			ok := false
			for _, dn := range trust.DNs {
				ok = ok || bytes.Equal(dn, c.SubjectDN)
			}
			if !ok {
				return notAuth(errors.New("iec60870sec: station name not authorized by configuration"))
			}
		}
		return c, nil
	}
	return notAuth(errors.New("iec60870sec: certificate issued by a Central Authority not provisioned"))
}

// Signer signs certificates in BuildCertificate: a secp256r1 or secp256k1
// private key.
type Signer interface {
	signerCurve() Curve
	sign(digest []byte) ([]byte, error)
	publicKey() []byte
}

// ECDSASigner signs with a secp256r1 (P-256) key.
type ECDSASigner struct{ Key *ecdsa.PrivateKey }

func (s ECDSASigner) signerCurve() Curve { return Secp256r1 }
func (s ECDSASigner) sign(d []byte) ([]byte, error) {
	return ecdsa.SignASN1(randReader, s.Key, d)
}
func (s ECDSASigner) publicKey() []byte {
	b, _ := s.Key.PublicKey.ECDH()
	if b == nil {
		return nil
	}
	return b.Bytes()
}

// SignerFor returns a signer for a station key on secp256r1 or secp256k1
// (a self-signed certificate).
func SignerFor(k *PrivateKey) (Signer, error) {
	switch k.curve {
	case Secp256k1:
		return k1Signer{k.k1}, nil
	case BrainpoolP256r1:
		return bpSigner{k.bp}, nil
	case Secp256r1:
		ek, err := ecdsaFromECDH(k)
		if err != nil {
			return nil, err
		}
		return ECDSASigner{ek}, nil
	}
	return nil, fmt.Errorf("iec60870sec: a %s key cannot sign", k.curve)
}

type bpSigner struct{ k *brainpool.PrivateKey }

func (s bpSigner) signerCurve() Curve            { return BrainpoolP256r1 }
func (s bpSigner) sign(d []byte) ([]byte, error) { return s.k.Sign(randReader, d, nil) }
func (s bpSigner) publicKey() []byte             { return nil }

type k1Signer struct{ k *secp256k1.PrivateKey }

func (s k1Signer) signerCurve() Curve { return Secp256k1 }
func (s k1Signer) sign(d []byte) ([]byte, error) {
	return k1ecdsa.Sign(s.k, d).Serialize(), nil
}
func (s k1Signer) publicKey() []byte { return s.k.PubKey().SerializeUncompressed() }

// CertTemplate describes a certificate for BuildCertificate.
type CertTemplate struct {
	Subject   pkix.Name
	Issuer    *Certificate // nil: self-signed
	NotBefore time.Time
	NotAfter  time.Time
	Serial    int64
	// Extensions are added as they are (for example the IEC 62351-8
	// IECUserRoles access token).
	Extensions []pkix.Extension
}

// BuildCertificate makes a DER certificate for a station public key signed
// by signer (for provisioning, simulators and tests).
func BuildCertificate(t CertTemplate, pub []byte, curve Curve, signer Signer) ([]byte, error) {
	var keyAlg algID
	switch curve {
	case Curve25519:
		keyAlg = algID{Algorithm: oidX25519}
	case Curve448:
		keyAlg = algID{Algorithm: oidX448}
	case Secp256r1, Secp256k1, BrainpoolP256r1:
		oid := oidP256
		if curve == Secp256k1 {
			oid = oidSecp256k1
		} else if curve == BrainpoolP256r1 {
			oid = oidBrainpoolP256r1
		}
		p, _ := asn1.Marshal(oid)
		keyAlg = algID{Algorithm: oidECPublicKey, Parameters: asn1.RawValue{FullBytes: p}}
	default:
		return nil, errors.New("iec60870sec: no curve")
	}
	subject, err := asn1.Marshal(t.Subject.ToRDNSequence())
	if err != nil {
		return nil, err
	}
	issuer := subject
	if t.Issuer != nil {
		issuer = t.Issuer.SubjectDN
	}
	type tbsOut struct {
		Version    int `asn1:"explicit,tag:0"`
		Serial     *big.Int
		Signature  algID
		Issuer     asn1.RawValue
		Validity   validity
		Subject    asn1.RawValue
		PublicKey  spki
		Extensions []pkix.Extension `asn1:"optional,explicit,tag:3"`
	}
	sigAlg := algID{Algorithm: oidECDSAWithSHA256}
	tbs := tbsOut{Version: 2, Serial: big.NewInt(max(t.Serial, 1)), Signature: sigAlg,
		Issuer: asn1.RawValue{FullBytes: issuer}, Validity: validity{t.NotBefore.UTC(), t.NotAfter.UTC()},
		Subject: asn1.RawValue{FullBytes: subject}, PublicKey: spki{Algorithm: keyAlg, PublicKey: asn1.BitString{Bytes: pub, BitLength: 8 * len(pub)}},
		Extensions: t.Extensions}
	tbsDER, err := asn1.Marshal(tbs)
	if err != nil {
		return nil, err
	}
	h := sha256.Sum256(tbsDER)
	sig, err := signer.sign(h[:])
	if err != nil {
		return nil, err
	}
	return asn1.Marshal(struct {
		TBS       asn1.RawValue
		Algorithm algID
		Signature asn1.BitString
	}{asn1.RawValue{FullBytes: tbsDER}, sigAlg, asn1.BitString{Bytes: sig, BitLength: 8 * len(sig)}})
}

// ParseCurve reads a curve name (secp256r1 when empty).
func ParseCurve(s string) (Curve, error) {
	switch strings.ToLower(s) {
	case "", "secp256r1", "p-256", "p256", "prime256v1":
		return Secp256r1, nil
	case "secp256k1":
		return Secp256k1, nil
	case "curve25519", "x25519":
		return Curve25519, nil
	case "curve448", "x448":
		return Curve448, nil
	case "brainpoolp256r1":
		return BrainpoolP256r1, nil
	}
	return CurveUnknown, fmt.Errorf("curve %q not supported (secp256r1, secp256k1, curve25519, curve448, brainpoolP256r1)", s)
}
