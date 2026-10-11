package sec

import (
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/subtle"
	"errors"
	"fmt"

	"github.com/cloudflare/circl/dh/x448"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"

	"github.com/cB-Sigma/iotcrypto/brainpool"
)

// Curve is an elliptic curve of IEC 62351-5:2023 8.3.2.2 Table 8 for the
// station's key pair. Curve25519 and Curve448 serve key agreement only;
// secp256k1 and secp256r1 also sign self-signed certificates.
type Curve int

// Curves of Table 8: the four mandatory ones and the optional
// brainpoolP256r1 (RFC 5639, 9.3.4).
const (
	CurveUnknown Curve = iota
	Curve25519
	Curve448
	Secp256k1
	Secp256r1
	BrainpoolP256r1
)

// String is the curve's name.
func (c Curve) String() string {
	return [...]string{"unknown", "Curve25519", "Curve448", "secp256k1", "secp256r1", "brainpoolP256r1"}[c]
}

// CanSign reports whether the curve can sign a certificate (8.3.2.2).
func (c Curve) CanSign() bool { return c == Secp256k1 || c == Secp256r1 || c == BrainpoolP256r1 }

// PrivateKey is a station's private key on one of the curves.
type PrivateKey struct {
	curve Curve
	nist  *ecdh.PrivateKey // X25519 or P-256
	k1    *secp256k1.PrivateKey
	x448  x448.Key
	bp    *brainpool.PrivateKey
}

// GenerateKey makes a fresh key pair on the curve.
func GenerateKey(c Curve) (*PrivateKey, error) {
	switch c {
	case Curve25519:
		k, err := ecdh.X25519().GenerateKey(rand.Reader)
		return &PrivateKey{curve: c, nist: k}, err
	case Secp256r1:
		k, err := ecdh.P256().GenerateKey(rand.Reader)
		return &PrivateKey{curve: c, nist: k}, err
	case Secp256k1:
		k, err := secp256k1.GeneratePrivateKey()
		return &PrivateKey{curve: c, k1: k}, err
	case Curve448:
		var k x448.Key
		if _, err := rand.Read(k[:]); err != nil {
			return nil, err
		}
		return &PrivateKey{curve: c, x448: k}, nil
	case BrainpoolP256r1:
		k, err := brainpool.GenerateKey(brainpool.P256r1(), rand.Reader)
		return &PrivateKey{curve: c, bp: k}, err
	}
	return nil, fmt.Errorf("iec60870sec: curve %s not supported", c)
}

// ParsePrivateKey reads a raw private key (the scalar: 32 octets, or 56 for
// Curve448).
func ParsePrivateKey(c Curve, raw []byte) (*PrivateKey, error) {
	switch c {
	case Curve25519:
		k, err := ecdh.X25519().NewPrivateKey(raw)
		return &PrivateKey{curve: c, nist: k}, err
	case Secp256r1:
		k, err := ecdh.P256().NewPrivateKey(raw)
		return &PrivateKey{curve: c, nist: k}, err
	case Secp256k1:
		if len(raw) != 32 {
			return nil, errors.New("iec60870sec: secp256k1 private key must be 32 octets")
		}
		return &PrivateKey{curve: c, k1: secp256k1.PrivKeyFromBytes(raw)}, nil
	case Curve448:
		if len(raw) != x448.Size {
			return nil, errors.New("iec60870sec: Curve448 private key must be 56 octets")
		}
		p := &PrivateKey{curve: c}
		copy(p.x448[:], raw)
		return p, nil
	case BrainpoolP256r1:
		k, err := brainpool.NewPrivateKey(brainpool.P256r1(), raw)
		return &PrivateKey{curve: c, bp: k}, err
	}
	return nil, fmt.Errorf("iec60870sec: curve %s not supported", c)
}

// Curve is the key's curve.
func (k *PrivateKey) Curve() Curve { return k.curve }

// Bytes is the raw private scalar (a secret: never log it).
func (k *PrivateKey) Bytes() []byte {
	switch k.curve {
	case Curve25519, Secp256r1:
		return k.nist.Bytes()
	case Secp256k1:
		return k.k1.Serialize()
	case BrainpoolP256r1:
		return k.bp.Bytes()
	default:
		return append([]byte(nil), k.x448[:]...)
	}
}

// PublicKey is the encoded public key as carried in a certificate's
// subjectPublicKey: 32 or 56 octets for the Montgomery curves, the 65-octet
// uncompressed point for the Weierstrass curves.
func (k *PrivateKey) PublicKey() []byte {
	switch k.curve {
	case Curve25519, Secp256r1:
		return k.nist.PublicKey().Bytes()
	case Secp256k1:
		return k.k1.PubKey().SerializeUncompressed()
	case BrainpoolP256r1:
		pub := k.bp.Public().(*ecdsa.PublicKey)
		out := make([]byte, 65)
		out[0] = 4
		pub.X.FillBytes(out[1:33])
		pub.Y.FillBytes(out[33:])
		return out
	default:
		var pub x448.Key
		x448.KeyGen(&pub, &k.x448)
		return pub[:]
	}
}

// ECDH is the shared secret with the remote public key: the IKM of
// IEC 62351-5:2023 8.3.10 step 2 (K of RFC 7748 for the Montgomery curves,
// the x coordinate for the Weierstrass curves).
func (k *PrivateKey) ECDH(remote []byte) ([]byte, error) {
	switch k.curve {
	case Curve25519:
		pub, err := ecdh.X25519().NewPublicKey(remote)
		if err != nil {
			return nil, err
		}
		return k.nist.ECDH(pub)
	case Secp256r1:
		pub, err := ecdh.P256().NewPublicKey(remote)
		if err != nil {
			return nil, err
		}
		return k.nist.ECDH(pub)
	case Secp256k1:
		pub, err := secp256k1.ParsePubKey(remote)
		if err != nil {
			return nil, err
		}
		return secp256k1.GenerateSharedSecret(k.k1, pub), nil
	case BrainpoolP256r1:
		return brainpool.ECDH(brainpool.P256r1(), k.bp.Bytes(), remote)
	case Curve448:
		if len(remote) != x448.Size {
			return nil, errors.New("iec60870sec: Curve448 public key must be 56 octets")
		}
		var pub, shared x448.Key
		copy(pub[:], remote)
		if !x448.Shared(&shared, &k.x448, &pub) {
			return nil, errors.New("iec60870sec: Curve448 shared secret is zero")
		}
		return shared[:], nil
	}
	return nil, fmt.Errorf("iec60870sec: curve %s not supported", k.curve)
}

// UpdateKeys are the Encryption and Authentication Update Keys of one
// association (IEC 62351-5:2023 6.2.6.3, 8.3.10), 32 octets each.
type UpdateKeys struct {
	Encryption     []byte
	Authentication []byte
}

// DeriveUpdateKeys is IEC 62351-5:2023 8.3.10: HKDF-Extract with the salt
// made of the controlling then the controlled station's random data and the
// ECDH secret as IKM, then HKDF-Expand with an empty info to 64 octets; the
// first 32 are the Encryption Update Key, the last 32 the Authentication
// Update Key. The hash is the one of the MAC algorithm selected in the
// Update Key Change Request (TS 60870-5-7 5.3.3).
func DeriveUpdateKeys(mal MACAlgorithm, ikm, controllingRandom, controlledRandom []byte) (UpdateKeys, error) {
	if mal.Hash == nil {
		return UpdateKeys{}, errors.New("iec60870sec: MAC algorithm has no hash for HKDF")
	}
	salt := append(append([]byte(nil), controllingRandom...), controlledRandom...)
	t, err := mal.DeriveKeys(ikm, salt, "", 64)
	if err != nil {
		return UpdateKeys{}, err
	}
	return UpdateKeys{Encryption: t[:32], Authentication: t[32:]}, nil
}

// Equal compares two key sets in constant time.
func (u UpdateKeys) Equal(o UpdateKeys) bool {
	return subtle.ConstantTimeCompare(u.Encryption, o.Encryption)&subtle.ConstantTimeCompare(u.Authentication, o.Authentication) == 1
}

// Valid reports whether both keys are present with 256 bits (9.2.4.3).
func (u UpdateKeys) Valid() bool { return len(u.Encryption) == 32 && len(u.Authentication) == 32 }
