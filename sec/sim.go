package sec

import (
	"crypto/x509/pkix"
	"errors"
	"time"
)

// Identity is a station's key pair and self-signed certificate.
type Identity struct {
	Key         *PrivateKey
	Certificate []byte
}

// NewIdentity makes a key pair on a curve that can sign (secp256r1 or
// secp256k1) and a self-signed certificate valid for the given time, as
// IEC 62351-5:2023 8.3.2.3 describes (for commissioning, simulators and
// tests).
func NewIdentity(c Curve, name string, valid time.Duration) (Identity, error) {
	k, err := GenerateKey(c)
	if err != nil {
		return Identity{}, err
	}
	s, err := SignerFor(k)
	if err != nil {
		return Identity{}, err
	}
	now := time.Now()
	der, err := BuildCertificate(CertTemplate{Subject: pkix.Name{CommonName: name}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(valid)},
		k.PublicKey(), c, s)
	return Identity{Key: k, Certificate: der}, err
}

// Pin returns the Trust that admits this identity's self-signed certificate
// by its public key.
func (id Identity) Pin() Trust { return Trust{PublicKeys: [][]byte{id.Key.PublicKey()}} }

// Pair is a controlling and a controlled endpoint of one association wired
// back to back in memory, for tests of adapters and for demonstrations.
// Frames each side transmits are delivered to the other by Pump.
type Pair struct {
	Controlling, Controlled *Endpoint
}

// NewPair makes a pair on the link from two configurations (Link, Params,
// MaxASDU and the identities must already be set; Transmit is left unset
// so Pump can move the frames).
func NewPair(ctl, cld Config) (*Pair, error) {
	ctl.Controlling, cld.Controlling = true, false
	a, err := NewEndpoint(ctl)
	if err != nil {
		return nil, err
	}
	b, err := NewEndpoint(cld)
	if err != nil {
		return nil, err
	}
	return &Pair{Controlling: a, Controlled: b}, nil
}

// Pump moves the frames each side has queued to the other until neither has
// any, returning the data ASDUs each side received.
func (p *Pair) Pump() (toControlled, toControlling [][]byte) {
	for i := 0; i < 1000; i++ {
		a, b := p.Controlling.Outbox(), p.Controlled.Outbox()
		if len(a) == 0 && len(b) == 0 {
			return
		}
		for _, f := range a {
			if in, _ := p.Controlled.Receive(f); in.Kind == Data {
				toControlled = append(toControlled, in.ASDU)
			}
		}
		for _, f := range b {
			if in, _ := p.Controlling.Receive(f); in.Kind == Data {
				toControlling = append(toControlling, in.ASDU)
			}
		}
	}
	return
}

// Deliver feeds segments to an endpoint and returns the first completed
// result (or Pending when none completed).
func Deliver(to *Endpoint, segs [][]byte) (Inbound, error) {
	for _, s := range segs {
		in, err := to.Receive(s)
		if err != nil || in.Kind != Pending {
			return in, err
		}
	}
	if len(segs) == 0 {
		return Inbound{}, errors.New("iec60870sec: nothing to deliver")
	}
	return Inbound{Kind: Pending}, nil
}
