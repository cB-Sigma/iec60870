package sec

import (
	"encoding/binary"
	"errors"
	"fmt"
)

// ErrDataAuthentication is returned when a Secure Data MAC or AEAD tag does
// not verify.
var ErrDataAuthentication = errors.New("iec60870sec: secure data authentication failed")

// ProtectSecureData builds S_SD_NA_1 (5.4.3.13) around a plain IEC 101/104
// ASDU and returns the whole security ASDU (DUI and object, no ASC).
//
// With a MAC algorithm the MAC covers the DUI (TS 5.4.3.2, Figure 5), AIM,
// AIS, DSQ, ADL and the ASDU (IEC 62351-5:2023 Table 31) and follows the
// ASDU (Table 30). With AEAD-AES-256-GCM the DUI, AIM and AIS are the
// additional data (TS 5.4.3.13, Table 32), the nonce is DSQ padded to 12
// octets and ADL with the ASDU is encrypted; the payload is the AEAD output
// (8.5.2.2.6.3). ADL is the length of the ASDU (8.5.2.2.5).
func ProtectSecureData(d DUI, p Params, dir Direction, aim, ais uint16, dsq uint32, asdu []byte, dp DataProtection, key []byte) ([]byte, error) {
	if dsq == 0 {
		return nil, errors.New("iec60870sec: DSQ 0 is never sent (8.5.2.2.4 f)")
	}
	if len(asdu) == 0 {
		return nil, errors.New("iec60870sec: empty application data")
	}
	if len(asdu) > 0xFFFF {
		return nil, fmt.Errorf("iec60870sec: application data of %d octets", len(asdu))
	}
	d.Cause, d.Negative = CauseDataProtection, false
	sd := SecureData{AIM: aim, AIS: ais, DSQ: dsq}
	plain := binary.LittleEndian.AppendUint16(nil, uint16(len(asdu)))
	plain = append(plain, asdu...)
	switch {
	case dp.AEAD:
		g, err := newGCM(key)
		if err != nil {
			return nil, err
		}
		head, err := MACInput(d, p, SecureData{AIM: aim, AIS: ais})
		if err != nil {
			return nil, err
		}
		sd.Rest = g.Seal(nil, Nonce(dsq), plain, head[:len(head)-4])
	case dp.MAC != nil:
		sd.Rest = plain
		in, err := MACInput(d, p, sd)
		if err != nil {
			return nil, err
		}
		sd.Rest = append(plain, dp.MAC.Sum(key, in)...)
	default:
		return nil, errors.New("iec60870sec: no data protection algorithm")
	}
	return Encode(d, p, sd)
}

// OpenSecureData verifies (and with AEAD decrypts) a whole S_SD_NA_1 and
// returns the plain ASDU it carries with the decoded header.
func OpenSecureData(asdu []byte, p Params, dir Direction, dp DataProtection, key []byte) ([]byte, SecureData, error) {
	d, m, err := Decode(asdu, p, dir)
	if err != nil {
		return nil, SecureData{}, err
	}
	sd, ok := m.(SecureData)
	if !ok {
		return nil, SecureData{}, fmt.Errorf("iec60870sec: %s is not secure data", TypeName(d.Type))
	}
	var plain []byte
	switch {
	case dp.AEAD:
		g, err := newGCM(key)
		if err != nil {
			return nil, sd, err
		}
		aad := asdu[:p.DUILen()+4]
		if plain, err = g.Open(nil, Nonce(sd.DSQ), sd.Rest, aad); err != nil {
			return nil, sd, ErrDataAuthentication
		}
	case dp.MAC != nil:
		n := len(sd.Rest) - dp.MAC.Len
		if n < 2 {
			return nil, sd, ErrDataAuthentication
		}
		body, mac := sd.Rest[:n], sd.Rest[n:]
		if !dp.MAC.Verify(key, mac, asdu[:len(asdu)-dp.MAC.Len]) {
			return nil, sd, ErrDataAuthentication
		}
		plain = body
	default:
		return nil, sd, errors.New("iec60870sec: no data protection algorithm")
	}
	if len(plain) < 2 || int(binary.LittleEndian.Uint16(plain)) != len(plain)-2 {
		return nil, sd, fmt.Errorf("iec60870sec: application data length does not match ADL")
	}
	return plain[2:], sd, nil
}
