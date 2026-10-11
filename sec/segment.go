package sec

import (
	"bytes"
	"errors"
	"fmt"
)

// Params are the link's data unit identifier sizes (IEC 60870-5-101 7.1):
// cause of transmission 1 or 2 octets (the second is the originator address)
// and common address 1 or 2 octets. IEC 104 uses 2 and 2.
type Params struct {
	COTSize int
	CASize  int
}

// Params104 are the IEC 60870-5-104 sizes.
var Params104 = Params{COTSize: 2, CASize: 2}

func (p Params) validate() error {
	if p.COTSize != 1 && p.COTSize != 2 {
		return fmt.Errorf("iec60870sec: cause of transmission size %d, want 1 or 2", p.COTSize)
	}
	if p.CASize != 1 && p.CASize != 2 {
		return fmt.Errorf("iec60870sec: common address size %d, want 1 or 2", p.CASize)
	}
	return nil
}

// DUILen is the length of the data unit identifier.
func (p Params) DUILen() int { return 2 + p.COTSize + p.CASize }

// BroadcastCA is the broadcast common address for the CA size.
func (p Params) BroadcastCA() uint16 {
	if p.CASize == 1 {
		return defaultBroadcastCA1
	}
	return defaultBroadcastCA2
}

// DUI is a data unit identifier: type, variable structure qualifier, cause
// (6 bits) with the P/N and test bits, originator address and common address.
type DUI struct {
	Type       uint8
	VSQ        uint8
	Cause      uint8
	Negative   bool
	Test       bool
	Originator uint8
	CA         uint16
}

// Encode appends the DUI in the given sizes.
func (d DUI) Encode(p Params) []byte {
	b := make([]byte, 0, p.DUILen())
	cot := d.Cause & 0x3F
	if d.Negative {
		cot |= 0x40
	}
	if d.Test {
		cot |= 0x80
	}
	b = append(b, d.Type, d.VSQ, cot)
	if p.COTSize == 2 {
		b = append(b, d.Originator)
	}
	b = append(b, byte(d.CA))
	if p.CASize == 2 {
		b = append(b, byte(d.CA>>8))
	}
	return b
}

// ParseDUI reads the DUI at the start of b.
func ParseDUI(b []byte, p Params) (DUI, error) {
	if len(b) < p.DUILen() {
		return DUI{}, errShort
	}
	d := DUI{Type: b[0], VSQ: b[1], Cause: b[2] & 0x3F, Negative: b[2]&0x40 != 0, Test: b[2]&0x80 != 0}
	i := 3
	if p.COTSize == 2 {
		d.Originator = b[i]
		i++
	}
	d.CA = uint16(b[i])
	if p.CASize == 2 {
		d.CA |= uint16(b[i+1]) << 8
	}
	return d, nil
}

var errShort = errors.New("iec60870sec: ASDU too short")

// ASC is the ASDU segmentation control octet of 5.4.2.5 Figure 2: FIN in
// bit 8, FIR in bit 7, ASN (0 to 63) in bits 1 to 6.
type ASC struct {
	FIN, FIR bool
	ASN      uint8
}

// Byte encodes the ASC octet.
func (a ASC) Byte() byte {
	b := a.ASN & 0x3F
	if a.FIR {
		b |= 0x40
	}
	if a.FIN {
		b |= 0x80
	}
	return b
}

// ParseASC decodes the ASC octet.
func ParseASC(b byte) ASC { return ASC{FIN: b&0x80 != 0, FIR: b&0x40 != 0, ASN: b & 0x3F} }

// Segment splits a security ASDU held as DUI followed by its information
// object (no ASC; the form the MAC is computed over) into wire ASDUs of at
// most maxASDU octets, each the DUI, an ASC octet and a slice of the object
// (5.4.2.5, Figure 3). firstASN is the sequence number of the first
// segment; the next free number is returned.
func Segment(asdu []byte, p Params, maxASDU int, firstASN uint8) ([][]byte, uint8, error) {
	n := p.DUILen()
	if len(asdu) < n {
		return nil, firstASN, errShort
	}
	room := maxASDU - n - 1
	if room < 1 {
		return nil, firstASN, fmt.Errorf("iec60870sec: maximum ASDU length %d leaves no room for data", maxASDU)
	}
	dui, obj := asdu[:n], asdu[n:]
	asn := firstASN & 0x3F
	var out [][]byte
	for first := true; first || len(obj) > 0; first = false {
		k := min(room, len(obj))
		seg := make([]byte, 0, n+1+k)
		seg = append(seg, dui...)
		seg = append(seg, ASC{FIR: first, FIN: k == len(obj), ASN: asn}.Byte())
		seg = append(seg, obj[:k]...)
		out = append(out, seg)
		obj = obj[k:]
		asn = (asn + 1) & 0x3F
	}
	return out, asn, nil
}

// SegmentEvent says what the reassembler did with a segment; the values are
// the action numbers of Table 3 (1 to 11).
type SegmentEvent int

// Reassembler implements the ASDU segment reception state machine of
// 5.4.2.5 Table 3. It is not safe for concurrent use.
type Reassembler struct {
	p        Params
	assembly bool
	first    []byte // DUI of the first segment of the series
	prev     []byte // preceding segment, octet for octet
	asn      uint8
	buf      []byte
	// Discarded is called whenever a segment or series is discarded (the
	// Discarded Messages statistic, 5.4.2.5). A duplicate (row 4) is not
	// counted: it is dropped without discarding anything received.
	Discarded func()
}

// NewReassembler returns an idle reassembler for the DUI sizes.
func NewReassembler(p Params) *Reassembler { return &Reassembler{p: p} }

// Assembling reports whether a series is in progress.
func (r *Reassembler) Assembling() bool { return r.assembly }

// Reset drops any series in progress (link failure) without counting it.
func (r *Reassembler) Reset() { r.assembly, r.buf, r.prev, r.first = false, nil, nil, nil }

func (r *Reassembler) discard() {
	if r.Discarded != nil {
		r.Discarded()
	}
}

// Add feeds one received segment (DUI, ASC, data). When a series completes it
// returns the whole ASDU as DUI followed by the joined data. The event is the
// Table 3 row that applied.
func (r *Reassembler) Add(seg []byte) ([]byte, SegmentEvent, error) {
	n := r.p.DUILen()
	if len(seg) < n+1 {
		r.discard()
		return nil, 0, errShort
	}
	dui, asc, data := seg[:n], ParseASC(seg[n]), seg[n+1:]
	start := func() {
		r.first = append([]byte(nil), dui...)
		r.buf = append([]byte(nil), data...)
		r.prev = append([]byte(nil), seg...)
		r.asn = asc.ASN
	}
	complete := func() []byte {
		out := append(append([]byte(nil), r.first...), r.buf...)
		r.Reset()
		return out
	}
	if !r.assembly {
		switch {
		case !asc.FIR:
			r.discard()
			return nil, 1, nil
		case asc.FIN:
			start()
			return complete(), 2, nil
		default:
			start()
			r.assembly = true
			return nil, 3, nil
		}
	}
	if asc.FIR {
		// Rows 9 and 10: the series in progress is abandoned for the new one.
		r.discard()
		start()
		if asc.FIN {
			return complete(), 10, nil
		}
		return nil, 9, nil
	}
	if !bytes.Equal(dui, r.first) {
		r.discard()
		r.Reset()
		return nil, 11, nil
	}
	switch {
	case asc.ASN == r.asn:
		if bytes.Equal(seg, r.prev) {
			return nil, 4, nil
		}
		r.discard()
		r.Reset()
		return nil, 5, nil
	case asc.ASN == (r.asn+1)&0x3F:
		r.buf = append(r.buf, data...)
		r.prev = append(r.prev[:0], seg...)
		r.asn = asc.ASN
		if asc.FIN {
			return complete(), 7, nil
		}
		return nil, 6, nil
	default:
		r.discard()
		r.Reset()
		return nil, 8, nil
	}
}
