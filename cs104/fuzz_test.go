package cs104

import (
	"bytes"
	"testing"
	"time"

	"github.com/cB-Sigma/iec60870"
)

// Covers: SIG-IPE-141, SIG-IPE-630
func FuzzDecode(f *testing.F) {
	f.Add([]byte{13, 1, 3, 0, 1, 0, 1, 0, 0, 0x00, 0x00, 0xc0, 0x3f, 0x00}, uint8(0))
	f.Add([]byte{11, 0x83, 20, 0, 1, 0, 0xf4, 1, 0, 1, 0, 0, 2, 0, 0, 3, 0, 0}, uint8(1))
	f.Add([]byte{0x68, 4, 0x07, 0, 0, 0}, uint8(2))
	// CP24Time2a types: M_ME_TC_1, M_SP_TA_1 and a step position.
	f.Add([]byte{14, 1, 3, 0, 1, 0, 7, 0, 0, 0x00, 0x00, 0xc0, 0x3f, 0x00, 0x2a, 0x76, 0x0f}, uint8(0))
	f.Add([]byte{2, 1, 3, 1, 7, 0, 0x11, 0x10, 0x27, 0x85}, uint8(0))
	f.Add([]byte{6, 1, 3, 1, 7, 0, 0xc1, 0x80, 0x10, 0x27, 0x05}, uint8(0))
	f.Add([]byte{33, 1, 3, 0, 1, 0, 1, 0, 0, 0xef, 0xbe, 0xad, 0xde, 0, 0x2a, 0x76, 0x0f, 0x0a, 24, 9, 26}, uint8(0))
	f.Fuzz(func(t *testing.T, b []byte, sizes uint8) {
		p := iec60870.Params{COTSize: 1 + int(sizes&1), CASize: 1 + int(sizes>>1&1), IOASize: 1 + int(sizes>>2)%3}
		if a, err := iec60870.DecodeASDU(b, p, time.UTC); err == nil {
			if _, err := a.Encode(p, time.UTC); err != nil && len(a.Objects) > 0 {
				t.Errorf("decoded ASDU %s does not re-encode: %v", a, err)
			}
		}
		_, _ = ReadAPDU(bytes.NewReader(b))
	})
}
