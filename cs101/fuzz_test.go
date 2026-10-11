package cs101

import (
	"bytes"
	"testing"
)

// Covers: SIG-IPE-300
func FuzzReadFrame(f *testing.F) {
	for _, s := range [][]byte{{0x10, 0x49, 0x01, 0x4a, 0x16}, {0xe5}, {0x68, 0x03, 0x03, 0x68, 0x08, 0x01, 0x00, 0x09, 0x16}, {0x68, 0x00}} {
		f.Add(s, 1)
	}
	f.Fuzz(func(t *testing.T, b []byte, asize int) {
		asize = (asize%3 + 3) % 3
		r := bytes.NewReader(b)
		for i := 0; i < 64; i++ {
			fr, err := ReadFrame(r, asize)
			if err != nil {
				if r.Len() == 0 {
					return
				}
				continue
			}
			if back := fr.Encode(asize); !fr.Single && fr.ASDU != nil && len(fr.ASDU)+1+asize <= MaxUserData && len(back) < 6 {
				t.Fatalf("re-encoding %v gave %x", fr, back)
			}
		}
	})
}
