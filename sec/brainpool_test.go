package sec

import (
	"bytes"
	"testing"
	"time"
)

// Covers: SIG-IPE-1730
func TestBrainpoolP256r1ECDH(t *testing.T) {
	// RFC 7027 A.1 (brainpoolP256r1 key agreement).
	a, err := ParsePrivateKey(BrainpoolP256r1, unhex(t, "81DB1EE100150FF2EA338D708271BE38300CB54241D79950F77B063039804F1D"))
	if err != nil {
		t.Fatal(err)
	}
	wantA := unhex(t, "04"+"44106E913F92BC02A1705D9953A8414DB95E1AAA49E81D9E85F929A8E3100BE5"+"8AB4846F11CACCB73CE49CBDD120F5A900A69FD32C272223F789EF10EB089BDC")
	if !bytes.Equal(a.PublicKey(), wantA) {
		t.Errorf("public key %x", a.PublicKey())
	}
	qB := unhex(t, "04"+"8D2D688C6CF93E1160AD04CC4429117DC2C41825E1E9FCA0ADDD34E6F1B39F7B"+"990C57520812BE512641E47034832106BC7D3E8DD0E4C7F1136D7006547CEC6A")
	z, err := a.ECDH(qB)
	if err != nil || !bytes.Equal(z, unhex(t, "89AFC39D41D3B327814B80940B042590F96556EC91E6AE7939BCE31F3A18BF2B")) {
		t.Errorf("shared secret %x %v", z, err)
	}
	if _, err := a.ECDH(append([]byte{4}, make([]byte, 64)...)); err == nil {
		t.Error("point not on the curve accepted")
	}
	if c, err := ParseCurve("brainpoolP256r1"); err != nil || c != BrainpoolP256r1 {
		t.Error("curve name")
	}
}

// Covers: SIG-IPE-1731
func TestBrainpoolP256r1CertificateAndAssociation(t *testing.T) {
	id, err := NewIdentity(BrainpoolP256r1, "rtu-bp", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	c, err := VerifyRemote(id.Certificate, BrainpoolP256r1, id.Pin(), time.Now(), false)
	if err != nil || c.Curve != BrainpoolP256r1 {
		t.Fatalf("self-signed brainpoolP256r1 certificate: %v", err)
	}
	bad := bytes.Clone(id.Certificate)
	bad[len(bad)-3] ^= 1
	if _, err := VerifyRemote(bad, BrainpoolP256r1, id.Pin(), time.Now(), false); err == nil {
		t.Error("bad signature accepted")
	}
	if _, err := VerifyRemote(id.Certificate, Secp256r1, id.Pin(), time.Now(), false); err == nil {
		t.Error("curve mismatch accepted")
	}
	pr, _ := newTestPair(t, pairOpts{link: TCP, curve: BrainpoolP256r1})
	connect(t, pr)
	if !pr.Controlling.KeysValid() || !pr.Controlled.KeysValid() || !pr.Controlling.st.equalKeys(pr.Controlled.st) {
		t.Fatal("association on brainpoolP256r1 failed")
	}
}
