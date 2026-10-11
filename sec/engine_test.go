package sec

import (
	"bytes"
	"encoding/binary"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/cB-Sigma/iotsec"
)

type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *clock) add(d time.Duration) time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
	return c.t
}

type pairOpts struct {
	link         Link
	curve        Curve
	mal, dpa     uint8
	maxASDU      int
	ctlStore     KeyStore
	cldStore     KeyStore
	acceptDPA    []uint8
	acceptMAL    []uint8
	settingsCtl  *Settings
	settingsCld  *Settings
	broadcast    *BroadcastSender
	pri          *ProtocolInfo
	ctlID, cldID *Identity
	ctlTrust     *Trust
	cldTrust     *Trust
	cldRBAC      iotsec.CertificateRoleAuthority
	cldRoles     []Role
	cldRevoked   func(*Certificate) bool
}

func newTestPair(t *testing.T, o pairOpts) (*Pair, *clock) {
	t.Helper()
	if o.curve == CurveUnknown {
		o.curve = Secp256r1
	}
	ck := &clock{t: time.Now()}
	if o.ctlID == nil {
		id, err := NewIdentity(o.curve, "scada", 24*time.Hour)
		if err != nil {
			t.Fatal(err)
		}
		o.ctlID = &id
	}
	if o.cldID == nil {
		id, err := NewIdentity(o.curve, "rtu", 24*time.Hour)
		if err != nil {
			t.Fatal(err)
		}
		o.cldID = &id
	}
	p := Params104
	if o.link == Serial {
		p = Params{COTSize: 1, CASize: 1}
	}
	if o.maxASDU == 0 {
		o.maxASDU = 249
	}
	ctlTrust := o.cldID.Pin()
	if o.ctlTrust != nil {
		ctlTrust = *o.ctlTrust
	}
	ctl := Config{Link: o.link, Params: p, MaxASDU: o.maxASDU, CA: 3, AIM: 11, Key: o.ctlID.Key, Certificate: o.ctlID.Certificate,
		Trust: ctlTrust, MAL: o.mal, DPA: o.dpa, Store: o.ctlStore, Now: ck.now, BroadcastSender: o.broadcast}
	cld := Config{Link: o.link, Params: p, MaxASDU: o.maxASDU, CA: 3, AIS: 22, Key: o.cldID.Key, Certificate: o.cldID.Certificate,
		Trust: o.ctlID.Pin(), Store: o.cldStore, Now: ck.now, AcceptDPA: o.acceptDPA, AcceptMAL: o.acceptMAL, Broadcast: o.broadcast != nil}
	if o.settingsCtl != nil {
		ctl.Settings = *o.settingsCtl
	}
	if o.settingsCld != nil {
		cld.Settings = *o.settingsCld
	}
	if o.cldTrust != nil {
		cld.Trust = *o.cldTrust
	}
	cld.Revoked = o.cldRevoked
	cld.RBAC, cld.Roles = o.cldRBAC, o.cldRoles
	pr, err := NewPair(ctl, cld)
	if err != nil {
		t.Fatal(err)
	}
	return pr, ck
}

func connect(t *testing.T, pr *Pair) {
	t.Helper()
	for _, e := range []*Endpoint{pr.Controlling, pr.Controlled} {
		if err := e.Start(); err != nil {
			t.Fatal(err)
		}
	}
	pr.Controlled.LinkUp()
	pr.Controlling.LinkUp()
	pr.Pump()
}

func cmdASDU(p Params, v byte) []byte {
	return append(DUI{Type: 45, VSQ: 1, Cause: 6, CA: 3}.Encode(p), 1, 0, 0, v)
}

func indASDU(p Params, v byte) []byte {
	return append(DUI{Type: 1, VSQ: 1, Cause: 3, CA: 3}.Encode(p), 1, 0, 0, v)
}

// Covers: SIG-IPE-1705
// Covers: SIG-IPE-1706
// Covers: SIG-IPE-1707
func TestAssociationAndSessionKeyChange(t *testing.T) {
	for _, c := range []struct {
		name  string
		link  Link
		curve Curve
		mal   uint8
		dpa   uint8
		max   int
	}{
		{"104 P-256 HMAC-SHA-256", TCP, Secp256r1, 4, 4, 249},
		{"104 secp256k1 AES-GCM", TCP, Secp256k1, 4, 11, 249},
		{"104 SHA3", TCP, Secp256r1, 8, 8, 249},
		{"104 BLAKE2s", TCP, Secp256k1, 10, 10, 249},
		{"101 P-256 segmented", Serial, Secp256r1, 3, 3, 40},
		{"101 AEAD segmented", Serial, Secp256k1, 7, 11, 24},
	} {
		t.Run(c.name, func(t *testing.T) {
			pr, _ := newTestPair(t, pairOpts{link: c.link, curve: c.curve, mal: c.mal, dpa: c.dpa, maxASDU: c.max})
			connect(t, pr)
			for _, e := range []*Endpoint{pr.Controlling, pr.Controlled} {
				st := e.Status()
				if !st.UpdateKeysValid || !st.SessionKeysValid || st.AIM != 11 || st.AIS != 22 {
					t.Fatalf("status %+v", st)
				}
			}
			if !pr.Controlling.st.equalKeys(pr.Controlled.st) {
				t.Fatal("stations disagree on keys")
			}
			for _, e := range []*Endpoint{pr.Controlling, pr.Controlled} {
				s := e.Stats()
				if s.Get(StatSuccessfulAssociations) != 1 || s.Get(StatSuccessfulSessionKeyChanges) != 1 || s.Get(StatDiscardedMessages) != 0 {
					t.Errorf("stats %v", s.Snapshot())
				}
			}
			p := pr.Controlling.cfg.Params
			segs, err := pr.Controlling.Wrap(cmdASDU(p, 0x81))
			if err != nil || len(segs) == 0 {
				t.Fatalf("wrap %v", err)
			}
			for _, s := range segs {
				if len(s) > c.max {
					t.Fatalf("segment of %d octets", len(s))
				}
			}
			in, err := Deliver(pr.Controlled, segs)
			if err != nil || in.Kind != Data || !bytes.Equal(in.ASDU, cmdASDU(p, 0x81)) {
				t.Fatalf("command: %+v %v", in, err)
			}
			up, _ := pr.Controlled.Wrap(indASDU(p, 1))
			in, err = Deliver(pr.Controlling, up)
			if err != nil || in.Kind != Data || !bytes.Equal(in.ASDU, indASDU(p, 1)) {
				t.Fatalf("indication: %+v %v", in, err)
			}
			// A replay is refused (DSQ lower than expected).
			if in, err := Deliver(pr.Controlling, up); !errors.Is(err, ErrReplay) || in.Kind != Discarded {
				t.Errorf("replay: %v", err)
			}
			// A changed octet fails authentication.
			segs, _ = pr.Controlling.Wrap(cmdASDU(p, 0x80))
			last := bytes.Clone(segs[len(segs)-1])
			last[len(last)-1] ^= 1
			segs[len(segs)-1] = last
			if _, err := Deliver(pr.Controlled, segs); !errors.Is(err, ErrDataAuthentication) {
				t.Errorf("tamper: %v", err)
			}
			if pr.Controlled.Stats().Get(StatDataAuthenticationErrors) != 1 {
				t.Error("data authentication error not counted")
			}
		})
	}
}

func (s State) equalKeys(o State) bool {
	return bytes.Equal(s.Encryption, o.Encryption) && bytes.Equal(s.Authentication, o.Authentication) &&
		bytes.Equal(s.Control, o.Control) && bytes.Equal(s.Monitor, o.Monitor) && s.AIM == o.AIM && s.AIS == o.AIS
}

// capture runs the association with a recorder between the stations and
// returns every whole security ASDU exchanged, in order.
func capture(t *testing.T, pr *Pair) [][]byte {
	t.Helper()
	var all [][]byte
	r := NewReassembler(pr.Controlling.cfg.Params)
	for _, e := range []*Endpoint{pr.Controlling, pr.Controlled} {
		_ = e.Start()
	}
	pr.Controlled.LinkUp()
	pr.Controlling.LinkUp()
	for i := 0; i < 50; i++ {
		a, b := pr.Controlling.Outbox(), pr.Controlled.Outbox()
		if len(a)+len(b) == 0 {
			break
		}
		for _, f := range a {
			if w, _, _ := r.Add(f); w != nil {
				all = append(all, w)
			}
			pr.Controlled.Receive(f)
		}
		for _, f := range b {
			if w, _, _ := r.Add(f); w != nil {
				all = append(all, w)
			}
			pr.Controlling.Receive(f)
		}
	}
	return all
}

// Covers: SIG-IPE-1708
func TestMACInputsOfTheTables(t *testing.T) {
	pr, _ := newTestPair(t, pairOpts{link: TCP})
	msgs := capture(t, pr)
	if len(msgs) != 8 {
		t.Fatalf("%d messages, want AQ AP UH UP SQ SP KH KP", len(msgs))
	}
	want := []uint8{SAQNA1, SAPNA1, SUHNA1, SUPNA1, SSQNA1, SSPNA1, SKHNA1, SKPNA1}
	dec := make([]Message, 8)
	for i, m := range msgs {
		if m[0] != want[i] {
			t.Fatalf("message %d is type %d, want %d", i, m[0], want[i])
		}
		dir := Control
		if i%2 == 1 {
			dir = Monitor
		}
		_, dm, err := Decode(m, Params104, dir)
		if err != nil {
			t.Fatal(err)
		}
		dec[i] = dm
	}
	ap, uh, up := dec[1].(AssociationResponse), dec[2].(UpdateKeyChangeRequest), dec[3].(UpdateKeyChangeResponse)
	sp, kh, kp := dec[5].(SessionResponse), dec[6].(SessionKeyChangeRequest), dec[7].(SessionKeyChangeResponse)
	aq := dec[0].(AssociationRequest)
	if aq.AIS != 0 || aq.AIM != 11 || !bytes.Equal(aq.CertData, pr.Controlling.cfg.Certificate) || ap.AIS != 22 {
		t.Error("association IDs")
	}
	if uh.MAL != 4 || uh.KWA != 2 || kh.DPA != 4 || len(kh.Wrapped) != 72 {
		t.Errorf("algorithms MAL %d KWA %d DPA %d WKL %d", uh.MAL, uh.KWA, kh.DPA, len(kh.Wrapped))
	}
	auth := pr.Controlled.st.Authentication
	mac := HMACSHA256TCP
	cut := func(m []byte, n int) []byte { return m[:len(m)-n] }
	// Table 12: controlled station random data, then the request up to CGD.
	if !mac.Verify(auth, uh.MAC, ap.Random, cut(msgs[2], 16)) {
		t.Error("Table 12")
	}
	// Table 14: the whole request, then the response up to AIS.
	if !mac.Verify(auth, up.MAC, msgs[2], cut(msgs[3], 16)) {
		t.Error("Table 14")
	}
	// Table 20: the whole Session Request, then the response up to CGD.
	if !mac.Verify(auth, sp.MAC, msgs[4], cut(msgs[5], 16)) {
		t.Error("Table 20")
	}
	// Table 24: controlled random of the Session Response, then the request up to WKD.
	if !mac.Verify(auth, kh.MAC, sp.Random, cut(msgs[6], 16)) {
		t.Error("Table 24")
	}
	// Table 26: the whole Session Key Change Request, then the response up to AIS.
	if !mac.Verify(auth, kp.MAC, msgs[6], cut(msgs[7], 16)) {
		t.Error("Table 26")
	}
	// Table 22: WKD wraps the control then the monitor direction key with the
	// Encryption Update Key (RFC 3394).
	plain, err := AESKeyUnwrap(pr.Controlled.st.Encryption, kh.Wrapped)
	if err != nil || !bytes.Equal(plain[:32], pr.Controlling.st.Control) || !bytes.Equal(plain[32:], pr.Controlling.st.Monitor) {
		t.Error("Table 22")
	}
	// 8.3.10 with the controlling then the controlled random as salt.
	ikm, _ := pr.Controlling.cfg.Key.ECDH(pr.Controlled.cfg.Key.PublicKey())
	uk, _ := DeriveUpdateKeys(mac, ikm, uh.Random, ap.Random)
	if !bytes.Equal(uk.Authentication, auth) || !bytes.Equal(uk.Encryption, pr.Controlled.st.Encryption) {
		t.Error("8.3.10 derivation")
	}
	// DSQ starts at 1 in each direction after the change (8.5.2.2.4 b).
	segs, _ := pr.Controlling.Wrap(cmdASDU(Params104, 1))
	if dsq := binary.LittleEndian.Uint32(segs[0][11:]); dsq != 1 {
		t.Errorf("first DSQ %d", dsq)
	}
}

// Covers: SIG-IPE-1709
func TestReplyTimeoutsAndMaxReplyTimeouts(t *testing.T) {
	pr, ck := newTestPair(t, pairOpts{link: TCP})
	ctl := pr.Controlling
	ctl.LinkUp()
	first := ctl.Outbox()
	if len(first) == 0 || first[0][0] != SAQNA1 {
		t.Fatal("no association request")
	}
	// Two reply timeouts retransmit, the third reaches Max Reply Timeouts (3).
	for i := 1; i <= 2; i++ {
		ctl.Tick(ck.add(2 * time.Second))
		o := ctl.Outbox()
		if len(o) != len(first) || !bytes.Equal(o[0][7:], first[0][7:]) {
			t.Fatalf("timeout %d: %d frames", i, len(o))
		}
	}
	ctl.Tick(ck.add(2 * time.Second))
	s := ctl.Stats()
	if s.Get(StatReplyTimeouts) != 3 || s.Get(StatMaxReplyTimeouts) != 1 || s.Get(StatAssociationFailures) != 1 || ctl.Status().State != "Key Management Idle" {
		t.Errorf("after max: %v %s", s.Snapshot(), ctl.Status().State)
	}
	// 8.3.11: a failed association is not retried automatically.
	ctl.Tick(ck.add(10 * time.Second))
	if len(ctl.Outbox()) != 0 {
		t.Error("association retried automatically")
	}
	// The moving threshold was reset: three more timeouts are needed.
	_ = ctl.StartAssociation()
	ctl.Outbox()
	ctl.Tick(ck.add(2 * time.Second))
	if ctl.Stats().Get(StatMaxReplyTimeouts) != 1 {
		t.Error("threshold not moved")
	}
}

// Covers: SIG-IPE-1710
func TestControlledRequestTimeoutAndRetransmission(t *testing.T) {
	pr, ck := newTestPair(t, pairOpts{link: TCP})
	ctl, cld := pr.Controlling, pr.Controlled
	cld.LinkUp()
	ctl.LinkUp()
	aq := ctl.Outbox()
	Deliver(cld, aq)
	ap := cld.Outbox()
	// The same request again: the same response (same random data).
	Deliver(cld, aq)
	ap2 := cld.Outbox()
	if len(ap) != len(ap2) || !bytes.Equal(ap[len(ap)-1][7:], ap2[len(ap2)-1][7:]) {
		t.Error("association response not repeated with the same random data")
	}
	// The Request Timer (Expected Request Time) runs out.
	cld.Tick(ck.add(7 * time.Second))
	if cld.Stats().Get(StatRequestTimeouts) != 1 || cld.Stats().Get(StatAssociationFailures) != 1 {
		t.Errorf("request timeout %v", cld.Stats().Snapshot())
	}
	// The controlling station's late Update Key Change Request is unexpected.
	Deliver(ctl, ap)
	uh := ctl.Outbox()
	Deliver(cld, uh)
	if cld.Stats().Get(StatUnexpectedMessages) != 1 {
		t.Error("late request not unexpected")
	}
}

// Covers: SIG-IPE-1711
func TestProtocolAndAlgorithmRefusals(t *testing.T) {
	// The controlled station accepts only HMAC-SHA-256/16 for MAL.
	pr, _ := newTestPair(t, pairOpts{link: TCP, mal: 8, acceptMAL: []uint8{4}})
	connect(t, pr)
	if pr.Controlled.Stats().Get(StatKeyAuthAlgorithmSupportFailures) != 1 || pr.Controlled.UpdateKeysValid() {
		t.Errorf("MAL refusal %v", pr.Controlled.Stats().Snapshot())
	}
	// The controlled station accepts only MAC data protection.
	pr, _ = newTestPair(t, pairOpts{link: TCP, dpa: 11, acceptDPA: []uint8{4}})
	connect(t, pr)
	if pr.Controlled.Stats().Get(StatDataProtectionAlgorithmSupportFailures) != 1 || pr.Controlled.KeysValid() || !pr.Controlled.UpdateKeysValid() {
		t.Errorf("DPA refusal %v", pr.Controlled.Stats().Snapshot())
	}
	// A protocol version other than 1.0 counts a Protocol Information Error.
	pr, _ = newTestPair(t, pairOpts{link: TCP})
	aq, _ := Encode(DUI{Cause: 16, CA: 3}, Params104, AssociationRequest{AIM: 11, PRI: ProtocolInfo{Major: 2}, CertData: pr.Controlling.cfg.Certificate})
	pr.Controlled.LinkUp()
	segs, _, _ := Segment(aq, Params104, 249, 0)
	if in, _ := Deliver(pr.Controlled, segs); in.Kind != Discarded || pr.Controlled.Stats().Get(StatProtocolInformationErrors) != 1 {
		t.Error("protocol information error")
	}
	// An unknown station's certificate: not authorized.
	stranger, _ := NewIdentity(Secp256r1, "stranger", time.Hour)
	aq, _ = Encode(DUI{Cause: 16, CA: 3}, Params104, AssociationRequest{AIM: 11, PRI: ConformingPRI, CertData: stranger.Certificate})
	segs, _, _ = Segment(aq, Params104, 249, 10)
	Deliver(pr.Controlled, segs)
	if pr.Controlled.Stats().Get(StatRemoteAuthorizationFailures) != 1 {
		t.Error("stranger not refused")
	}
	// A tampered Update Key Change Request is a key authentication error.
	pr, _ = newTestPair(t, pairOpts{link: TCP})
	pr.Controlled.LinkUp()
	pr.Controlling.LinkUp()
	Deliver(pr.Controlled, pr.Controlling.Outbox())
	Deliver(pr.Controlling, pr.Controlled.Outbox())
	uhs := pr.Controlling.Outbox()
	uh := uhs[len(uhs)-1]
	uh[len(uh)-1] ^= 1
	Deliver(pr.Controlled, uhs)
	if pr.Controlled.Stats().Get(StatKeyAuthenticationErrors) != 1 || pr.Controlled.UpdateKeysValid() {
		t.Error("tampered update key change request")
	}
}

// Covers: SIG-IPE-1712
func TestSecureDataDuringSessionKeyChange(t *testing.T) {
	pr, ck := newTestPair(t, pairOpts{link: TCP})
	connect(t, pr)
	ctl, cld := pr.Controlling, pr.Controlled
	p := Params104
	// Controlling station starts a change; during Wait for Session Response
	// it may still send (8.5.5.3).
	_ = ctl.StartSessionKeyChange()
	sq := ctl.Outbox()
	if segs, err := ctl.Wrap(cmdASDU(p, 1)); err != nil || segs == nil {
		t.Fatalf("send during Wait for Session Response: %v", err)
	}
	for _, f := range sq {
		cld.Receive(f)
	}
	sp := cld.Outbox()
	for _, f := range sp {
		ctl.Receive(f)
	}
	kh := ctl.Outbox()
	// Wait for Session Key Change Response: transmission suspended, queued.
	if segs, err := ctl.Wrap(cmdASDU(p, 2)); err != nil || segs != nil {
		t.Fatalf("not suspended: %v %d", err, len(segs))
	}
	if ctl.Status().Queued != 1 {
		t.Error("not queued")
	}
	// Old keys still accepted from the controlled station meanwhile.
	up, _ := cld.Wrap(indASDU(p, 5))
	if in, err := Deliver(ctl, up); err != nil || in.Kind != Data {
		t.Errorf("old keys refused during the change: %v", err)
	}
	for _, f := range kh {
		cld.Receive(f)
	}
	for _, f := range cld.Outbox() {
		ctl.Receive(f)
	}
	// The queued command goes out with the new keys and DSQ 1.
	q := ctl.Outbox()
	if len(q) != 1 || binary.LittleEndian.Uint32(q[0][11:]) != 1 {
		t.Fatalf("queued frames %d", len(q))
	}
	if in, err := Deliver(cld, q); err != nil || !bytes.Equal(in.ASDU, cmdASDU(p, 2)) {
		t.Errorf("queued command: %v", err)
	}
	_ = ck
}

// Covers: SIG-IPE-1713
func TestSessionKeyUsageLimits(t *testing.T) {
	sc := DefaultSettings(true)
	sc.MaxSessionKeyUsageCount = 4
	sd := DefaultSettings(false)
	sd.MaxSessionKeyUsageCount = 8
	pr, ck := newTestPair(t, pairOpts{link: TCP, settingsCtl: &sc, settingsCld: &sd})
	connect(t, pr)
	ctl, cld := pr.Controlling, pr.Controlled
	p := Params104
	for i := 0; i < 2; i++ {
		s, _ := ctl.Wrap(cmdASDU(p, byte(i)))
		Deliver(cld, s)
		u, _ := cld.Wrap(indASDU(p, byte(i)))
		Deliver(ctl, u)
	}
	// Counted in both directions (8.5.5.1): 4 reached, the controlling station changes keys.
	old := bytes.Clone(ctl.st.Control)
	ctl.Tick(ck.add(time.Second))
	pr.Pump()
	if bytes.Equal(old, ctl.st.Control) || ctl.Stats().Get(StatSuccessfulSessionKeyChanges) != 2 {
		t.Error("count limit did not change keys")
	}
	// Max Session Key Usage Time at the controlled station (default 30 min)
	// invalidates its keys when the controlling station did not change them.
	ck.add(31 * time.Minute)
	cld.Tick(ck.now())
	if cld.KeysValid() || cld.Stats().Get(StatKeyInvalidationsTime) != 1 {
		t.Error("usage time at the controlled station")
	}
}

// Covers: SIG-IPE-1714
// Covers: SIG-IPE-1419
// Covers: SIG-IPE-1420
// Covers: SIG-IPE-1421
func TestRestartAndSessionInitiation(t *testing.T) {
	ctlStore, cldStore := &MemoryKeyStore{}, &MemoryKeyStore{}
	ctlID, _ := NewIdentity(Secp256r1, "scada", time.Hour)
	cldID, _ := NewIdentity(Secp256r1, "rtu", time.Hour)
	o := pairOpts{link: TCP, ctlStore: ctlStore, cldStore: cldStore, ctlID: &ctlID, cldID: &cldID}
	pr, _ := newTestPair(t, o)
	connect(t, pr)
	st, _, _ := cldStore.Load()
	if !pr.Controlling.KeysValid() || len(st.Authentication) != 32 || len(st.Control) != 32 {
		t.Fatal("state not stored")
	}
	// The controlled station restarts: stored keys come back invalid and it
	// asks for new session keys with a Session Initiation Request (TS 5.3.4.3.2).
	cld2, err := NewEndpoint(pr.Controlled.cfg)
	if err != nil {
		t.Fatal(err)
	}
	_ = cld2.Start()
	if !cld2.UpdateKeysValid() || cld2.KeysValid() {
		t.Fatal("restart state")
	}
	cld2.LinkUp()
	si := cld2.Outbox()
	if len(si) != 1 || si[0][0] != SSINA1 {
		t.Fatalf("no session initiation request: %d", len(si))
	}
	// TS Table 4: both session keys, then the message up to CGD.
	_, m, _ := Decode(append(bytes.Clone(si[0][:6]), si[0][7:]...), Params104, Monitor)
	sir := m.(SessionInitiationRequest)
	in := append(append(bytes.Clone(st.Control), st.Monitor...), append(bytes.Clone(si[0][:6]), si[0][7:len(si[0])-16]...)...)
	if !HMACSHA256TCP.Verify(st.Authentication, sir.MAC, in) {
		t.Error("TS Table 4 MAC")
	}
	pr2 := &Pair{Controlling: pr.Controlling, Controlled: cld2}
	for _, f := range si {
		pr.Controlling.Receive(f)
	}
	pr2.Pump()
	if !cld2.KeysValid() || !pr.Controlling.KeysValid() || pr.Controlling.Stats().Get(StatSuccessfulSessionKeyChanges) != 2 {
		t.Fatalf("solicited change failed: %v / %v", pr.Controlling.Stats().Snapshot(), cld2.Stats().Snapshot())
	}
	p := Params104
	s, _ := pr.Controlling.Wrap(cmdASDU(p, 9))
	if in, err := Deliver(cld2, s); err != nil || in.Kind != Data {
		t.Errorf("after restart: %v", err)
	}
	// The controlling station restarts: association kept, session keys
	// changed at once on LinkUp (8.4.5).
	ctl2, _ := NewEndpoint(pr.Controlling.cfg)
	_ = ctl2.Start()
	if !ctl2.UpdateKeysValid() || ctl2.KeysValid() {
		t.Fatal("controlling restart state")
	}
	pr3 := &Pair{Controlling: ctl2, Controlled: cld2}
	ctl2.LinkUp()
	pr3.Pump()
	if !ctl2.KeysValid() || ctl2.Stats().Get(StatSuccessfulAssociations) != 0 {
		t.Errorf("controlling restart: %v", ctl2.Stats().Snapshot())
	}
	// A Session Initiation Request while a change runs is unexpected; a bad
	// MAC is a key authentication error (TS 5.3.4.3.3).
	_ = ctl2.StartSessionKeyChange()
	ctl2.Outbox()
	cld2.InvalidateForTest()
	cld2.Tick(time.Now())
	si = cld2.Outbox()
	if len(si) == 0 {
		t.Fatal("no session initiation request")
	}
	ctl2.Receive(si[0])
	if ctl2.Stats().Get(StatUnexpectedMessages) != 1 {
		t.Error("SI during a change not unexpected")
	}
}

// InvalidateForTest marks the session keys invalid (as the usage limits do).
func (e *Endpoint) InvalidateForTest() {
	e.mu.Lock()
	e.sessionValid, e.siPending = false, false
	e.mu.Unlock()
}

// Covers: SIG-IPE-1715
// Covers: SIG-IPE-1422
func TestBroadcastSessionKeyEndToEnd(t *testing.T) {
	bs := &BroadcastSender{}
	k0 := bytes.Repeat([]byte{0xB0}, 32)
	if _, err := bs.Begin(k0, []uint16{3}); err != nil {
		t.Fatal(err)
	}
	pr, _ := newTestPair(t, pairOpts{link: Serial, broadcast: bs, maxASDU: 60})
	connect(t, pr)
	pr.Pump()
	if bs.Distributing() || len(pr.Controlled.BroadcastReceiver().Keys()) != 1 {
		t.Fatalf("broadcast key not distributed: %v", pr.Controlling.Stats().Snapshot())
	}
	p := Params{COTSize: 1, CASize: 1}
	bc := append(DUI{Type: 103, VSQ: 1, Cause: 6, CA: 0xFF}.Encode(p), 0, 0, 1, 2, 3, 4, 5, 6, 7)
	segs, err := pr.Controlling.Wrap(bc)
	if err != nil {
		t.Fatal(err)
	}
	in, err := Deliver(pr.Controlled, segs)
	if err != nil || !in.Broadcast || !bytes.Equal(in.ASDU, bc) {
		t.Fatalf("broadcast %+v %v", in, err)
	}
	// The broadcast Session Request carries BK = 1 (TS 5.4.3.9.2.4).
	_, _ = bs.Begin(bytes.Repeat([]byte{0xB1}, 32), []uint16{3})
	pr.Controlling.StartBroadcastKeyChange()
	sq := pr.Controlling.Outbox()
	if len(sq) != 1 || sq[0][0] != SSQNA1 || sq[0][10]&1 != 1 {
		t.Fatalf("broadcast session request %x", sq)
	}
	for _, f := range sq {
		pr.Controlled.Receive(f)
	}
	pr.Pump()
	if bs.Distributing() || len(pr.Controlled.BroadcastReceiver().Keys()) != 2 {
		t.Errorf("update not distributed")
	}
}

// Covers: SIG-IPE-1716
func TestDSQRules(t *testing.T) {
	pr, _ := newTestPair(t, pairOpts{link: TCP})
	connect(t, pr)
	p := Params104
	var frames [][][]byte
	for i := 0; i < 3; i++ {
		s, _ := pr.Controlling.Wrap(cmdASDU(p, byte(i)))
		frames = append(frames, s)
	}
	// A gap is accepted (only lower than expected is refused, 8.5.2.2.4 d).
	if in, err := Deliver(pr.Controlled, frames[2]); err != nil || in.Kind != Data {
		t.Errorf("DSQ 3 first: %v", err)
	}
	if _, err := Deliver(pr.Controlled, frames[1]); !errors.Is(err, ErrReplay) {
		t.Errorf("DSQ 2 after 3: %v", err)
	}
	if pr.Controlled.Stats().Get(StatUnexpectedMessages) != 1 {
		t.Error("lower DSQ counted as unexpected (Table 34 row 3)")
	}
}

// Covers: SIG-IPE-1717
// Covers: SIG-IPE-1418
func TestUnsecuredAndNoSession(t *testing.T) {
	pr, _ := newTestPair(t, pairOpts{link: TCP})
	p := Params104
	pr.Controlled.LinkUp()
	if in, err := pr.Controlled.Receive(cmdASDU(p, 1)); !errors.Is(err, ErrUnsecured) || in.Kind != Discarded {
		t.Error("plain ASDU on a secured connection")
	}
	// Before a session: queued, sent once the session is established.
	pr.Controlling.LinkUp()
	if s, err := pr.Controlling.Wrap(cmdASDU(p, 7)); err != nil || s != nil {
		t.Fatal("not queued without a session")
	}
	got, _ := pr.Pump()
	if len(got) != 1 || !bytes.Equal(got[0], cmdASDU(p, 7)) {
		t.Errorf("queued command not delivered: %d", len(got))
	}
	s := DefaultSettings(true)
	s.DisableSecureCommunication = true
	e, err := NewEndpoint(Config{Controlling: true, Link: TCP, Params: p, MaxASDU: 249, Settings: s})
	if err != nil {
		t.Fatal(err)
	}
	e.LinkUp()
	if out, _ := e.Wrap(cmdASDU(p, 1)); len(out) != 1 || !bytes.Equal(out[0], cmdASDU(p, 1)) {
		t.Error("disabled secure communication changed the ASDU")
	}
	if in, err := e.Receive(indASDU(p, 1)); err != nil || in.Kind != Plain {
		t.Error("plain receive")
	}
}

// Covers: SIG-IPE-1718
func TestSecurityEvents(t *testing.T) {
	st := NewStats()
	var got []Event
	st.Event = func(e Event) { got = append(got, e) }
	st.Inc(StatKeyAuthenticationErrors)
	st.Inc(StatTotalMessagesSent)
	st.Inc(StatSuccessfulAssociations)
	if len(got) != 2 || got[0].Mnemonic != "KEY_AUTN_ERR" || got[0].Severity != "alarm" || got[0].ID != "62351-5:1.11" ||
		got[1].Mnemonic != "STAS_PROC_SUCC" || got[1].Severity != "notice" {
		t.Errorf("events %+v", got)
	}
	// Counters run to 2^32-1 (7.5.1); reports are modulo 2^31 with the carry.
	st.IOA[StatDiscardedMessages] = 5
	var reps []StatReport
	st.Report = func(r StatReport) { reps = append(reps, r) }
	st.Add(StatDiscardedMessages, BCRMax+5)
	if st.Get(StatDiscardedMessages) != BCRMax+5 || len(reps) != 1 || !reps[0].Carry || reps[0].Value != 4 {
		t.Errorf("wide counter %d %+v", st.Get(StatDiscardedMessages), reps)
	}
}
