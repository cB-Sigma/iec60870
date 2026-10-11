package sec

import (
	"bytes"
	"errors"
	"testing"
	"time"
)

// Covers: SIG-IPE-1423
func TestStatistics(t *testing.T) {
	if len(AllStats()) != 29 {
		t.Fatalf("%d statistics, Table 10 / IEC 62351-5 Table 7 have 29", len(AllStats()))
	}
	for st, th := range map[Stat]uint32{StatSuccessfulSessionKeyChanges: 10, StatUnexpectedMessages: 10, StatSuccessfulDataAuthentications: 100,
		StatReplyTimeouts: 3, StatTotalMessagesSent: 500, StatDiscardedMessages: 10, StatKeyAuthenticationErrors: 1} {
		if st.DefaultThreshold() != th {
			t.Errorf("%s threshold %d, want %d", st, st.DefaultThreshold(), th)
		}
	}
	if StatMaxReplyTimeouts.KeptBy(false) || !StatRequestTimeouts.KeptBy(false) || StatRequestTimeouts.KeptBy(true) {
		t.Error("Table 10 station types")
	}
	s := NewStats()
	var reps []StatReport
	s.Report = func(r StatReport) { reps = append(reps, r) }
	s.IOA[StatReplyTimeouts] = 9001
	s.Inc(StatReplyTimeouts)
	s.Inc(StatReplyTimeouts)
	if len(reps) != 0 {
		t.Fatal("reported below threshold")
	}
	s.Inc(StatReplyTimeouts)
	if len(reps) != 1 || reps[0].IOA != 9001 || reps[0].Value != 3 {
		t.Fatalf("reports %+v", reps)
	}
	// 7.5.3: the next report is due at the reported value plus the threshold.
	s.Inc(StatReplyTimeouts)
	s.Inc(StatReplyTimeouts)
	if len(reps) != 1 {
		t.Error("threshold not moved to the reported value")
	}
	s.Inc(StatReplyTimeouts)
	if len(reps) != 2 || reps[1].Value != 6 {
		t.Errorf("second report %+v", reps)
	}
	s.Inc(StatDiscardedMessages) // no IOA: counted, not reported
	if len(reps) != 2 || s.Get(StatDiscardedMessages) != 1 {
		t.Error("statistic without IOA reported")
	}
}

// Covers: SIG-IPE-1424
func TestRBAC(t *testing.T) {
	want := map[string]Permission{
		"VIEWER":    PermMonitorData | PermFileRead,
		"OPERATOR":  PermMonitorData | PermOperateControls | PermFileRead,
		"ENGINEER":  PermMonitorData | PermFileRead | PermFileWrite | PermFileMngt | PermConfigOperation,
		"INSTALLER": PermMonitorData | PermFileRead | PermFileWrite | PermConfigOperation,
		"SECADM":    PermFileRead | PermFileWrite | PermFileMngt | PermConfigSecurity,
		"SECAUD":    PermFileRead,
		"RBACMNT":   PermFileRead | PermFileWrite | PermFileMngt | PermConfigSecurity,
	}
	for i, r := range Roles {
		if int(r.ID) != i || want[r.Name] != r.Perms {
			t.Errorf("role %d %s %b", r.ID, r.Name, r.Perms)
		}
	}
	if !(Role{Perms: PermFileWrite}).Has(PermFileRead) {
		t.Error("FILEWRITE includes FILEREAD")
	}
	viewer, _ := RoleByID(0)
	operator, _ := RoleByID(1)
	if Authorized([]Role{viewer}, 45) || !Authorized([]Role{operator}, 45) || !Authorized([]Role{viewer}, 100) || !Authorized([]Role{viewer}, 103) {
		t.Error("authorisation")
	}
	secaud, _ := RoleByID(5)
	if Authorized([]Role{secaud}, 100) {
		t.Error("SECAUD has no MONITOR DATA")
	}
	d := NotAuthorizedDUI(DUI{Type: 45, VSQ: 1, Cause: 6, CA: 1})
	if b := d.Encode(Params104); b[2] != 0x40|17 {
		t.Errorf("negative confirmation cause %#x", b[2])
	}
}

// Covers: SIG-IPE-1425
// Covers: SIG-IPE-1719
func TestSettingsAndProfiles(t *testing.T) {
	c := DefaultSettings(true)
	if c.ExpectedReplyTime != 2*time.Second || c.ExpectedRequestTime != 6*time.Second || c.MaxReplyTimeouts != 3 || c.DisableSecureCommunication ||
		c.MaxSessionKeyUsageTime != 15*time.Minute || c.MaxSessionKeyUsageCount != 1000 {
		t.Errorf("defaults %+v", c)
	}
	d := DefaultSettings(false)
	if d.MaxSessionKeyUsageTime != 2*c.MaxSessionKeyUsageTime || d.MaxSessionKeyUsageCount != 2*c.MaxSessionKeyUsageCount {
		t.Error("controlled limits not doubled")
	}
	bad := c
	bad.MaxReplyTimeouts = 0
	if bad.Validate() == nil {
		t.Error("0 reply timeouts accepted")
	}
	bad = c
	bad.MaxSessionKeyUsageCount = 0
	if bad.Validate() == nil {
		t.Error("usage count 0 accepted")
	}
	long := c
	long.ExpectedReplyTime = 120 * time.Second
	if long.Validate() != nil {
		t.Error("120 s reply time refused (9.2.6.3)")
	}
	if DefaultPort(true) != 19998 || DefaultPort(false) != 2404 {
		t.Error("ports")
	}
	if (Profiles{T: true}).Validate(Serial) == nil || (Profiles{A: true, T: true}).Validate(TCP) != nil {
		t.Error("profiles")
	}
}

// Covers: SIG-IPE-1426
func TestCommunicationFailure(t *testing.T) {
	pr, ck := newTestPair(t, pairOpts{link: Serial, maxASDU: 12})
	connect(t, pr)
	p := Params{COTSize: 1, CASize: 1}
	segs, _ := pr.Controlling.Wrap(cmdASDU(p, 1))
	if len(segs) < 2 {
		t.Fatal("expected segments")
	}
	pr.Controlled.Receive(segs[0])
	pr.Controlled.LinkDown()
	if _, err := pr.Controlled.Wrap(cmdASDU(p, 1)); !errors.Is(err, ErrLinkDown) {
		t.Errorf("send after failure: %v", err)
	}
	pr.Controlled.LinkUp()
	if in, _ := pr.Controlled.Receive(segs[1]); in.Kind == Data {
		t.Error("series survived the failure")
	}
	// A failure while waiting for a response fails the procedure (Table 27 row 13).
	_ = pr.Controlling.StartSessionKeyChange()
	pr.Controlling.LinkDown()
	if pr.Controlling.Stats().Get(StatSessionKeyChangeFailures) != 1 || pr.Controlling.Status().State != "Key Management Idle" {
		t.Error("key change not failed on communication failure")
	}
	// The session keys stay valid and the usage timer keeps running.
	ck.add(20 * time.Minute)
	pr.Controlling.LinkUp()
	pr.Controlling.Tick(ck.now())
	if o := pr.Controlling.Outbox(); len(o) == 0 || o[0][0] != SSQNA1 {
		t.Error("usage time not honoured after the failure")
	}
}

// Covers: SIG-IPE-1427
// Covers: SIG-IPE-1417
func TestSimulatorPair(t *testing.T) {
	pr, _ := newTestPair(t, pairOpts{link: TCP})
	connect(t, pr)
	for i := 0; i < 70; i++ { // ASN wraps past 63
		asdu := indASDU(Params104, byte(i))
		segs, _ := pr.Controlled.Wrap(asdu)
		in, err := Deliver(pr.Controlling, segs)
		if err != nil || !bytes.Equal(in.ASDU, asdu) {
			t.Fatalf("message %d: %v", i, err)
		}
	}
	if _, err := Deliver(pr.Controlling, nil); err == nil {
		t.Error("empty delivery")
	}
}
