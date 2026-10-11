package sec

import (
	"strings"
	"sync"
	"time"
)

// Stat is a security statistic of TS 60870-5-7 9.7 Table 10 (the counters of
// IEC 62351-5:2023 7.5).
type Stat int

// Statistics in Table 10 order.
const (
	StatSuccessfulAssociations Stat = iota
	StatAssociationFailures
	StatSuccessfulSessionKeyChanges
	StatSessionKeyChangeFailures
	StatKeyInvalidationsTime
	StatKeyInvalidationsCount
	StatProtocolInformationErrors
	StatKeyAuthAlgorithmSupportFailures
	StatKeyWrapAlgorithmSupportFailures
	StatDataProtectionAlgorithmSupportFailures
	StatKeyAuthenticationErrors
	StatDataAuthenticationErrors
	StatUnexpectedMessages
	StatMaxReplyTimeouts
	StatRemoteAuthorizationFailures
	StatOperationAuthorizationFailures
	StatRemoteCertValidityFailures
	StatRemoteCertExpirations
	StatRemoteCertRevocations
	StatLocalCertExpirations
	StatLocalCertRevocations
	StatKeyInvalidationsRemoteRevocation
	StatKeyInvalidationsLocalRevocation
	StatSuccessfulDataAuthentications
	StatReplyTimeouts
	StatRequestTimeouts
	StatTotalMessagesSent
	StatTotalMessagesReceived
	StatDiscardedMessages
	numStats
)

// Station roles of Table 10.
const (
	atControlling = 1 << iota
	atControlled
	atBoth = atControlling | atControlled
)

// statDefs are the rows of TS 60870-5-7 Table 10 (IEC 62351-5:2023 Table 7):
// name, where kept, default threshold, and the event mnemonic, severity
// and identifier of Table 7 and Annex A ("" when the statistic has no
// event). Rows whose threshold cell is empty in the TS have threshold 0
// (reported at every change, F-419).
var statDefs = [numStats]struct {
	name      string
	at        int
	threshold uint32
	event     string
	severity  string
	id        string
}{
	{"Successful Station Associations", atBoth, 1, "STAS_PROC_SUCC", "notice", "62351-5:1.1"},
	{"Station Association Failures", atBoth, 1, "STAS_PROC_FAIL", "alarm", "62351-5:1.2"},
	{"Successful Session Key Changes", atBoth, 10, "SKEY_PROC_SUCC", "notice", "62351-5:1.3"},
	{"Session Key Change Failures", atBoth, 1, "SKEY_PROC_FAIL", "alarm", "62351-5:1.4"},
	{"Session Key Invalidations due Max Session Key Usage Time expired", atControlled, 1, "SKEY_INV_USETOUT", "alarm", "62351-5:1.5"},
	{"Session Key Invalidations due Max Session Key Usage Count reached", atControlled, 1, "SKEY_INV_USECNT", "alarm", "62351-5:1.6"},
	{"Protocol Information Errors", atControlled, 1, "PROT_INFO_ERR", "alarm", "62351-5:1.7"},
	{"Key Authentication Algorithm Support Failures", atControlled, 1, "KEY_AUTNALG_SUP", "alarm", "62351-5:1.8"},
	{"Key Wrap Algorithm Support Failures", atControlled, 1, "KEY_WRAPALG_SUP", "alarm", "62351-5:1.9"},
	{"Data Protection Algorithm Support Failures", atControlled, 1, "DATA_PROTALG_SUP", "alarm", "62351-5:1.10"},
	{"Key Authentication Errors", atBoth, 1, "KEY_AUTN_ERR", "alarm", "62351-5:1.11"},
	{"Data Authentication Errors", atBoth, 1, "DATA_AUTN_ERR", "warning", "62351-5:1.12"},
	{"Unexpected Messages", atBoth, 10, "UNXP_MSG_ERR", "warning", "62351-5:1.13"},
	{"Max Reply Timeouts", atControlling, 1, "MAX_REPLY_TOUT", "warning", "62351-5:1.14"},
	{"Remote Station's Authorization Failures", atBoth, 1, "NODE_NOT_AUTR", "alarm", "62351-5:2.1"},
	{"Operation Authorization Failures", atControlled, 1, "OPER_NOT_AUTR", "warning", "62351-5:2.2"},
	{"Remote Station's Certificate Validity Check Failures", atBoth, 1, "REM_CERT_NOTVALID", "alarm", "62351-5:2.3"},
	{"Remote Station's Certificate Expirations", atBoth, 1, "REM_CERT_EXPIRED", "warning", "62351-5:2.4"},
	{"Remote Station's Certificate Revocations", atBoth, 1, "REM_CERT_REVOKED", "alarm", "62351-5:2.5"},
	{"Local Station's Certificate Expirations", atBoth, 1, "LOC_CERT_EXPIRED", "warning", "62351-5:2.6"},
	{"Local Station's Certificate Revocations", atBoth, 1, "LOC_CERT_REVOKED", "alarm", "62351-5:2.7"},
	{"Cryptographic Keys Invalidations due to Remote Station's Certificate Revocation", atBoth, 0, "KEYS_INV_REMCERTREV", "alarm", "62351-5:2.8"},
	{"Cryptographic Keys Invalidations due to Local Station's Certificate Revocation", atBoth, 0, "KEYS_INV_LOCCERTREV", "alarm", "62351-5:2.9"},
	{"Successful Data Authentications", atBoth, 100, "", "", ""},
	{"Reply Timeouts", atControlling, 3, "", "", ""},
	{"Request Timeouts", atControlled, 1, "", "", ""},
	{"Total Messages Sent", atBoth, 500, "", "", ""},
	{"Total Messages Received", atBoth, 500, "", "", ""},
	{"Discarded Messages", atBoth, 10, "", "", ""},
}

// Event is a security event of IEC 62351-5:2023 Table 7 and Annex A,
// announced each time its statistic is incremented (7.5.1).
type Event struct {
	Stat     Stat
	Mnemonic string // e.g. KEY_AUTN_ERR
	Severity string // notice, warning or alarm
	ID       string // IEC 62351-14 event identifier, e.g. 62351-5:1.11
	Count    uint32 // the statistic after the increment
}

// String is the statistic's Table 10 name.
func (s Stat) String() string {
	if s < 0 || s >= numStats {
		return "unknown"
	}
	return statDefs[s].name
}

// DefaultThreshold is the Table 10 default threshold.
func (s Stat) DefaultThreshold() uint32 { return statDefs[s].threshold }

// KeptBy reports whether the statistic is kept at the controlling
// (controlling true) or controlled station per Table 10.
func (s Stat) KeptBy(controlling bool) bool {
	if controlling {
		return statDefs[s].at&atControlling != 0
	}
	return statDefs[s].at&atControlled != 0
}

// AllStats lists every statistic in Table 10 order.
func AllStats() []Stat {
	out := make([]Stat, numStats)
	for i := range out {
		out[i] = Stat(i)
	}
	return out
}

// BCRMax is the largest BCR value a statistic reports (TS 5.4.2.3: 0 to
// 2^31-1). The counters themselves count to 2^32-1 (IEC 62351-5:2023 7.5.1)
// and are reported modulo 2^31 with the carry set (F-419).
const BCRMax = 1<<31 - 1

// StatReport is one statistic to send as an integrated total with
// CP56Time2a (type 37, M_IT_TB_1) at the configured IOA (5.4.2.3, 9.7).
// Carry is set when the reported value passed BCRMax and restarted from 0
// since the last report.
type StatReport struct {
	Stat  Stat
	IOA   uint32
	Value uint32
	Carry bool
	Time  time.Time
}

// Stats holds the security statistics of one association. Thresholds and
// IOAs are configurable per 9.7; a statistic with no IOA is counted but not
// reported. Report is called (without the lock) when a statistic has grown
// by its threshold since it was last reported (Table 10 NOTE 1).
type Stats struct {
	mu        sync.Mutex
	value     [numStats]uint32
	carry     [numStats]bool
	reported  [numStats]uint32
	Threshold [numStats]uint32
	IOA       map[Stat]uint32
	Report    func(StatReport)
	// Event, when set, is called (without the lock) for every increment of
	// a statistic that has a Table 7 event.
	Event func(Event)
	Now   func() time.Time
}

// NewStats returns statistics with the Table 10 default thresholds.
func NewStats() *Stats {
	s := &Stats{IOA: map[Stat]uint32{}}
	for i := range s.Threshold {
		s.Threshold[i] = statDefs[i].threshold
	}
	return s
}

// Inc adds one to a statistic.
func (s *Stats) Inc(st Stat) { s.Add(st, 1) }

// Add adds n to a statistic. The counter wraps after 2^32-1. A report is
// due when the statistic has grown by its threshold since startup or since
// it was last reported (IEC 62351-5:2023 7.5.3, 9.2.6.7).
func (s *Stats) Add(st Stat, n uint32) {
	if s == nil || st < 0 || st >= numStats || n == 0 {
		return
	}
	s.mu.Lock()
	old := s.value[st]
	s.value[st] += n
	if uint64(old)%(BCRMax+1)+uint64(n) > BCRMax {
		s.carry[st] = true
	}
	var rep *StatReport
	ioa, ok := s.IOA[st]
	if ok && s.Report != nil && (s.carry[st] || s.value[st]-s.reported[st] >= max(s.Threshold[st], 1)) {
		now := time.Now()
		if s.Now != nil {
			now = s.Now()
		}
		rep = &StatReport{Stat: st, IOA: ioa, Value: s.value[st] & BCRMax, Carry: s.carry[st], Time: now}
		s.reported[st], s.carry[st] = s.value[st], false
	}
	ev, cb := statDefs[st], s.Event
	v := s.value[st]
	s.mu.Unlock()
	if rep != nil {
		s.Report(*rep)
	}
	if cb != nil && ev.event != "" {
		cb(Event{Stat: st, Mnemonic: ev.event, Severity: ev.severity, ID: ev.id, Count: v})
	}
}

// Get returns a statistic's value.
func (s *Stats) Get(st Stat) uint32 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.value[st]
}

// Snapshot returns every statistic by name.
func (s *Stats) Snapshot() map[string]uint32 {
	s.mu.Lock()
	defer s.mu.Unlock()
	m := make(map[string]uint32, numStats)
	for i, v := range s.value {
		m[statDefs[i].name] = v
	}
	return m
}

// StatByName finds a statistic by its name (String) or the mnemonic of
// its event, ignoring case.
func StatByName(n string) (Stat, bool) {
	for _, s := range AllStats() {
		if strings.EqualFold(s.String(), n) || statDefs[s].event != "" && strings.EqualFold(statDefs[s].event, n) {
			return s, true
		}
	}
	return 0, false
}
