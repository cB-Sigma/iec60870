package sec

import (
	"bytes"
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/cB-Sigma/iotsec"
)

// Errors of the Endpoint.
var (
	ErrUnsecured    = errors.New("iec60870sec: unsecured ASDU refused on a secured connection")
	ErrNoSessionKey = errors.New("iec60870sec: no valid session key")
	ErrLinkDown     = errors.New("iec60870sec: communication failure, sending stopped")
	ErrReplay       = errors.New("iec60870sec: data sequence number lower than expected")
	ErrAssociation  = errors.New("iec60870sec: association IDs do not match")
	ErrQueueFull    = errors.New("iec60870sec: secure data queue full")
)

// maxQueue bounds the ASDUs held while no session is established or the
// transmission is suspended (Tables 33 and 34 queue them).
const maxQueue = 1024

// Config configures one end of an A-Profile association.
type Config struct {
	Controlling bool
	Link        Link
	Params      Params
	MaxASDU     int // largest ASDU the link carries (IEC 104: 249)
	Settings    Settings
	// CA and Originator fill the DUI of the security messages we send.
	CA         uint16
	Originator uint8
	// AIM (controlling station) or AIS (controlled station) is the ID this
	// station chooses for the association (8.3.5.2.2, 8.3.5.5.3), 1 to 65535.
	AIM, AIS uint16
	// Station Association (8.3): our key pair and certificate (DER), and
	// what we trust. Without them the association cannot run and only
	// update keys kept in Store (or provisioned) are used.
	Key                *PrivateKey
	Certificate        []byte
	Trust              Trust
	IgnoreCertValidity bool // TS 60870-5-7 Annex B, devices without an accurate clock
	// Algorithms the controlling station selects (defaults: HMAC-SHA-256
	// truncated for the link, AES-256 Key Wrap, the same MAC for data). The
	// controlled station accepts the codes in Accept* (empty: all built).
	MAL, KWA, DPA uint8
	AcceptMAL     []uint8
	AcceptKWA     []uint8
	AcceptDPA     []uint8
	// Roles are the RBAC roles of the controlling station at the controlled
	// station (8.3.12.2.2, configured for self-signed certificates).
	Roles []Role
	// RBAC, when set, takes the controlling station's roles from the
	// IEC 62351-8 access token of its Central Authority certificate
	// (Profile A) or of an attribute certificate bound to it (Profile B),
	// and checks the certificate's revocation (8.3.12.2, IEC 62351-8
	// clause 12). A CA-signed certificate without a token gets no role.
	RBAC iotsec.CertificateRoleAuthority
	// Revoked, when set, checks a certificate's revocation status (CRL and
	// OCSP after IEC 62351-9, say): at the Station Association
	// (a revoked remote certificate is refused) and in CheckCertificates
	// (a revoked remote or own certificate invalidates the keys, Tables 15
	// and 16). It may fetch over the network.
	Revoked func(c *Certificate) bool
	// Store keeps the association over restarts; nil keeps it in memory.
	Store KeyStore
	// Broadcast is the IEC 101 Broadcast Session Key: on the controlling
	// station a sender shared by the stations of the line, on the
	// controlled station BroadcastReceiver is set (5.3.4.2).
	BroadcastSender *BroadcastSender
	Broadcast       bool
	Stats           *Stats
	Now             func() time.Time
	// Transmit sends security messages and queued Secure Data (frames
	// already segmented). It must not block and must not call back into the
	// Endpoint; nil keeps them for Outbox.
	Transmit func(frames []Frame)
}

// Frame is one ASDU to transmit. Orig is set on the last segment of queued
// Secure Data: the application ASDU given to Wrap (the same slice), so a
// link can report it acknowledged.
type Frame struct {
	Data []byte
	Orig []byte
}

// InboundKind classifies a received ASDU.
type InboundKind int

const (
	// Pending means a segment was taken and the ASDU is not complete.
	Pending InboundKind = iota
	// Plain is an IEC 101/104 ASDU received with the A-Profile disabled.
	Plain
	// Data is the verified ASDU carried by a Secure Data message.
	Data
	// Security is a key management message the Endpoint has processed.
	Security
	// Discarded means the ASDU was refused and counted.
	Discarded
)

// Inbound is the result of Receive.
type Inbound struct {
	Kind      InboundKind
	ASDU      []byte // Plain and Data: the IEC 101/104 ASDU
	DUI       DUI
	Msg       Message // Security: the message processed
	Broadcast bool    // Data protected with the Broadcast Session Key
}

// Controlling station key management states (IEC 62351-5:2023 Table 4).
type kmState int

const (
	kmIdle kmState = iota
	kmWaitAssociationResponse
	kmWaitUpdateKeyChangeResponse
	kmWaitSessionResponse
	kmWaitSessionKeyChangeResponse
)

var kmNames = [...]string{"Key Management Idle", "Wait for Association Response", "Wait for Update Key Change Response",
	"Wait for Session Response", "Wait for Session Key Change Response"}

// Controlled station states (Table 5).
type saState int

const (
	saIdle saState = iota
	saWaitUpdateKeyChangeRequest
)

type skcState int

const (
	skcNoAssociation skcState = iota
	skcSessionIdle
	skcWaitSessionKeyChangeRequest
)

// Status is a snapshot of the association for status reporting (no keys).
type Status struct {
	UpdateKeysValid  bool   `json:"updateKeysValid"`
	SessionKeysValid bool   `json:"sessionKeysValid"`
	State            string `json:"state"`
	AIM              uint16 `json:"aim,omitempty"`
	AIS              uint16 `json:"ais,omitempty"`
	MAL              string `json:"mal,omitempty"`
	DPA              string `json:"dpa,omitempty"`
	Queued           int    `json:"queued,omitempty"`
	RemoteSubject    string `json:"remote,omitempty"`
}

// Endpoint is one station's end of an A-Profile association: the Station
// Association, Session Key Change and Secure Data Exchange state machines
// of IEC 62351-5:2023 clause 8 with the IEC 60870-5-101/104 mapping and
// additions of IEC TS 60870-5-7 (segmentation, Session Initiation Request,
// broadcast key). Drive it with Start, LinkUp, LinkDown, Receive, Wrap and
// Tick. It is safe for concurrent use.
type Endpoint struct {
	mu    sync.Mutex
	cfg   Config
	enrol func(context.Context, *Endpoint, *slog.Logger) // IEC 62351-9 enrolment (SetEnrolment)
	stats *Stats
	reasm *Reassembler
	asn   uint8
	up    bool
	out   []Frame // frames for Transmit, flushed after the lock

	// association
	st          State // persisted
	updateValid bool
	remote      *Certificate
	// certRoles are the roles of the remote certificate's IEC 62351-8
	// token (certRBAC set) or of a pending association (pendingRoles).
	certRoles    []Role
	certRBAC     bool
	pendingRoles []Role
	pendingRBAC  bool
	mal          MACAlgorithm
	dp           DataProtection

	// controlling
	km            kmState
	replyAt       time.Time // zero: reply timer stopped
	lastRequest   []byte    // last request sent (whole ASDU), retransmitted on a reply timeout
	maxReply      uint32    // Max Reply Timeouts moving threshold (7.5.2)
	pendingKeys   UpdateKeys
	pendingAIS    uint16
	assocRandom   []byte // controlled random of the Association Response
	sessRequest   []byte // Session Request sent (whole ASDU)
	sessBroadcast bool   // the running change is for the broadcast key
	newSession    SessionKeys
	newBroadcast  []byte
	suspended     bool
	solicited     bool   // the running change was solicited (TS 5.3.4.3)
	lastSI        []byte // Session Initiation Request: last sent (controlled) or received (controlling)
	broadcastDue  bool

	// controlled
	sa         saState
	skc        skcState
	saTimerAt  time.Time
	skcTimerAt time.Time
	siTimerAt  time.Time
	siPending  bool
	apSent     []byte // Association Response sent
	apRandom   []byte
	uhValid    []byte // last valid Update Key Change Request
	upSent     []byte
	sqRecv     []byte // Session Request received
	spSent     []byte
	spRandom   []byte
	khValid    []byte
	kpSent     []byte
	brecv      *BroadcastReceiver

	// session
	sessionValid bool
	keys         SessionKeys
	usage        KeyUsage
	txDSQ, rxDSQ uint32
	queue        [][]byte
}

// NewEndpoint checks the configuration.
func NewEndpoint(cfg Config) (*Endpoint, error) {
	if err := cfg.Params.validate(); err != nil {
		return nil, err
	}
	if cfg.Link == TCP && cfg.Params != Params104 {
		return nil, errors.New("iec60870sec: IEC 104 uses 2-octet cause and common address")
	}
	if cfg.Link == TCP && (cfg.Broadcast || cfg.BroadcastSender != nil) {
		return nil, errors.New("iec60870sec: the Broadcast Session Key is IEC 101 only (TS 5.3.4.1)")
	}
	if cfg.MaxASDU < cfg.Params.DUILen()+2 {
		return nil, fmt.Errorf("iec60870sec: maximum ASDU length %d too small", cfg.MaxASDU)
	}
	if cfg.Settings == (Settings{}) {
		cfg.Settings = DefaultSettings(cfg.Controlling)
	}
	if err := cfg.Settings.Validate(); err != nil {
		return nil, err
	}
	serial := cfg.Link == Serial
	if cfg.MAL == 0 {
		cfg.MAL = map[bool]uint8{true: MALHMACSHA256S, false: MALHMACSHA256N}[serial]
	}
	if cfg.KWA == 0 {
		cfg.KWA = KWAAES256
	}
	if cfg.DPA == 0 {
		cfg.DPA = cfg.MAL
	}
	if _, ok := MACByCode(cfg.MAL); !ok {
		return nil, fmt.Errorf("iec60870sec: MAC algorithm %d not supported", cfg.MAL)
	}
	if _, ok := KeyWrapByCode(cfg.KWA); !ok {
		return nil, fmt.Errorf("iec60870sec: key wrap algorithm %d not supported", cfg.KWA)
	}
	if _, ok := DataProtectionByCode(cfg.DPA); !ok {
		return nil, fmt.Errorf("iec60870sec: data protection algorithm %d not supported", cfg.DPA)
	}
	if !cfg.Settings.DisableSecureCommunication {
		if cfg.Controlling && cfg.AIM == 0 {
			return nil, errors.New("iec60870sec: the controlling station's association ID (AIM) must be 1 to 65535")
		}
		if !cfg.Controlling && cfg.AIS == 0 {
			return nil, errors.New("iec60870sec: the controlled station's association ID (AIS) must be 1 to 65535")
		}
		if cfg.Key != nil && len(cfg.Certificate) == 0 {
			return nil, errors.New("iec60870sec: a private key needs its certificate")
		}
		if len(cfg.Certificate) > 0 {
			c, err := ParseCertificate(cfg.Certificate)
			if err != nil {
				return nil, err
			}
			if cfg.Key == nil || c.Curve != cfg.Key.Curve() || !bytes.Equal(c.PublicKey, cfg.Key.PublicKey()) {
				return nil, errors.New("iec60870sec: the certificate does not carry our public key")
			}
		}
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	e := &Endpoint{cfg: cfg, stats: cfg.Stats}
	if e.stats == nil {
		e.stats = NewStats()
	}
	e.reasm = NewReassembler(cfg.Params)
	e.reasm.Discarded = func() { e.stats.Inc(StatDiscardedMessages) }
	e.usage = KeyUsage{MaxTime: cfg.Settings.MaxSessionKeyUsageTime, MaxCount: cfg.Settings.MaxSessionKeyUsageCount}
	if cfg.Broadcast && !cfg.Controlling {
		e.brecv = &BroadcastReceiver{Usage: KeyUsage{MaxTime: cfg.Settings.MaxBroadcastKeyUsageTime, MaxCount: cfg.Settings.MaxBroadcastKeyUsageCount}}
	}
	e.resetMaxReply()
	return e, nil
}

// Secure reports whether the A-Profile applies to this connection (TS 5.3.5).
func (e *Endpoint) Secure() bool { return !e.cfg.Settings.DisableSecureCommunication }

// Stats returns the association's statistics.
func (e *Endpoint) Stats() *Stats { return e.stats }

// BroadcastReceiver is the controlled station's broadcast key state.
func (e *Endpoint) BroadcastReceiver() *BroadcastReceiver { return e.brecv }

// Roles are the RBAC roles of the controlling station (controlled station).
func (e *Endpoint) Roles() []Role {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.roles()
}

func (e *Endpoint) roles() []Role {
	if e.certRBAC {
		return e.certRoles
	}
	if len(e.st.Roles) > 0 {
		var rs []Role
		for _, id := range e.st.Roles {
			if r, ok := RoleByID(int(id)); ok {
				rs = append(rs, r)
			}
		}
		return rs
	}
	return e.cfg.Roles
}

// Permits reports whether the controlling station's roles allow a request
// of the type identification (TS 60870-5-7 Table 1, cause 17 otherwise).
// Without RBAC (no roles configured and none from a certificate) every
// request is allowed.
func (e *Endpoint) Permits(typeID uint8) bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	roles := e.roles()
	if !e.certRBAC && len(roles) == 0 {
		return true
	}
	return Authorized(roles, typeID)
}

// certificateRoles evaluates the IEC 62351-8 token of a remote station
// certificate already verified by VerifyRemote (8.3.12.2). use is false
// when the roles are the configured ones (no RBAC verifier, a self-signed
// certificate: 8.3.12.2.2). The subject is authenticated: the association
// completes only with the certificate's private key (ECDH, 8.3.10).
func (e *Endpoint) certificateRoles(cert *Certificate) (roles []Role, use bool, err error) {
	v := e.cfg.RBAC
	if v == nil || e.cfg.Controlling || cert == nil || cert.SelfSigned() {
		return nil, false, nil
	}
	var issuer *x509.Certificate
	for _, der := range e.cfg.Trust.CAs {
		if c, err := x509.ParseCertificate(der); err == nil && bytes.Equal(c.RawSubject, cert.IssuerDN) {
			issuer = c
		}
	}
	grants, err := v.CertificateRoles(context.Background(), cert.Raw, issuer, iotsec.RoleRequest{Peer: cert.Subject, Remote: true,
		SubjectAuthenticated: true, TokenVerified: true})
	if errors.Is(err, iotsec.ErrRevoked) {
		return nil, true, err
	}
	if err != nil {
		grants = nil
	}
	return RolesFromGrants(grants), true, nil
}

// Config returns the configuration the endpoint runs with (Credentials
// and SetCredentials change its key and certificate).
func (e *Endpoint) Config() Config {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.cfg
}

// TrustAnchors returns the Central Authority certificates (DER) the
// endpoint trusts (Config.Trust.CAs).
func (e *Endpoint) TrustAnchors() [][]byte {
	e.mu.Lock()
	defer e.mu.Unlock()
	return append([][]byte(nil), e.cfg.Trust.CAs...)
}

// RoleAuthority is the IEC 62351-8 authority the endpoint evaluates the
// controlling station's certificate with (Config.RBAC; nil without one).
func (e *Endpoint) RoleAuthority() iotsec.CertificateRoleAuthority { return e.cfg.RBAC }

// SetCredentials replaces the station's private key and certificate; the
// next Station Association uses them (the current update keys stay).
func (e *Endpoint) SetCredentials(key *PrivateKey, cert []byte) {
	e.mu.Lock()
	defer e.unlock()
	e.cfg.Key, e.cfg.Certificate = key, cert
}

// Credentials returns the station's certificate (DER).
func (e *Endpoint) Credentials() []byte {
	e.mu.Lock()
	defer e.unlock()
	return e.cfg.Certificate
}

// RunEnrolment runs the station's certificate enrolment and renewal
// until ctx ends (nothing without SetEnrolment).
func (e *Endpoint) RunEnrolment(ctx context.Context, log *slog.Logger) {
	e.mu.Lock()
	run := e.enrol
	e.mu.Unlock()
	if run != nil {
		run(ctx, e, log)
	}
}

// SetEnrolment installs what RunEnrolment runs: an IEC 62351-9
// certificate enrolment and renewal that installs renewed credentials
// with SetCredentials (nil: none).
func (e *Endpoint) SetEnrolment(run func(ctx context.Context, e *Endpoint, log *slog.Logger)) {
	e.mu.Lock()
	defer e.unlock()
	e.enrol = run
}

func (e *Endpoint) sendDir() Direction {
	if e.cfg.Controlling {
		return Control
	}
	return Monitor
}

func (e *Endpoint) recvDir() Direction {
	if e.cfg.Controlling {
		return Monitor
	}
	return Control
}

// unlock releases the lock and hands the frames produced meanwhile to
// Transmit.
func (e *Endpoint) unlock() {
	out := e.out
	if e.cfg.Transmit != nil {
		e.out = nil
	} else {
		out = nil
	}
	e.mu.Unlock()
	if len(out) > 0 {
		e.cfg.Transmit(out)
	}
}

// Outbox returns (and clears) the frames produced while no Transmit is
// configured.
func (e *Endpoint) Outbox() [][]byte {
	e.mu.Lock()
	defer e.mu.Unlock()
	var o [][]byte
	for _, f := range e.out {
		o = append(o, f.Data)
	}
	e.out = nil
	return o
}

// Status reports the association state.
func (e *Endpoint) Status() Status {
	e.mu.Lock()
	defer e.mu.Unlock()
	s := Status{UpdateKeysValid: e.updateValid, SessionKeysValid: e.sessionValid, AIM: e.st.AIM, AIS: e.st.AIS, Queued: len(e.queue)}
	if e.cfg.Controlling {
		s.State = kmNames[e.km]
	} else {
		s.State = [...]string{"No Association", "Session Idle", "Wait for Session Key Change Request"}[e.skc]
		if e.sa == saWaitUpdateKeyChangeRequest {
			s.State = "Wait for Update Key Change Request"
		}
	}
	if e.updateValid {
		s.MAL = e.mal.Name
	}
	if e.sessionValid {
		if e.dp.AEAD {
			s.DPA = "AEAD-AES-256-GCM"
		} else if e.dp.MAC != nil {
			s.DPA = e.dp.MAC.Name
		}
	}
	if e.remote != nil {
		s.RemoteSubject = e.remote.Subject
	}
	return s
}

// ProvisionUpdateKeys installs update keys and association IDs obtained
// outside the Station Association procedure (commissioning; not an
// IEC 62351-5 procedure, which derives them by ECDH, F-426).
func (e *Endpoint) ProvisionUpdateKeys(aim, ais uint16, mal, kwa uint8, k UpdateKeys) error {
	m, ok := MACByCode(mal)
	if !ok || !k.Valid() || aim == 0 || ais == 0 {
		return errors.New("iec60870sec: provisioned update keys need AIM, AIS, a known MAL and two 32-octet keys")
	}
	if _, ok := KeyWrapByCode(kwa); !ok {
		return errors.New("iec60870sec: provisioned key wrap algorithm not supported")
	}
	e.mu.Lock()
	defer e.unlock()
	e.st.AIM, e.st.AIS, e.st.MAL, e.st.KWA = aim, ais, mal, kwa
	e.st.Encryption, e.st.Authentication = bytes.Clone(k.Encryption), bytes.Clone(k.Authentication)
	e.mal, e.updateValid = m, true
	if !e.cfg.Controlling && e.skc == skcNoAssociation {
		e.skc = skcSessionIdle
	}
	return e.save()
}

// Start loads the association kept over a restart. Update keys stay valid
// (6.2.6.3); stored session keys are marked invalid (TS 5.3.4.3.2/3).
func (e *Endpoint) Start() error {
	e.mu.Lock()
	defer e.unlock()
	if e.cfg.Store == nil {
		return nil
	}
	st, ok, err := e.cfg.Store.Load()
	if err != nil || !ok {
		return err
	}
	e.st = st
	if m, ok := MACByCode(st.MAL); ok && (UpdateKeys{st.Encryption, st.Authentication}).Valid() && st.AIM != 0 && st.AIS != 0 {
		e.mal, e.updateValid = m, true
		if !e.cfg.Controlling {
			e.skc = skcSessionIdle
		}
	}
	if len(st.RemoteCert) > 0 {
		e.remote, _ = ParseCertificate(st.RemoteCert)
		roles, use, err := e.certificateRoles(e.remote)
		e.certRoles, e.certRBAC = roles, use
		if errors.Is(err, iotsec.ErrRevoked) {
			// Table 16 row 14: a revoked remote certificate invalidates the keys.
			e.stats.Inc(StatRemoteCertRevocations)
			e.stats.Inc(StatKeyInvalidationsRemoteRevocation)
			e.updateValid, e.skc = false, skcNoAssociation
		}
	}
	e.keys = SessionKeys{Control: st.Control, Monitor: st.Monitor}
	e.dp, _ = DataProtectionByCode(st.DPA)
	e.sessionValid = false
	return nil
}

func (e *Endpoint) save() error {
	if e.cfg.Store == nil {
		return nil
	}
	return e.cfg.Store.Save(e.st)
}

// LinkUp reports communication established: the controlling station runs
// the Station Association when it has no valid update keys (8.3.11), else
// the Session Key Change when the session keys are not valid (8.4.5); a
// controlled station whose kept session keys are invalid sends the Session
// Initiation Request (TS 5.3.4.3.2).
func (e *Endpoint) LinkUp() {
	e.mu.Lock()
	defer e.unlock()
	e.up = true
	if !e.Secure() {
		return
	}
	now := e.cfg.Now()
	if e.cfg.Controlling {
		if e.km != kmIdle {
			return
		}
		if !e.updateValid {
			e.startAssociation(now)
		} else if !e.sessionValid {
			e.startSessionKeyChange(now, false)
		}
		return
	}
	e.maybeSessionInitiation(now)
	e.flushQueue()
}

// LinkDown is a detected communication failure (Tables 15, 16, 27, 28, 33,
// 34): sending stops, timers stop (the session key usage timer keeps
// running, TS 5.3.2), a running procedure fails.
func (e *Endpoint) LinkDown() {
	e.mu.Lock()
	defer e.unlock()
	e.up = false
	e.reasm.Reset()
	e.out = nil
	if e.cfg.Controlling {
		switch e.km {
		case kmWaitAssociationResponse, kmWaitUpdateKeyChangeResponse:
			e.stats.Inc(StatAssociationFailures)
		case kmWaitSessionResponse, kmWaitSessionKeyChangeResponse:
			e.stats.Inc(StatSessionKeyChangeFailures)
		}
		e.km, e.replyAt, e.suspended = kmIdle, time.Time{}, false
		e.resetMaxReply()
		return
	}
	if e.sa == saWaitUpdateKeyChangeRequest {
		e.stats.Inc(StatAssociationFailures)
	}
	if e.skc == skcWaitSessionKeyChangeRequest {
		e.stats.Inc(StatSessionKeyChangeFailures)
		e.skc = skcSessionIdle
	}
	e.sa, e.saTimerAt, e.skcTimerAt, e.siTimerAt = saIdle, time.Time{}, time.Time{}, time.Time{}
}

// StartAssociation asks the controlling station to run the Station
// Association (Central Authority or application request, 8.3.11).
func (e *Endpoint) StartAssociation() error {
	e.mu.Lock()
	defer e.unlock()
	if !e.cfg.Controlling || e.km != kmIdle {
		return errors.New("iec60870sec: a key management procedure is running")
	}
	return e.startAssociation(e.cfg.Now())
}

// StartSessionKeyChange asks the controlling station to change the session
// keys (application request, Table 27).
func (e *Endpoint) StartSessionKeyChange() error {
	e.mu.Lock()
	defer e.unlock()
	if !e.cfg.Controlling || e.km != kmIdle || !e.updateValid {
		return errors.New("iec60870sec: no valid update keys, or a key management procedure is running")
	}
	e.startSessionKeyChange(e.cfg.Now(), false)
	return nil
}

// StartBroadcastKeyChange runs the Session Key Change for the IEC 101
// Broadcast Session Key with this station (5.3.4.2, BK=1) once the
// unicast keys are established.
func (e *Endpoint) StartBroadcastKeyChange() {
	e.mu.Lock()
	defer e.unlock()
	if e.cfg.BroadcastSender == nil {
		return
	}
	e.broadcastDue = true
	if e.km == kmIdle && e.sessionValid && e.up {
		e.broadcastDue = false
		e.startSessionKeyChange(e.cfg.Now(), true)
	}
}

func (e *Endpoint) resetMaxReply() {
	e.maxReply = e.stats.Get(StatReplyTimeouts) + uint32(e.cfg.Settings.MaxReplyTimeouts)
}

func (e *Endpoint) dui() DUI { return DUI{CA: e.cfg.CA, Originator: e.cfg.Originator} }

// emit encodes a security message and queues its segments for Transmit.
// It returns the whole ASDU (for MAC inputs and retransmission).
func (e *Endpoint) emit(m Message) []byte {
	c, _ := PermittedCause(m.TypeID(), e.sendDir())
	d := e.dui()
	d.Cause = c
	whole, err := Encode(d, e.cfg.Params, m)
	if err != nil {
		return nil
	}
	e.emitWhole(whole)
	return whole
}

func (e *Endpoint) emitWhole(whole []byte) {
	if !e.up {
		return
	}
	segs, next, err := Segment(whole, e.cfg.Params, e.cfg.MaxASDU, e.asn)
	if err != nil {
		return
	}
	e.asn = next
	for _, sg := range segs {
		e.out = append(e.out, Frame{Data: sg})
	}
	e.stats.Inc(StatTotalMessagesSent)
}

// macInput is a message up to the field before its MAC, DUI first
// (TS 5.4.3.2).
func (e *Endpoint) macInput(m Message) []byte {
	c, _ := PermittedCause(m.TypeID(), e.sendDir())
	d := e.dui()
	d.Cause = c
	b, _ := MACInput(d, e.cfg.Params, m)
	return b
}

// macInputOf is the same for a received message whose DUI is known.
func (e *Endpoint) macInputOf(d DUI, m Message) []byte {
	b, _ := MACInput(d, e.cfg.Params, m)
	return b
}

func (e *Endpoint) protocolInfo(broadcast bool) ProtocolInfo {
	p := ConformingPRI
	p.Broadcast = broadcast
	return p
}

// Tick runs the timers: reply timer (controlling), request timers
// (controlled), the session key usage timer and counter, and the Session
// Initiation Request repeat. Call it every few hundred milliseconds.
func (e *Endpoint) Tick(now time.Time) {
	e.mu.Lock()
	defer e.unlock()
	if !e.Secure() {
		return
	}
	if e.cfg.Controlling {
		e.tickControlling(now)
	} else {
		e.tickControlled(now)
	}
}

func (e *Endpoint) tickControlling(now time.Time) {
	if !e.replyAt.IsZero() && !now.Before(e.replyAt) {
		e.replyAt = time.Time{}
		e.stats.Inc(StatReplyTimeouts)
		if e.stats.Get(StatReplyTimeouts) >= e.maxReply {
			// Max Reply Timeouts: the procedure fails (Tables 15 and 27 row 10/11).
			e.stats.Inc(StatMaxReplyTimeouts)
			e.resetMaxReply()
			switch e.km {
			case kmWaitAssociationResponse, kmWaitUpdateKeyChangeResponse:
				e.stats.Inc(StatAssociationFailures)
			default:
				e.stats.Inc(StatSessionKeyChangeFailures)
			}
			e.km, e.suspended = kmIdle, false
			e.flushQueue()
			return
		}
		if e.lastRequest != nil {
			e.emitWhole(e.lastRequest)
			e.replyAt = now.Add(e.cfg.Settings.ExpectedReplyTime)
		}
		return
	}
	if e.km != kmIdle || !e.updateValid || !e.up {
		return
	}
	switch {
	case e.sessionValid && (e.usage.TimeExpired(now) || e.usage.CountReached() || e.txDSQ >= dsqRekey || e.rxDSQ >= dsqRekey):
		e.startSessionKeyChange(now, false)
	case !e.sessionValid:
		e.startSessionKeyChange(now, false)
	case e.broadcastDue:
		e.broadcastDue = false
		e.startSessionKeyChange(now, true)
	case e.cfg.BroadcastSender != nil && e.cfg.BroadcastSender.Distributing():
	}
}

// dsqRekey is where the controlling station changes the session keys so
// that DSQ never rolls over to 0 (8.5.2.2.4 f).
const dsqRekey = 0xFFFFFF00

func (e *Endpoint) tickControlled(now time.Time) {
	if !e.saTimerAt.IsZero() && !now.Before(e.saTimerAt) {
		e.saTimerAt = time.Time{}
		if e.sa == saWaitUpdateKeyChangeRequest {
			e.stats.Inc(StatRequestTimeouts)
			e.stats.Inc(StatAssociationFailures)
			e.sa = saIdle
		} else {
			e.uhValid, e.upSent = nil, nil
		}
	}
	if !e.skcTimerAt.IsZero() && !now.Before(e.skcTimerAt) {
		e.skcTimerAt = time.Time{}
		if e.skc == skcWaitSessionKeyChangeRequest {
			e.stats.Inc(StatRequestTimeouts)
			e.stats.Inc(StatSessionKeyChangeFailures)
			e.skc = skcSessionIdle
		} else {
			e.khValid, e.kpSent = nil, nil
		}
	}
	if e.sessionValid && e.skc != skcNoAssociation {
		timeUp, countUp := e.usage.TimeExpired(now), e.usage.CountReached()
		if timeUp || countUp {
			e.sessionValid = false
			if timeUp {
				e.stats.Inc(StatKeyInvalidationsTime)
			} else {
				e.stats.Inc(StatKeyInvalidationsCount)
			}
		}
	}
	if e.siPending && !e.siTimerAt.IsZero() && !now.Before(e.siTimerAt) {
		e.siPending = false
		e.stats.Inc(StatRequestTimeouts)
	}
	e.maybeSessionInitiation(now)
}

// maybeSessionInitiation sends the Session Initiation Request when the
// session keys are invalid while the Session Key Change state machine is in
// Session Idle (TS 5.3.4.3.2) and repeats it when the Request Timer expires.
func (e *Endpoint) maybeSessionInitiation(now time.Time) {
	if e.cfg.Controlling || !e.up || e.sessionValid || e.siPending || e.skc != skcSessionIdle || !e.updateValid || !e.keys.Available() {
		return
	}
	random, err := randomBytes(32)
	if err != nil {
		return
	}
	m := SessionInitiationRequest{AIM: e.st.AIM, AIS: e.st.AIS, Random: random}
	d := e.dui()
	d.Cause = CauseSessionKey
	in, err := SessionInitiationMACInput(e.keys, d, e.cfg.Params, m)
	if err != nil {
		return
	}
	m.MAC = e.mal.Sum(e.st.Authentication, in)
	e.lastSI = e.emit(m)
	e.siPending = true
	e.siTimerAt = now.Add(e.cfg.Settings.ExpectedRequestTime)
}

// SessionInitiationMACInput is the TS 60870-5-7 Table 4 input of the
// S_SI_NA_1 MAC: both session keys (even marked invalid) and the message up
// to CGD, DUI first. The key is the Authentication Update Key.
func SessionInitiationMACInput(keys SessionKeys, d DUI, p Params, m SessionInitiationRequest) ([]byte, error) {
	msg, err := MACInput(d, p, m)
	if err != nil {
		return nil, err
	}
	in := make([]byte, 0, len(keys.Control)+len(keys.Monitor)+len(msg))
	return append(append(append(in, keys.Control...), keys.Monitor...), msg...), nil
}

// Receive takes one received ASDU (a segment of a security ASDU, or any
// other ASDU).
func (e *Endpoint) Receive(asdu []byte) (Inbound, error) {
	d, err := ParseDUI(asdu, e.cfg.Params)
	if err != nil {
		e.stats.Inc(StatDiscardedMessages)
		return Inbound{Kind: Discarded}, err
	}
	if !IsSecurityType(d.Type) {
		if e.Secure() {
			e.stats.Inc(StatTotalMessagesReceived)
			e.stats.Inc(StatDiscardedMessages)
			return Inbound{Kind: Discarded}, ErrUnsecured
		}
		return Inbound{Kind: Plain, ASDU: asdu}, nil
	}
	e.mu.Lock()
	defer e.unlock()
	whole, _, err := e.reasm.Add(asdu)
	if err != nil {
		return Inbound{Kind: Discarded}, err
	}
	if whole == nil {
		return Inbound{Kind: Pending}, nil
	}
	e.stats.Inc(StatTotalMessagesReceived)
	if !e.Secure() {
		e.stats.Inc(StatDiscardedMessages)
		return Inbound{Kind: Discarded}, errors.New("iec60870sec: security message on an unsecured connection")
	}
	d, m, err := Decode(whole, e.cfg.Params, e.recvDir())
	if err != nil {
		return e.discard(StatUnexpectedMessages, err)
	}
	now := e.cfg.Now()
	var in Inbound
	if e.cfg.Controlling {
		in, err = e.receiveControlling(now, whole, d, m)
	} else {
		in, err = e.receiveControlled(now, whole, d, m)
	}
	if in.Kind == 0 {
		in = Inbound{Kind: Security, DUI: d, Msg: m}
	}
	return in, err
}

func (e *Endpoint) discard(st Stat, err error) (Inbound, error) {
	if st >= 0 {
		e.stats.Inc(st)
	}
	e.stats.Inc(StatDiscardedMessages)
	return Inbound{Kind: Discarded}, err
}

func errf(format string, a ...any) error { return fmt.Errorf("iec60870sec: "+format, a...) }

func randomOK(r []byte) bool { return len(r) >= 4 && len(r) <= 64 }

// ---------------------------------------------------------------- controlling

func (e *Endpoint) startAssociation(now time.Time) error {
	if e.cfg.Key == nil || len(e.cfg.Certificate) == 0 {
		// Table 15 row 1: no valid certificate, no operation.
		return errors.New("iec60870sec: no station certificate for the Station Association")
	}
	if c, err := ParseCertificate(e.cfg.Certificate); err != nil || (!e.cfg.IgnoreCertValidity && (now.Before(c.NotBefore) || now.After(c.NotAfter))) {
		return errors.New("iec60870sec: our station certificate is not valid")
	}
	m := AssociationRequest{AIM: e.cfg.AIM, AIS: 0, PRI: e.protocolInfo(false), CertData: e.cfg.Certificate}
	e.lastRequest = e.emit(m)
	e.km, e.replyAt = kmWaitAssociationResponse, now.Add(e.cfg.Settings.ExpectedReplyTime)
	return nil
}

func (e *Endpoint) startSessionKeyChange(now time.Time, broadcast bool) {
	random, err := randomBytes(32)
	if err != nil {
		return
	}
	m := SessionRequest{AIM: e.st.AIM, AIS: e.st.AIS, PRI: e.protocolInfo(broadcast), Random: random}
	e.sessRequest = e.emit(m)
	e.lastRequest = e.sessRequest
	e.sessBroadcast = broadcast
	e.km, e.replyAt = kmWaitSessionResponse, now.Add(e.cfg.Settings.ExpectedReplyTime)
}

func (e *Endpoint) unexpected(err error) (Inbound, error) {
	return e.discard(StatUnexpectedMessages, err)
}

func (e *Endpoint) receiveControlling(now time.Time, whole []byte, d DUI, m Message) (Inbound, error) {
	switch v := m.(type) {
	case AssociationResponse:
		if e.km != kmWaitAssociationResponse {
			return e.unexpected(errf("association response not expected"))
		}
		if v.AIM != e.cfg.AIM || v.AIS == 0 || !randomOK(v.Random) {
			return e.unexpected(errf("association response parameters"))
		}
		cert, err := VerifyRemote(v.CertData, e.cfg.Key.Curve(), e.cfg.Trust, now, e.cfg.IgnoreCertValidity)
		if err != nil {
			var ce *CertError
			if errors.As(err, &ce) && ce.NotAuthorized {
				return e.discard(StatRemoteAuthorizationFailures, err)
			}
			return e.discard(StatRemoteCertValidityFailures, err)
		}
		if e.cfg.Revoked != nil && e.cfg.Revoked(cert) {
			e.stats.Inc(StatRemoteCertRevocations)
			return e.discard(StatRemoteCertValidityFailures, errors.New("iec60870sec: remote certificate revoked"))
		}
		mal, _ := MACByCode(e.cfg.MAL)
		ikm, err := e.cfg.Key.ECDH(cert.PublicKey)
		if err != nil {
			return e.discard(StatRemoteCertValidityFailures, err)
		}
		random, err := randomBytes(32)
		if err != nil {
			return Inbound{Kind: Discarded}, err
		}
		keys, err := DeriveUpdateKeys(mal, ikm, random, v.Random)
		if err != nil {
			return Inbound{Kind: Discarded}, err
		}
		uh := UpdateKeyChangeRequest{AIM: e.cfg.AIM, AIS: v.AIS, KWA: e.cfg.KWA, MAL: e.cfg.MAL, Random: random}
		// Table 12: controlled station random data, then the request up to CGD.
		uh.MAC = mal.Sum(keys.Authentication, v.Random, e.macInput(uh))
		e.pendingKeys, e.pendingAIS, e.assocRandom, e.remote = keys, v.AIS, v.Random, cert
		e.lastRequest = e.emit(uh)
		e.km, e.replyAt = kmWaitUpdateKeyChangeResponse, now.Add(e.cfg.Settings.ExpectedReplyTime)
		return Inbound{}, nil
	case UpdateKeyChangeResponse:
		if e.km != kmWaitUpdateKeyChangeResponse {
			return e.unexpected(errf("update key change response not expected"))
		}
		mal, _ := MACByCode(e.cfg.MAL)
		// Table 14: the whole request received by the station, then the response up to AIS.
		if !mal.Verify(e.pendingKeys.Authentication, v.MAC, e.lastRequest, e.macInputOf(d, v)) {
			return e.discard(StatKeyAuthenticationErrors, errf("update key change response not authentic"))
		}
		if v.AIM != e.cfg.AIM || v.AIS != e.pendingAIS {
			return e.unexpected(ErrAssociation)
		}
		e.replyAt = time.Time{}
		e.st.AIM, e.st.AIS, e.st.MAL, e.st.KWA = e.cfg.AIM, v.AIS, e.cfg.MAL, e.cfg.KWA
		e.st.Encryption, e.st.Authentication = e.pendingKeys.Encryption, e.pendingKeys.Authentication
		e.st.RemoteCert = e.remote.Raw
		e.mal, e.updateValid = mal, true
		_ = e.save()
		e.stats.Inc(StatSuccessfulAssociations)
		e.resetMaxReply()
		// Table 15 row 6: the Session Key Change follows at once.
		e.startSessionKeyChange(now, false)
		return Inbound{}, nil
	case SessionResponse:
		if e.km != kmWaitSessionResponse {
			return e.unexpected(errf("session response not expected"))
		}
		var in []byte
		if e.solicited && e.lastSI != nil {
			// TS 60870-5-7 Table 5.
			in = append(append(append([]byte(nil), e.sessRequest...), e.macInputOf(d, v)...), e.lastSI...)
		} else {
			// IEC 62351-5 Table 20.
			in = append(append([]byte(nil), e.sessRequest...), e.macInputOf(d, v)...)
		}
		if !e.mal.Verify(e.st.Authentication, v.MAC, in) {
			return e.discard(StatKeyAuthenticationErrors, errf("session response not authentic"))
		}
		if v.AIM != e.st.AIM || v.AIS != e.st.AIS || !randomOK(v.Random) {
			return e.unexpected(ErrAssociation)
		}
		kw, _ := KeyWrapByCode(e.st.KWA)
		var plain []byte
		if e.sessBroadcast {
			bs := e.cfg.BroadcastSender
			if bs == nil {
				return e.unexpected(errf("no broadcast key"))
			}
			c, err := bs.Content()
			if err != nil {
				return e.unexpected(err)
			}
			plain = c
		} else {
			cd, err1 := randomBytes(32)
			md, err2 := randomBytes(32)
			if err1 != nil || err2 != nil {
				return Inbound{Kind: Discarded}, errors.New("iec60870sec: no random source")
			}
			e.newSession = SessionKeys{Control: cd, Monitor: md}
			plain = append(append([]byte(nil), cd...), md...) // Table 22
		}
		wkd, err := kw.Wrap(e.st.Encryption, plain)
		if err != nil {
			return Inbound{Kind: Discarded}, err
		}
		kh := SessionKeyChangeRequest{AIM: e.st.AIM, AIS: e.st.AIS, DPA: e.cfg.DPA, Wrapped: wkd}
		// Table 24: controlled station random data, then the request up to WKD.
		kh.MAC = e.mal.Sum(e.st.Authentication, v.Random, e.macInput(kh))
		e.replyAt = time.Time{}
		e.suspended = !e.sessBroadcast
		e.lastRequest = e.emit(kh)
		e.km, e.replyAt = kmWaitSessionKeyChangeResponse, now.Add(e.cfg.Settings.ExpectedReplyTime)
		return Inbound{}, nil
	case SessionKeyChangeResponse:
		if e.km != kmWaitSessionKeyChangeResponse {
			return e.unexpected(errf("session key change response not expected"))
		}
		// Table 26: the whole request, then the response up to AIS.
		if !e.mal.Verify(e.st.Authentication, v.MAC, e.lastRequest, e.macInputOf(d, v)) {
			return e.discard(StatKeyAuthenticationErrors, errf("session key change response not authentic"))
		}
		if v.AIM != e.st.AIM || v.AIS != e.st.AIS {
			return e.unexpected(ErrAssociation)
		}
		e.replyAt = time.Time{}
		e.km, e.suspended, e.solicited = kmIdle, false, false
		e.resetMaxReply()
		e.stats.Inc(StatSuccessfulSessionKeyChanges)
		if e.sessBroadcast {
			e.cfg.BroadcastSender.StationDone(e.cfg.CA, now)
			return Inbound{}, nil
		}
		dp, _ := DataProtectionByCode(e.cfg.DPA)
		e.keys, e.dp, e.sessionValid = e.newSession, dp, true
		e.st.Control, e.st.Monitor, e.st.DPA = e.newSession.Control, e.newSession.Monitor, e.cfg.DPA
		_ = e.save()
		e.usage.Start(now)
		e.txDSQ, e.rxDSQ = 0, 0
		e.flushQueue()
		if e.cfg.BroadcastSender != nil && (e.broadcastDue || e.cfg.BroadcastSender.pendingFor(e.cfg.CA)) {
			e.broadcastDue = false
			e.startSessionKeyChange(now, true)
		}
		return Inbound{}, nil
	case SessionInitiationRequest:
		// TS 60870-5-7 5.3.4.3.3.
		if e.km != kmIdle {
			return e.unexpected(errf("session initiation request during a key management procedure"))
		}
		if !e.updateValid || !e.keys.Available() || v.AIM != e.st.AIM || v.AIS != e.st.AIS {
			return e.discard(-1, ErrAssociation)
		}
		in, _ := SessionInitiationMACInput(e.keys, d, e.cfg.Params, v)
		if !e.mal.Verify(e.st.Authentication, v.MAC, in) {
			return e.discard(StatKeyAuthenticationErrors, errf("session initiation request not authentic"))
		}
		e.sessionValid, e.solicited, e.lastSI = false, true, whole
		e.startSessionKeyChange(now, false)
		if e.cfg.BroadcastSender != nil {
			e.broadcastDue = true
		}
		return Inbound{}, nil
	case SecureData:
		return e.receiveData(now, whole, d, v)
	}
	return e.unexpected(errf("%s not expected at the controlling station", TypeName(d.Type)))
}

// ---------------------------------------------------------------- controlled

func (e *Endpoint) acceptCode(list []uint8, code uint8, known bool) bool {
	if !known {
		return false
	}
	if len(list) == 0 {
		return true
	}
	for _, c := range list {
		if c == code {
			return true
		}
	}
	return false
}

func (e *Endpoint) receiveControlled(now time.Time, whole []byte, d DUI, m Message) (Inbound, error) {
	switch v := m.(type) {
	case AssociationRequest:
		if v.PRI.Major != ConformingPRI.Major || v.PRI.Minor != ConformingPRI.Minor {
			return e.discard(StatProtocolInformationErrors, errf("association request protocol version %d.%d", v.PRI.Major, v.PRI.Minor))
		}
		if e.cfg.Key == nil {
			return e.discard(-1, errors.New("iec60870sec: no station certificate for the Station Association"))
		}
		cert, err := VerifyRemote(v.CertData, e.cfg.Key.Curve(), e.cfg.Trust, now, e.cfg.IgnoreCertValidity)
		if err != nil {
			var ce *CertError
			if errors.As(err, &ce) && ce.NotAuthorized {
				return e.discard(StatRemoteAuthorizationFailures, err)
			}
			return e.discard(StatRemoteCertValidityFailures, err)
		}
		if e.cfg.Revoked != nil && e.cfg.Revoked(cert) {
			e.stats.Inc(StatRemoteCertRevocations)
			return e.discard(StatRemoteCertValidityFailures, errors.New("iec60870sec: remote certificate revoked"))
		}
		roles, use, rerr := e.certificateRoles(cert)
		if rerr != nil {
			e.stats.Inc(StatRemoteCertRevocations)
			return e.discard(StatRemoteCertValidityFailures, rerr)
		}
		e.pendingRoles, e.pendingRBAC = roles, use
		if e.sa == saWaitUpdateKeyChangeRequest && e.apSent != nil {
			// Table 16 row 1 column D: the same random data again.
			e.emitWhole(e.apSent)
			return Inbound{}, nil
		}
		random, err := randomBytes(32)
		if err != nil {
			return Inbound{Kind: Discarded}, err
		}
		ap := AssociationResponse{AIM: v.AIM, AIS: e.cfg.AIS, CertData: e.cfg.Certificate, Random: random}
		e.apRandom, e.remote = random, cert
		e.apSent = e.emit(ap)
		e.sa, e.saTimerAt = saWaitUpdateKeyChangeRequest, now.Add(e.cfg.Settings.ExpectedRequestTime)
		return Inbound{}, nil
	case UpdateKeyChangeRequest:
		if e.sa != saWaitUpdateKeyChangeRequest {
			if !e.saTimerAt.IsZero() && e.uhValid != nil && bytes.Equal(whole, e.uhValid) {
				e.emitWhole(e.upSent)
				return Inbound{}, nil
			}
			return e.unexpected(errf("update key change request not expected"))
		}
		mal, ok := MACByCode(v.MAL)
		if !e.acceptCode(e.cfg.AcceptMAL, v.MAL, ok) {
			return e.discard(StatKeyAuthAlgorithmSupportFailures, errf("MAC algorithm %d not supported", v.MAL))
		}
		if !randomOK(v.Random) {
			return e.unexpected(errf("update key change request random data length"))
		}
		ikm, err := e.cfg.Key.ECDH(e.remote.PublicKey)
		if err != nil {
			return e.discard(StatKeyAuthenticationErrors, err)
		}
		keys, err := DeriveUpdateKeys(mal, ikm, v.Random, e.apRandom)
		if err != nil {
			return Inbound{Kind: Discarded}, err
		}
		if !mal.Verify(keys.Authentication, v.MAC, e.apRandom, e.macInputOf(d, v)) {
			return e.discard(StatKeyAuthenticationErrors, errf("update key change request not authentic"))
		}
		if v.AIS != e.cfg.AIS || v.AIM == 0 {
			return e.unexpected(ErrAssociation)
		}
		_, ok = KeyWrapByCode(v.KWA)
		if !e.acceptCode(e.cfg.AcceptKWA, v.KWA, ok) {
			return e.discard(StatKeyWrapAlgorithmSupportFailures, errf("key wrap algorithm %d not supported", v.KWA))
		}
		up := UpdateKeyChangeResponse{AIM: v.AIM, AIS: e.cfg.AIS}
		up.MAC = mal.Sum(keys.Authentication, whole, e.macInput(up)) // Table 14
		e.st.AIM, e.st.AIS, e.st.MAL, e.st.KWA = v.AIM, e.cfg.AIS, v.MAL, v.KWA
		e.st.Encryption, e.st.Authentication = keys.Encryption, keys.Authentication
		e.st.RemoteCert = e.remote.Raw
		e.certRoles, e.certRBAC = e.pendingRoles, e.pendingRBAC
		e.mal, e.updateValid = mal, true
		_ = e.save()
		e.upSent = e.emit(up)
		e.uhValid = whole
		e.sa, e.saTimerAt = saIdle, now.Add(e.cfg.Settings.ExpectedRequestTime)
		e.stats.Inc(StatSuccessfulAssociations)
		if e.skc == skcNoAssociation {
			e.skc = skcSessionIdle // Table 28 row 12
		}
		return Inbound{}, nil
	case SessionRequest:
		if e.skc == skcNoAssociation {
			return e.unexpected(errf("session request without an association"))
		}
		if v.PRI.Major != ConformingPRI.Major || v.PRI.Minor != ConformingPRI.Minor || v.PRI.Broadcast && e.brecv == nil {
			return e.discard(StatProtocolInformationErrors, errf("session request protocol information not supported"))
		}
		if v.AIM != e.st.AIM || v.AIS != e.st.AIS || !randomOK(v.Random) {
			return e.unexpected(ErrAssociation)
		}
		if e.skc == skcWaitSessionKeyChangeRequest && e.spRandom != nil {
			// Table 28 row 1 column F: the same random data again.
			e.sqRecv = whole
			e.sendSessionResponse(now, e.spRandom)
			return Inbound{}, nil
		}
		e.solicited = e.siPending
		e.siPending, e.siTimerAt = false, time.Time{}
		random, err := randomBytes(32)
		if err != nil {
			return Inbound{Kind: Discarded}, err
		}
		e.sqRecv, e.sessBroadcast = whole, v.PRI.Broadcast
		e.sendSessionResponse(now, random)
		return Inbound{}, nil
	case SessionKeyChangeRequest:
		if e.skc == skcNoAssociation {
			return e.unexpected(errf("session key change request without an association"))
		}
		if e.skc == skcSessionIdle {
			if !e.skcTimerAt.IsZero() && e.khValid != nil && bytes.Equal(whole, e.khValid) {
				e.emitWhole(e.kpSent)
				return Inbound{}, nil
			}
			return e.unexpected(errf("session key change request not expected"))
		}
		// Table 24: the station's random data, then the request up to WKD.
		if !e.mal.Verify(e.st.Authentication, v.MAC, e.spRandom, e.macInputOf(d, v)) {
			return e.discard(StatKeyAuthenticationErrors, errf("session key change request not authentic"))
		}
		if v.AIM != e.st.AIM || v.AIS != e.st.AIS {
			return e.unexpected(ErrAssociation)
		}
		dp, ok := DataProtectionByCode(v.DPA)
		if !e.acceptCode(e.cfg.AcceptDPA, v.DPA, ok) {
			return e.discard(StatDataProtectionAlgorithmSupportFailures, errf("data protection algorithm %d not supported", v.DPA))
		}
		kw, _ := KeyWrapByCode(e.st.KWA)
		plain, err := kw.Unwrap(e.st.Encryption, v.Wrapped)
		if err != nil || len(plain) != 64 {
			return e.discard(StatKeyAuthenticationErrors, errf("wrapped key data not valid"))
		}
		kp := SessionKeyChangeResponse{AIM: e.st.AIM, AIS: e.st.AIS}
		kp.MAC = e.mal.Sum(e.st.Authentication, whole, e.macInput(kp)) // Table 26
		e.kpSent = e.emit(kp)
		e.khValid = whole
		e.skc, e.skcTimerAt = skcSessionIdle, now.Add(e.cfg.Settings.ExpectedRequestTime)
		e.stats.Inc(StatSuccessfulSessionKeyChanges)
		if e.sessBroadcast {
			if err := e.brecv.Install(plain, now); err != nil {
				return e.discard(StatKeyAuthenticationErrors, err)
			}
			return Inbound{}, nil
		}
		e.keys = SessionKeys{Control: plain[:32], Monitor: plain[32:]}
		e.dp, e.sessionValid = dp, true
		e.st.Control, e.st.Monitor, e.st.DPA = e.keys.Control, e.keys.Monitor, v.DPA
		_ = e.save()
		e.usage.Start(now)
		e.txDSQ, e.rxDSQ = 0, 0
		e.solicited = false
		e.flushQueue()
		return Inbound{}, nil
	case SecureData:
		return e.receiveData(now, whole, d, v)
	}
	return e.unexpected(errf("%s not expected at the controlled station", TypeName(d.Type)))
}

func (e *Endpoint) sendSessionResponse(now time.Time, random []byte) {
	sp := SessionResponse{AIM: e.st.AIM, AIS: e.st.AIS, Random: random}
	var in []byte
	if e.solicited && e.lastSI != nil {
		in = append(append(append([]byte(nil), e.sqRecv...), e.macInput(sp)...), e.lastSI...) // TS Table 5
	} else {
		in = append(append([]byte(nil), e.sqRecv...), e.macInput(sp)...) // IEC 62351-5 Table 20
	}
	sp.MAC = e.mal.Sum(e.st.Authentication, in)
	e.spRandom = random
	e.spSent = e.emit(sp)
	e.skc, e.skcTimerAt = skcWaitSessionKeyChangeRequest, now.Add(e.cfg.Settings.ExpectedRequestTime)
}

// ---------------------------------------------------------------- secure data

func (e *Endpoint) receiveData(now time.Time, whole []byte, d DUI, v SecureData) (Inbound, error) {
	broadcast := e.brecv != nil && d.CA == e.cfg.Params.BroadcastCA()
	var keys [][]byte
	switch {
	case broadcast:
		keys = e.brecv.Keys()
	case e.sessionValid && e.cfg.Controlling:
		keys = [][]byte{e.keys.Monitor}
	case e.sessionValid:
		keys = [][]byte{e.keys.Control}
	}
	if len(keys) == 0 {
		return e.unexpected(ErrNoSessionKey) // Tables 33 and 34, No Session
	}
	dp := e.dp
	if broadcast && dp.MAC == nil && !dp.AEAD {
		dp = DataProtection{MAC: &e.mal}
	}
	var (
		plain []byte
		used  []byte
		err   error
	)
	for _, k := range keys {
		if plain, _, err = OpenSecureData(whole, e.cfg.Params, e.recvDir(), dp, k); err == nil {
			used = k
			break
		}
	}
	if err != nil {
		if errors.Is(err, ErrDataAuthentication) {
			return e.discard(StatDataAuthenticationErrors, err)
		}
		return e.unexpected(err)
	}
	if !broadcast && (v.AIM != e.st.AIM || v.AIS != e.st.AIS) {
		return e.unexpected(ErrAssociation)
	}
	if broadcast {
		// Broadcast Secure Data reaches every station of the line: its
		// AIM and AIS are those of the sender's first association and are
		// not checked; its DSQ counts under the broadcast key (F-417).
		e.brecv.Verified(used)
		if v.DSQ <= e.brecv.lastDSQ {
			return e.unexpected(ErrReplay)
		}
		e.brecv.lastDSQ = v.DSQ
		e.brecv.Usage.Use()
	} else {
		// 8.5.2.2.4 d: lower than expected (last + 1, or 1 after a change) is discarded.
		if v.DSQ < e.rxDSQ+1 || v.DSQ == 0 {
			return e.unexpected(ErrReplay)
		}
		e.rxDSQ = v.DSQ
		e.usage.Use()
	}
	e.stats.Inc(StatSuccessfulDataAuthentications)
	return Inbound{Kind: Data, ASDU: plain, DUI: d, Broadcast: broadcast}, nil
}

// Wrap protects an outgoing IEC 101/104 ASDU. Without the A-Profile it is
// returned unchanged. With valid session keys it becomes an S_SD_NA_1 cut
// into segments that fit the link; otherwise (no session, or the
// controlling station's transmission suspended during a Session Key
// Change) it is queued and sent by Transmit later, and Wrap returns nil.
func (e *Endpoint) Wrap(asdu []byte) ([][]byte, error) {
	if !e.Secure() {
		return [][]byte{asdu}, nil
	}
	d, err := ParseDUI(asdu, e.cfg.Params)
	if err != nil {
		return nil, err
	}
	e.mu.Lock()
	defer e.unlock()
	if !e.up {
		return nil, ErrLinkDown
	}
	if e.cfg.BroadcastSender != nil && d.CA == e.cfg.Params.BroadcastCA() {
		return e.wrapBroadcast(asdu, d)
	}
	if !e.sessionValid || e.suspended || len(e.queue) > 0 {
		if len(e.queue) >= maxQueue {
			return nil, ErrQueueFull
		}
		e.queue = append(e.queue, asdu)
		return nil, nil
	}
	return e.wrapLocked(asdu, d)
}

func (e *Endpoint) wrapLocked(asdu []byte, d DUI) ([][]byte, error) {
	key := e.keys.Monitor
	if e.cfg.Controlling {
		key = e.keys.Control
	}
	e.txDSQ++
	sd := DUI{Originator: d.Originator, CA: d.CA}
	whole, err := ProtectSecureData(sd, e.cfg.Params, e.sendDir(), e.st.AIM, e.st.AIS, e.txDSQ, asdu, e.dp, key)
	if err != nil {
		return nil, err
	}
	e.usage.Use()
	segs, next, err := Segment(whole, e.cfg.Params, e.cfg.MaxASDU, e.asn)
	if err != nil {
		return nil, err
	}
	e.asn = next
	e.stats.Inc(StatTotalMessagesSent)
	return segs, nil
}

// ErrBroadcastNotReady is returned for a broadcast before the first
// Broadcast Session Key reached every station (we then do not send it,
// which TS 5.4.3.11.2 leaves to the application).
var ErrBroadcastNotReady = errors.New("iec60870sec: broadcast session key not yet distributed")

func (e *Endpoint) wrapBroadcast(asdu []byte, d DUI) ([][]byte, error) {
	if !e.updateValid || !e.sessionValid || e.cfg.BroadcastSender.Distributing() {
		return nil, ErrBroadcastNotReady
	}
	key, err := e.cfg.BroadcastSender.Key()
	if err != nil {
		return nil, err
	}
	dp := e.dp
	if dp.MAC == nil && !dp.AEAD {
		dp = DataProtection{MAC: &e.mal}
	}
	e.cfg.BroadcastSender.Use()
	sd := DUI{Originator: d.Originator, CA: d.CA}
	whole, err := ProtectSecureData(sd, e.cfg.Params, Control, e.st.AIM, e.st.AIS, e.cfg.BroadcastSender.NextDSQ(), asdu, dp, key)
	if err != nil {
		return nil, err
	}
	segs, next, err := Segment(whole, e.cfg.Params, e.cfg.MaxASDU, e.asn)
	e.asn = next
	return segs, err
}

// flushQueue sends the queued ASDUs once the session is established and
// the transmission is not suspended.
func (e *Endpoint) flushQueue() {
	if !e.sessionValid || e.suspended || !e.up {
		return
	}
	q := e.queue
	e.queue = nil
	for _, a := range q {
		d, _ := ParseDUI(a, e.cfg.Params)
		if segs, err := e.wrapLocked(a, d); err == nil {
			for i, sg := range segs {
				f := Frame{Data: sg}
				if i == len(segs)-1 {
					f.Orig = a
				}
				e.out = append(e.out, f)
			}
		}
	}
}

// KeysValid reports whether valid session keys are installed.
func (e *Endpoint) KeysValid() bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.sessionValid
}

// UpdateKeysValid reports whether the association has valid update keys.
func (e *Endpoint) UpdateKeysValid() bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.updateValid
}

// NotAuthorized records a Secure Data request the controlling station's
// role does not permit (Table 34 row 6; TS: answered with cause 17 by the
// adapter).
func (e *Endpoint) NotAuthorized() {
	e.stats.Inc(StatOperationAuthorizationFailures)
	e.stats.Inc(StatDiscardedMessages)
}

// CertificateRevoked applies Tables 15 and 16 rows 12 to 15: a revoked
// certificate (ours when local) invalidates the update and session keys.
func (e *Endpoint) CertificateRevoked(local bool) {
	e.mu.Lock()
	defer e.unlock()
	if local {
		e.stats.Inc(StatLocalCertRevocations)
		e.stats.Inc(StatKeyInvalidationsLocalRevocation)
	} else {
		e.stats.Inc(StatRemoteCertRevocations)
		e.stats.Inc(StatKeyInvalidationsRemoteRevocation)
	}
	e.updateValid, e.sessionValid = false, false
	if !e.cfg.Controlling {
		e.skc, e.skcTimerAt = skcNoAssociation, time.Time{}
	} else if e.km == kmWaitSessionResponse || e.km == kmWaitSessionKeyChangeResponse {
		e.km, e.replyAt, e.suspended = kmIdle, time.Time{}, false
		e.resetMaxReply()
		e.stats.Inc(StatSessionKeyChangeFailures)
	}
}

// CertificateExpired applies rows 13 and 15: counted only; the update keys
// stay valid (8.3.9).
func (e *Endpoint) CertificateExpired(local bool) {
	if local {
		e.stats.Inc(StatLocalCertExpirations)
	} else {
		e.stats.Inc(StatRemoteCertExpirations)
	}
}

// CheckCertificates checks both certificates' validity periods (8.3.9, at
// least every 24 hours).
func (e *Endpoint) CheckCertificates(now time.Time) {
	e.mu.Lock()
	var own, remote *Certificate
	if len(e.cfg.Certificate) > 0 {
		own, _ = ParseCertificate(e.cfg.Certificate)
	}
	remote = e.remote
	ok := e.updateValid
	var revoked bool
	if ok && remote != nil && e.cfg.RBAC != nil {
		// IEC 62351-8 12.12: the token certificate's revocation state and
		// roles are checked again with the certificates.
		roles, use, err := e.certificateRoles(remote)
		revoked = errors.Is(err, iotsec.ErrRevoked)
		if !revoked {
			e.certRoles, e.certRBAC = roles, use
		}
	}
	e.mu.Unlock()
	if !revoked && ok && remote != nil && e.cfg.Revoked != nil && e.cfg.Revoked(remote) {
		revoked = true
	}
	if revoked {
		e.CertificateRevoked(false)
		return
	}
	if ok && own != nil && e.cfg.Revoked != nil && e.cfg.Revoked(own) {
		e.CertificateRevoked(true)
		return
	}
	if !ok || e.cfg.IgnoreCertValidity {
		return
	}
	if own != nil && now.After(own.NotAfter) {
		e.CertificateExpired(true)
	}
	if remote != nil && now.After(remote.NotAfter) {
		e.CertificateExpired(false)
	}
}
