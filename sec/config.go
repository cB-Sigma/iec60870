package sec

import (
	"errors"
	"fmt"
	"time"
)

// Link is the protocol the extension is applied to.
type Link int

const (
	// Serial is IEC 60870-5-101.
	Serial Link = iota
	// TCP is IEC 60870-5-104.
	TCP
)

// Ports of 7.3.1: 19998 by default when the T-Profile (TLS) is enabled,
// otherwise the IEC 104 port 2404.
const (
	PortTLS   = 19998
	PortPlain = 2404
)

// DefaultPort is the IEC 104 port for the T-Profile setting (7.3.1).
func DefaultPort(tProfile bool) int {
	if tProfile {
		return PortTLS
	}
	return PortPlain
}

// Profiles are the security profiles enabled for a connection; each can be
// enabled or disabled on its own (7.1).
type Profiles struct {
	A bool // application layer, IEC 62351-5 (Clause 5)
	T bool // TLS, IEC 62351-3 (Clause 6), IEC 104 only
}

// Validate checks the profiles against the link (7.2: IEC 101 has no
// T-Profile).
func (p Profiles) Validate(l Link) error {
	if l == Serial && p.T {
		return errors.New("iec60870sec: the T-Profile (TLS) does not apply to IEC 60870-5-101")
	}
	return nil
}

// Settings are the configurable parameters of TS 60870-5-7 9.6 Table 9 and
// IEC 62351-5:2023 9.2.6. The remote public key, authorized remote stations
// and algorithm choices are in Config.
type Settings struct {
	ExpectedReplyTime          time.Duration // controlling station: 2 s (9.2.6.3), up to at least 120 s
	ExpectedRequestTime        time.Duration // controlled station: 6 s (TS Table 9; 9.2.6.4 reply time x max reply timeouts)
	MaxSessionKeyUsageTime     time.Duration // 15 min (9.2.6.5), up to 1 week; 0 disables the timer
	MaxSessionKeyUsageCount    uint32        // 1000 (9.2.6.6); 1 to 2^31-1 (F-427)
	MaxBroadcastKeyUsageTime   time.Duration // IEC 101 broadcast key (TS 5.3.4.2.1)
	MaxBroadcastKeyUsageCount  uint32
	MaxReplyTimeouts           int  // controlling station, 3 (TS Table 9)
	DisableSecureCommunication bool // off by default (9.2.6.10)
}

// DefaultSettings returns the defaults of IEC 62351-5:2023 9.2.6 and TS
// Table 9. At the controlled station the usage limits are twice those of
// the controlling station, as 9.2.6.5 and 9.2.6.6 recommend (and 8.4.6
// requires them greater). The broadcast key lasts 24 h (the lower end of
// the TS recommendation) and 65535 uses.
func DefaultSettings(controlling bool) Settings {
	s := Settings{
		ExpectedReplyTime:         2 * time.Second,
		ExpectedRequestTime:       6 * time.Second,
		MaxSessionKeyUsageTime:    15 * time.Minute,
		MaxSessionKeyUsageCount:   1000,
		MaxBroadcastKeyUsageTime:  24 * time.Hour,
		MaxBroadcastKeyUsageCount: 1<<16 - 1,
		MaxReplyTimeouts:          3,
	}
	if !controlling {
		s.MaxSessionKeyUsageTime *= 2
		s.MaxSessionKeyUsageCount *= 2
		s.MaxBroadcastKeyUsageTime *= 2
		s.MaxBroadcastKeyUsageCount *= 2
	}
	return s
}

// Validate refuses settings that cannot work.
func (s Settings) Validate() error {
	switch {
	case s.ExpectedReplyTime <= 0 || s.ExpectedReplyTime > time.Hour:
		return fmt.Errorf("iec60870sec: expected reply time must be above 0 and at most 1 h")
	case s.ExpectedRequestTime <= 0 || s.ExpectedRequestTime > 3*time.Hour:
		return fmt.Errorf("iec60870sec: expected request time must be above 0 and at most 3 h")
	case s.MaxReplyTimeouts < 1 || s.MaxReplyTimeouts > 255:
		return fmt.Errorf("iec60870sec: max reply timeouts must be 1 to 255")
	case s.MaxSessionKeyUsageTime < 0 || s.MaxBroadcastKeyUsageTime < 0:
		return fmt.Errorf("iec60870sec: key usage times cannot be negative")
	case s.MaxSessionKeyUsageTime > 2*7*24*time.Hour || s.MaxBroadcastKeyUsageTime > 2*7*24*time.Hour:
		return fmt.Errorf("iec60870sec: key usage times above two weeks (one week, doubled at the controlled station)")
	case s.MaxSessionKeyUsageCount < 1 || s.MaxBroadcastKeyUsageCount < 1:
		return fmt.Errorf("iec60870sec: key usage counts must be at least 1")
	case s.MaxSessionKeyUsageCount > BCRMax || s.MaxBroadcastKeyUsageCount > BCRMax:
		return fmt.Errorf("iec60870sec: key usage counts above 2^31-1")
	case s.MaxSessionKeyUsageTime == 0 && s.MaxSessionKeyUsageCount == 0:
		return fmt.Errorf("iec60870sec: the usage count is needed when the usage timer is disabled")
	}
	return nil
}
