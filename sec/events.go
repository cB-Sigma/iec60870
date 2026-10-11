package sec

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"sync/atomic"
	"time"

	"github.com/cB-Sigma/iotsec"
)

var recorder atomic.Pointer[recorderBox]

type recorderBox struct{ r iotsec.Auditor }

// SetAuditor installs the security log the IEC 62351-5 events of every
// endpoint (through LogEvents) are recorded to; nil records them to the
// slog logger only. It is process-wide.
func SetAuditor(a iotsec.Auditor) {
	if a == nil {
		recorder.Store(nil)
		return
	}
	recorder.Store(&recorderBox{a})
}

// LogEvents returns a Stats.Event function that writes each security event
// (IEC 62351-5 Table 7, Annex A) to log and to the security log of
// SetAuditor. subject names the station; no key material is included.
func LogEvents(log *slog.Logger, subject string) func(Event) {
	return func(ev Event) {
		attrs := []any{"event", ev.Mnemonic, "severity", ev.Severity, "id", ev.ID, "station", subject, "count", ev.Count}
		msg := "IEC 62351-5 security event: " + ev.Stat.String()
		switch ev.Severity {
		case "alarm":
			log.Error(msg, attrs...)
		case "warning":
			log.Warn(msg, attrs...)
		default:
			log.Info(msg, attrs...)
		}
		b := recorder.Load()
		if b == nil {
			return
		}
		out := iotsec.OutcomeFailure
		if ev.Severity == "notice" {
			out = iotsec.OutcomeSuccess
		}
		b.r.RecordSecurity(context.Background(), iotsec.SecurityEvent{Category: "communication", Event: strings.ToLower(ev.Mnemonic),
			Outcome: out, Actor: "system", Subject: subject, Method: "iec62351-5",
			Detail: map[string]string{"severity": ev.Severity, "iec62351_14_id": ev.ID, "statistic": ev.Stat.String(), "count": fmt.Sprint(ev.Count)}})
	}
}

// Ticker runs e.Tick until ctx ends.
func Ticker(ctx context.Context, e *Endpoint, every time.Duration) {
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-t.C:
			e.Tick(now)
		}
	}
}
