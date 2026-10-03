package sched

import (
	"context"
	"fmt"
	"time"

	"tls-broker/internal/core"
)

// maxLastError bounds the error text kept in ProviderState.LastError.
const maxLastError = 300

// ReportProvider implements core.Scheduler.
//
//   - rate_limited: admission closed (rate_limited) for the provider's
//     RetryAfter, or SchedulerConfig.RateLimitRetryAfter when it gave none;
//   - busy: closed (rate_limited) for RetryAfter, or BusyRetryAfter;
//   - down: closed (down) for RetryAfter, or DownRetryAfter doubled for
//     each consecutive failure after the first, capped at
//     DownRetryAfterMax;
//   - nil: the failure count is reset and a closure whose time has passed
//     becomes healthy.
//
// A new closure never shortens one that is already in force. Closing
// admission fails every request waiting for a slot of that provider.
func (s *Scheduler) ReportProvider(ctx context.Context, name string, err error) {
	pe := core.AsProviderError(err)
	if err != nil && (pe == nil || !pe.AffectsHealth()) {
		return
	}
	s.stateMu.Lock()
	defer s.stateMu.Unlock()

	s.mu.Lock()
	s.refreshLocked()
	p := s.provider(name)
	now := s.clock.Now()
	old := p.state
	st := old
	st.Name = name
	if st.Health == "" {
		st.Health = core.ProviderHealthy
	}
	p.probe = nil
	if err == nil {
		st.Failures = 0
		if st.Health != core.ProviderHealthy && !now.Before(st.RetryAfter) {
			st.Health, st.RetryAfter, st.LastError = core.ProviderHealthy, time.Time{}, ""
		}
	} else {
		st.Failures++
		health, d := s.closure(pe, st.Failures)
		until := now.Add(d)
		if old.OpenAt(now) || until.After(old.RetryAfter) {
			st.Health, st.RetryAfter = health, until
		}
		st.LastError = truncate(err.Error(), maxLastError)
	}
	changed := st.Health != old.Health || !st.RetryAfter.Equal(old.RetryAfter) ||
		st.Failures != old.Failures || st.LastError != old.LastError
	if !changed {
		s.mu.Unlock()
		return
	}
	st.UpdatedAt = now
	p.state = st
	wasOpen, isOpen := old.OpenAt(now), st.OpenAt(now)
	if !isOpen {
		s.failWaitersLocked(p, s.circuitLocked(p, now))
	}
	s.mu.Unlock()

	if perr := s.states.Put(context.WithoutCancel(ctx), &st); perr != nil {
		s.log.Error("sched: persist provider state", "provider", name, "err", perr)
	}
	if s.auditor != nil && (wasOpen != isOpen || (old.Health != st.Health && st.Health == core.ProviderHealthy)) {
		ev := core.AuditEvent{Type: core.AuditProviderState, Provider: name}
		if isOpen {
			ev.Result = core.AuditResultOK
			ev.Detail = "admission open"
		} else {
			ev.Result = core.AuditResultFailed
			ev.Reason = core.ReasonProviderUnavailable
			if st.Health == core.ProviderLimited {
				ev.Reason = core.ReasonRateLimited
			}
			ev.Detail = fmt.Sprintf("admission closed until %s: %s", st.RetryAfter.Format(time.RFC3339), st.LastError)
		}
		s.auditor.Record(context.WithoutCancel(ctx), ev)
	}
}

// closure returns the health and closure length for a health-affecting
// provider error; failures counts this one.
func (s *Scheduler) closure(pe *core.ProviderError, failures int) (core.ProviderHealth, time.Duration) {
	sc := s.cfg.Scheduler
	switch pe.Kind {
	case core.ProviderRateLimited:
		return core.ProviderLimited, orDefault(pe.RetryAfter, sc.RateLimitRetryAfter, defaultRateLimitRetryAfter)
	case core.ProviderBusy:
		return core.ProviderLimited, orDefault(pe.RetryAfter, sc.BusyRetryAfter, defaultBusyRetryAfter)
	}
	if pe.RetryAfter > 0 {
		return core.ProviderUnavailable, pe.RetryAfter
	}
	base := orDefault(sc.DownRetryAfter, defaultDownRetryAfter)
	ceiling := orDefault(sc.DownRetryAfterMax, defaultDownRetryAfterMax)
	d := base
	for i := 1; i < failures && d < ceiling; i++ {
		d *= 2
	}
	return core.ProviderUnavailable, min(d, max(ceiling, base))
}

// orDefault returns the first positive duration.
func orDefault(ds ...time.Duration) time.Duration {
	for _, d := range ds {
		if d > 0 {
			return d
		}
	}
	return 0
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
