package issuance

import (
	"context"
	"errors"
	"fmt"
	"time"

	"tls-broker/internal/core"
)

// runOrder is the background life of an admitted ACME order: preparation,
// then finalize if the CSR arrived meanwhile. It is detached from the
// request that admitted the order.
func (e *Engine) runOrder(a *admitted) {
	ctx, cancel := e.bgContext()
	defer cancel()
	o := *a.order // the caller keeps the original
	var err error
	if a.adopted {
		err = e.resume(ctx, a.job, &o)
	} else {
		err = e.prepare(ctx, a.job, &o, a.plan)
	}
	if err != nil {
		return // failed or interrupted; already handled
	}
	if a.job.markPrepared() {
		e.finalizeOrder(a.job)
	}
}

// prepare creates the upstream order (architecture §7.1 "upstream
// preparation") and validates it. On a nil return the order is prepared and
// its slot released; on an error the order was failed or left for recovery.
//
// Crash safety: the order row (upstream intent) is already persisted and the
// ticket's OrderCreated is called before Provider.NewOrder, so the new-order
// budget is counted even if the process dies between the two.
func (e *Engine) prepare(ctx context.Context, j *job, o *core.Order, pl plan) error {
	p := pl.provider
	replaces := pl.replaces
	started := e.clock.Now()
	j.getTicket().OrderCreated()
	up, err := p.NewOrder(ctx, o.Names.Names(), replaces)
	e.report(ctx, p.Name(), err)
	e.log.Debug("issuance: upstream newOrder", "order", o.ID, "provider", p.Name(), "replaces", replaces,
		"upstream_order", up.URL, "status", up.Status, "err", err)

	if pe := core.AsProviderError(err); pe != nil && pe.Kind == core.ProviderAlreadyReplaced && replaces != "" {
		// Architecture §8: the predecessor already has a live replacement
		// order. Retry once without `replaces` as an ordinary renewal,
		// re-admitted so that the ordinary budgets are reserved.
		e.log.Info("issuance: replaces refused (alreadyReplaced), retrying as ordinary renewal",
			"order", o.ID, "provider", p.Name(), "replaces", replaces)
		j.getTicket().Refund()
		t, aerr := e.sched.Acquire(ctx, core.AdmissionRequest{
			Ref: o.ID, Provider: p.Name(), Names: o.Names, Class: pl.plainClass, Renewal: true,
		})
		if aerr != nil {
			return e.failOrder(ctx, j, o, aerr)
		}
		j.setTicket(t)
		t.OrderCreated()
		replaces = ""
		up, err = p.NewOrder(ctx, o.Names.Names(), "")
		e.report(ctx, p.Name(), err)
		e.log.Debug("issuance: upstream newOrder", "order", o.ID, "provider", p.Name(), "replaces", "",
			"upstream_order", up.URL, "status", up.Status, "err", err)
	}
	if err != nil {
		return e.failOrder(ctx, j, o, err)
	}

	if err := e.orders.SetUpstream(context.WithoutCancel(ctx), o.ID, up.URL, replaces, up.Expires, e.clock.Now()); err != nil {
		err = fmt.Errorf("record upstream order: %w", err)
		if cur, gerr := e.orders.Get(context.WithoutCancel(ctx), o.ID); gerr == nil && cur.Status.Terminal() {
			// The order ended (expired) between admission and here; the
			// upstream order cannot be attached to it and is left to
			// expire at the CA.
			return e.abandon(j, o, err)
		}
		// Still live (for example the CA returned an upstream order that a
		// live order already owns): fail it, or the client would poll a
		// processing order that nothing works on.
		return e.failOrder(ctx, j, o, err)
	}
	o.UpstreamOrderURL, o.UpstreamReplaces, o.UpstreamExpiresAt, o.Prep = up.URL, replaces, up.Expires, core.PrepPreparing
	return e.validate(ctx, j, o, p, up, started)
}

// resume continues preparation of an order whose upstream order exists: an
// adopted order, or one found after a restart. It asks the CA for the
// order's state and validates whatever is still pending.
func (e *Engine) resume(ctx context.Context, j *job, o *core.Order) error {
	p, err := e.provider(o.Provider)
	if err != nil {
		return e.failOrder(ctx, j, o, err)
	}
	started := e.clock.Now()
	up, err := p.GetOrder(ctx, o.UpstreamOrderURL)
	e.report(ctx, p.Name(), err)
	e.log.Debug("issuance: upstream getOrder", "order", o.ID, "provider", p.Name(), "upstream_order", o.UpstreamOrderURL,
		"status", up.Status, "err", err)
	if err != nil {
		return e.failOrder(ctx, j, o, err)
	}
	return e.validate(ctx, j, o, p, up, started)
}

// validate drives the upstream order to ready: DNS-01 for every pending
// authorization (all values presented, then all accepted once visible),
// wait for the CA, remove the TXT values, mark the order prepared. started
// is when preparation began, for the log.
func (e *Engine) validate(ctx context.Context, j *job, o *core.Order, p core.Provider, up core.UpstreamOrder, started time.Time) error {
	owner := core.OrderOwner(o.ID)
	if up.Status == core.UpstreamPending {
		chs, err := p.DNSChallenges(ctx, up)
		e.report(ctx, p.Name(), err)
		if err != nil {
			return e.failOrder(ctx, j, o, err)
		}
		e.log.Debug("issuance: presenting DNS-01 values", "order", o.ID, "challenges", len(chs))
		t0 := e.clock.Now()
		if err := e.present(ctx, owner, chs); err != nil {
			return e.failOrder(ctx, j, o, err)
		}
		e.log.Debug("issuance: DNS-01 values visible", "order", o.ID, "challenges", len(chs),
			"duration_ms", e.clock.Now().Sub(t0).Milliseconds())
		for _, ch := range chs {
			err := p.Accept(ctx, ch)
			e.report(ctx, p.Name(), err)
			e.log.Debug("issuance: upstream challenge accepted", "order", o.ID, "provider", p.Name(),
				"record", ch.RecordName, "challenge", ch.URL, "err", err)
			if err != nil {
				return e.failOrder(ctx, j, o, err)
			}
		}
		t0 = e.clock.Now()
		up, err = p.WaitReady(ctx, up.URL)
		e.report(ctx, p.Name(), err)
		e.log.Debug("issuance: upstream order validated", "order", o.ID, "provider", p.Name(), "status", up.Status,
			"duration_ms", e.clock.Now().Sub(t0).Milliseconds(), "err", err)
		if err != nil {
			return e.failOrder(ctx, j, o, err)
		}
	}
	e.cleanupDNS(ctx, owner)
	if up.Status == core.UpstreamInvalid {
		problem := up.Error
		if problem == nil {
			problem = core.NewProblem(core.ProblemMalformed, "upstream order is invalid")
		}
		return e.failOrder(ctx, j, o, &core.ProviderError{Provider: p.Name(), Kind: core.ProviderRejected, Problem: problem})
	}
	if err := e.orders.SetPrepared(context.WithoutCancel(ctx), o.ID, e.clock.Now()); err != nil {
		return e.abandon(j, o, fmt.Errorf("mark prepared: %w", err))
	}
	o.Prep = core.PrepPrepared
	j.getTicket().PrepDone()
	e.log.Info("issuance: order prepared", "order", o.ID, "provider", p.Name(), "names", o.Names.Key(),
		"upstream_order", up.URL, "duration_ms", e.clock.Now().Sub(started).Milliseconds())
	return nil
}

// present publishes every challenge value concurrently (a wildcard and its
// base name share one record and get two values) and returns once all are
// visible, or the first failure.
func (e *Engine) present(ctx context.Context, owner string, chs []core.UpstreamChallenge) error {
	if len(chs) == 0 {
		return nil
	}
	pctx, cancel := context.WithCancel(ctx)
	defer cancel()
	errs := make(chan error, len(chs))
	for _, ch := range chs {
		go func(ch core.UpstreamChallenge) {
			_, err := e.dns.Present(pctx, owner, ch.RecordName, ch.Value)
			errs <- err
		}(ch)
	}
	var first error
	for range chs {
		if err := <-errs; err != nil && first == nil {
			first = &dnsError{err}
			cancel() // the others stop presenting; the order fails anyway
		}
	}
	return first
}

// cleanupDNS removes every TXT value the order published. Failures are
// logged; the DNS engine's stale sweep catches what is left.
func (e *Engine) cleanupDNS(ctx context.Context, owner string) {
	if err := e.dns.CleanupOwner(context.WithoutCancel(ctx), owner); err != nil {
		e.log.Warn("issuance: cleanup DNS-01 values", "owner", owner, "err", err)
	}
}

// failOrder ends an order that cannot be issued: invalid with a problem,
// TXT values removed, reservation refunded, audited. When the cause is the
// engine shutting down the order is left in its persisted state for Recover
// instead. It always returns a non-nil error so callers stop.
func (e *Engine) failOrder(ctx context.Context, j *job, o *core.Order, cause error) error {
	if isCtxErr(cause) && e.closing() {
		e.log.Info("issuance: interrupted by shutdown, left for recovery", "order", o.ID)
		e.endJob(j)
		return cause
	}
	bctx := context.WithoutCancel(ctx)
	problem := failureProblem(cause)
	if err := e.orders.Fail(bctx, o.ID, problem, e.clock.Now()); err != nil {
		e.log.Error("issuance: mark order invalid", "order", o.ID, "err", err)
	}
	e.cleanupDNS(bctx, core.OrderOwner(o.ID))
	j.getTicket().Refund()
	ev := orderEvent(core.AuditIssue, o)
	ev.Result = core.AuditResultFailed
	ev.Reason = failureReason(cause)
	ev.Detail = problem.Error()
	if ev.Detail != cause.Error() {
		ev.Detail += " (" + cause.Error() + ")"
	}
	e.audit(bctx, ev)
	e.log.Warn("issuance: order failed", "order", o.ID, "provider", o.Provider, "names", o.Names.Key(), "err", cause)
	e.endJob(j)
	return cause
}

// abandon releases an order that ended (expired by Sweep) while a goroutine
// was still preparing it.
func (e *Engine) abandon(j *job, o *core.Order, err error) error {
	e.log.Warn("issuance: order ended during preparation", "order", o.ID, "err", err)
	j.getTicket().Refund()
	e.endJob(j)
	return err
}

// failureReason picks the audit reason for a failure.
func failureReason(err error) string {
	if ae := core.AsAdmissionError(err); ae != nil {
		if ae.Kind == core.AdmissionProviderDown {
			return core.ReasonProviderUnavailable
		}
		return core.ReasonRateLimited
	}
	if pe := core.AsProviderError(err); pe != nil {
		switch pe.Kind {
		case core.ProviderRateLimited:
			return core.ReasonRateLimited
		case core.ProviderBusy, core.ProviderDown:
			return core.ReasonProviderUnavailable
		}
	}
	if errors.Is(err, core.ErrDNSPropagation) {
		return core.ReasonDNSFailure
	}
	return ""
}
