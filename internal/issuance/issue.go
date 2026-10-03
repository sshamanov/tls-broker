package issuance

import (
	"context"
	"errors"

	"tls-broker/internal/core"
	"tls-broker/internal/names"
)

// Issue implements core.Issuer: one synchronous direct-mode issuance
// (architecture §3.3, §11). Admission and preparation run under the caller's
// context: if it ends before the CSR is sent the attempt is failed and
// refunded. Once the CSR is recorded, finalize runs in the background and
// Issue only waits for it; a caller that leaves then gets its context error
// while the certificate is still stored.
func (e *Engine) Issue(ctx context.Context, req core.IssueRequest) (*core.Certificate, error) {
	cfg := e.cfg.Current()
	set, err := names.NewSet(req.Identifier)
	if err != nil {
		return nil, core.ProblemFromError(err)
	}
	decision, err := e.checkRequest(ctx, cfg, core.ModeDirect, req.SourceIP, set, req.Decision)
	if err != nil {
		return nil, err
	}
	if _, err := parseCSR(req.CSRDER, set); err != nil {
		return nil, err
	}
	now := e.clock.Now()
	cls, err := e.classify(ctx, cfg, set, now)
	if err != nil {
		return nil, err
	}
	a, err := e.admit(ctx, cfg, admitParams{
		mode: core.ModeDirect, src: req.SourceIP, decision: decision, cls: cls,
		background: req.Background, now: now,
	})
	if err != nil {
		return nil, err
	}

	// Preparation, bounded by the caller.
	if a.adopted {
		err = e.resume(ctx, a.job, a.order)
	} else {
		err = e.prepare(ctx, a.job, a.order, a.plan)
	}
	if err != nil {
		return nil, clientError(err)
	}
	a.job.markPrepared()

	// The CSR is recorded: from here the issuance completes on its own.
	o, first, err := e.orders.BeginFinalize(ctx, a.order.ID, core.CSRHash(req.CSRDER), req.CSRDER, e.clock.Now())
	if err != nil {
		return nil, clientError(e.failOrder(ctx, a.job, a.order, err))
	}
	if !first || !a.job.requestFinalize() {
		// Cannot happen for a fresh order; be loud rather than silent.
		return nil, clientError(e.failOrder(ctx, a.job, o, errors.New("issuance: direct order finalized twice")))
	}
	type result struct {
		cert *core.Certificate
		err  error
	}
	ch := make(chan result, 1)
	e.spawn(func() {
		c, err := e.finalizeOrder(a.job)
		ch <- result{c, err}
	})
	select {
	case r := <-ch:
		if r.err != nil {
			return nil, clientError(r.err)
		}
		return r.cert, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// clientError maps the cause of a failed direct issuance to the Issuer's
// error vocabulary: provider, admission and context errors as they are,
// anything else as the Problem stored on the order.
func clientError(err error) error {
	if err == nil {
		return nil
	}
	if core.AsProviderError(err) != nil || core.AsAdmissionError(err) != nil || core.AsProblem(err) != nil || isCtxErr(err) ||
		errors.Is(err, core.ErrExpired) || errors.Is(err, core.ErrNotFound) {
		return err
	}
	return failureProblem(err)
}
