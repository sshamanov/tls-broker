package issuance

import (
	"context"
	"errors"
	"fmt"
	"time"

	"tls-broker/internal/core"
)

// Recover implements core.Issuer: architecture §20 for every non-terminal
// order, then settlement of reservations that belong to no live order.
//
//	intent, no upstream URL        -> invalid; new-order budget counted as spent
//	direct, preparing or ready     -> invalid, refunded (prepared stays adoptable)
//	direct, processing             -> ask the CA: CSR arrived -> finish (certificate
//	                                  stored, budget committed); not arrived -> invalid,
//	                                  refunded; unknown -> invalid, budget committed
//	acme, preparing                -> resume preparation in the background
//	acme, prepared, processing     -> resume finalize in the background
//	acme, prepared, ready          -> wait for the client's CSR (or expiry)
func (e *Engine) Recover(ctx context.Context) error {
	active, err := e.orders.ListActive(ctx)
	if err != nil {
		return fmt.Errorf("issuance: list active orders: %w", err)
	}
	live := map[string]bool{}
	for i := range active {
		o := &active[i]
		live[o.ID] = true
		ticket := e.reattach(ctx, o.ID)
		switch {
		case o.UpstreamOrderURL == "" || o.Prep == core.PrepIntent:
			// The upstream call may or may not have happened: count the
			// order as created, never create another.
			ticket.OrderCreated()
			e.recoverFail(ctx, o, ticket, "broker restarted before the upstream order was recorded")
		case o.Prep == core.PrepFailed:
			e.recoverFail(ctx, o, ticket, "broker restarted after preparation failed")
		case o.Mode == core.ModeDirect && o.Status == core.OrderProcessing:
			// The CSR was recorded and may have reached the CA. The key that
			// signed it is gone with the process, but a certificate the CA
			// issued is real: its budget is spent and it is the lineage's
			// predecessor for `replaces`. Ask the CA before deciding.
			j := newJob(o.ID, ticket)
			j.prepared, j.finalize, j.running = true, true, true
			j.prepOnce.Do(func() { close(j.prepDone) })
			e.addJob(j)
			order := *o
			e.spawn(func() { e.recoverDirectFinalize(j, &order) })
		case o.Mode == core.ModeDirect:
			// The requester's key context is gone; direct mode issues again
			// when asked. A prepared upstream order stays adoptable.
			e.recoverFail(ctx, o, ticket, "broker restarted during direct-mode issuance")
		case o.Prep == core.PrepPreparing:
			j := newJob(o.ID, ticket)
			j.finalize, j.running = o.Finalized(), true
			e.addJob(j)
			order := *o
			e.spawn(func() { e.runResumed(j, &order) })
		case o.Status == core.OrderProcessing:
			j := newJob(o.ID, ticket)
			j.prepared, j.finalize, j.running = true, true, true
			j.prepOnce.Do(func() { close(j.prepDone) })
			e.addJob(j)
			e.spawn(func() { e.finalizeOrder(j) })
		default:
			j := newJob(o.ID, ticket)
			j.prepared = true
			j.prepOnce.Do(func() { close(j.prepDone) })
			e.addJob(j)
		}
	}

	refs, err := e.sched.OpenRefs(ctx)
	if err != nil {
		return fmt.Errorf("issuance: open reservations: %w", err)
	}
	for _, ref := range refs {
		if live[ref] {
			continue
		}
		t, err := e.sched.Reattach(ctx, ref)
		if err != nil {
			continue
		}
		o, err := e.orders.Get(ctx, ref)
		if err == nil && o.Status == core.OrderValid {
			t.Commit()
		} else {
			t.Refund()
		}
		e.log.Info("issuance: settled orphaned reservation", "ref", ref, "committed", err == nil && o.Status == core.OrderValid)
	}
	return nil
}

// runResumed is the background life of an order found preparing at startup.
func (e *Engine) runResumed(j *job, o *core.Order) {
	ctx, cancel := e.bgContext()
	defer cancel()
	if err := e.resume(ctx, j, o); err != nil {
		return
	}
	if j.markPrepared() {
		e.finalizeOrder(j)
	}
}

// recoverDirectFinalize settles a direct-mode order found processing at
// startup. When the CA already has the CSR the issuance is finished like an
// ACME one (the certificate is stored and the budget committed; the direct
// cache issues again on the next fetch with that certificate as predecessor).
// When the CA never received it the order is failed and refunded. When the CA
// cannot be asked the certificate budget is counted as spent (architecture
// §10: over-counting is the safe error) and the order is failed.
func (e *Engine) recoverDirectFinalize(j *job, o *core.Order) {
	ctx, cancel := e.bgContext()
	defer cancel()
	p, err := e.provider(o.Provider)
	if err != nil {
		e.failOrder(ctx, j, o, err)
		return
	}
	up, err := p.GetOrder(ctx, o.UpstreamOrderURL)
	e.report(ctx, p.Name(), err)
	switch {
	case err != nil:
		if !(isCtxErr(err) && e.closing()) {
			j.getTicket().Commit()
		}
		e.failOrder(ctx, j, o, err)
	case up.Status == core.UpstreamProcessing || up.Status == core.UpstreamValid:
		e.finalizeOrder(j)
	default:
		e.failOrder(ctx, j, o, core.NewProblem(core.ProblemServerInternal,
			"broker restarted during direct-mode issuance before the CSR reached the certificate authority"))
	}
}

// recoverFail ends an order that cannot be resumed.
func (e *Engine) recoverFail(ctx context.Context, o *core.Order, ticket core.Ticket, why string) {
	problem := core.NewProblem(core.ProblemServerInternal, "%s", why)
	if err := e.orders.Fail(ctx, o.ID, problem, e.clock.Now()); err != nil && !errors.Is(err, core.ErrConflict) {
		e.log.Error("issuance: recovery: mark order invalid", "order", o.ID, "err", err)
	}
	e.cleanupDNS(ctx, core.OrderOwner(o.ID))
	ticket.Refund()
	ev := orderEvent(core.AuditIssue, o)
	ev.Visibility, ev.Result, ev.Detail = core.AuditVisibilityAdmin, core.AuditResultFailed, why
	e.audit(ctx, ev)
	e.log.Warn("issuance: recovery failed order", "order", o.ID, "status", o.Status, "prep", o.Prep, "why", why)
}

// Sweep implements core.Issuer: expire orders that never received a CSR
// (refund, remove TXT values, leave a prepared upstream order adoptable),
// then compact finished orders and old chains.
func (e *Engine) Sweep(ctx context.Context) error {
	now := e.clock.Now()
	if err := e.expireDue(ctx, now); err != nil {
		return err
	}
	if _, err := e.orders.Prune(ctx, now.Add(-KeepFinishedOrders)); err != nil {
		return fmt.Errorf("issuance: prune orders: %w", err)
	}
	if _, err := e.certs.DropChains(ctx, now.Add(-KeepExpiredChains)); err != nil {
		return fmt.Errorf("issuance: drop chains: %w", err)
	}
	return nil
}

// expireDue ends every order past its TTL that never received a CSR: the
// reservation is refunded, TXT values are removed, a waiting Finalize is
// woken. The store keeps a prepared upstream order adoptable.
func (e *Engine) expireDue(ctx context.Context, now time.Time) error {
	expired, err := e.orders.ExpireDue(ctx, now)
	if err != nil {
		return fmt.Errorf("issuance: expire orders: %w", err)
	}
	for i := range expired {
		o := &expired[i]
		var ticket core.Ticket
		if j := e.takeJob(o.ID); j != nil {
			ticket = j.getTicket()
			j.finish()
		} else {
			ticket = e.reattach(ctx, o.ID)
		}
		ticket.Refund()
		e.cleanupDNS(ctx, core.OrderOwner(o.ID))
		ev := orderEvent(core.AuditOrder, o)
		ev.Visibility, ev.Result = core.AuditVisibilityAdmin, core.AuditResultFailed
		ev.Detail = "order expired without a CSR"
		if o.Prep == core.PrepPrepared {
			ev.Detail += "; upstream order kept for adoption"
		}
		e.audit(ctx, ev)
		e.log.Info("issuance: order expired", "order", o.ID, "prep", o.Prep)
	}
	return nil
}
