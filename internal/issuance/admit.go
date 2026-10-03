package issuance

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"time"

	"tls-broker/internal/core"
)

// Admit implements core.Issuer (architecture §7.1 steps 4–7).
func (e *Engine) Admit(ctx context.Context, req core.AdmitRequest) (*core.Order, error) {
	cfg := e.cfg.Current()
	decision, err := e.checkRequest(ctx, cfg, core.ModeACME, req.SourceIP, req.Names, req.Decision)
	if err != nil {
		return nil, err
	}
	now := e.clock.Now()

	// 4. An open order of the same account for the same set is reused.
	if open, err := e.orders.FindOpen(ctx, req.AccountID, req.Names.Key(), now); err == nil {
		return open, nil
	} else if !errors.Is(err, core.ErrNotFound) {
		return nil, fmt.Errorf("issuance: find open order: %w", err)
	}

	cls, err := e.classify(ctx, cfg, req.Names, now)
	if err != nil {
		return nil, err
	}
	a, err := e.admit(ctx, cfg, admitParams{
		mode: core.ModeACME, accountID: req.AccountID, src: req.SourceIP, decision: decision,
		cls: cls, clientReplaces: req.Replaces, now: now,
	})
	if err != nil {
		return nil, err
	}
	// 7. Preparation runs in the background, detached from the request.
	e.spawn(func() { e.runOrder(a) })
	return a.order, nil
}

// admitParams are the inputs of admission shared by Admit and Issue.
type admitParams struct {
	mode           core.Mode
	accountID      string
	src            netip.Addr
	decision       core.Decision
	cls            classification
	clientReplaces string
	background     bool
	now            time.Time
}

// admitted is an admitted, persisted order and what its preparation needs.
type admitted struct {
	order *core.Order
	job   *job
	plan  plan
	// adopted is set when the order took over an abandoned upstream order:
	// preparation then only verifies it.
	adopted bool
}

// admit chooses the provider, obtains admission, and persists the order with
// its upstream intent (or adopting an abandoned upstream order). Nothing has
// been created upstream when it returns.
func (e *Engine) admit(ctx context.Context, cfg *core.Config, p admitParams) (*admitted, error) {
	plans, err := e.plans(ctx, cfg, p.cls, p.mode, p.background, p.clientReplaces, p.now)
	if err != nil {
		e.auditRefusal(ctx, p, err)
		return nil, err
	}
	// Freshly expired orders become adoptable.
	e.expireDue(ctx, p.now)

	id := core.NewID()
	var refusals []*core.AdmissionError
	for _, pl := range plans {
		for try := 0; try < 2; try++ {
			var donor *core.Order
			if try == 0 {
				d, err := e.orders.FindAdoptable(ctx, pl.provider.Name(), p.cls.key, p.now)
				switch {
				case err == nil:
					donor = d
				case !errors.Is(err, core.ErrNotFound):
					return nil, fmt.Errorf("issuance: find adoptable order: %w", err)
				}
			}
			ari := pl.ariQualified
			if donor != nil && donor.UpstreamReplaces != pl.replaces {
				ari = false // the adopted order was not placed as an exempt renewal
			}
			class := pl.class
			if !ari {
				class = pl.plainClass
			}
			ticket, err := e.sched.Acquire(ctx, core.AdmissionRequest{
				Ref: id, Provider: pl.provider.Name(), Names: p.cls.set, Class: class,
				Renewal: p.cls.renewal, ARIQualified: ari, ReuseUpstreamOrder: donor != nil,
				MaxWait: cfg.Scheduler.AdmitWait,
			})
			if err != nil {
				if ae := core.AsAdmissionError(err); ae != nil {
					refusals = append(refusals, ae)
					break // next provider
				}
				return nil, err
			}

			now := e.clock.Now()
			o := &core.Order{
				ID: id, Mode: p.mode, AccountID: p.accountID, Names: p.cls.set, Replaces: p.clientReplaces,
				SourceIP: p.src, GrantID: p.decision.GrantID,
				Status: core.OrderReady, Prep: core.PrepIntent, Class: class, ARIQualified: ari,
				Provider: pl.provider.Name(), CreatedAt: now, ExpiresAt: now.Add(orderTTL(cfg)), UpdatedAt: now,
			}
			if donor != nil {
				err = e.orders.CreateAdopting(ctx, o, donor.ID)
				if errors.Is(err, core.ErrConflict) {
					// Someone adopted it first; admission was taken without
					// new-order budget, so give it back and ask again.
					ticket.Refund()
					continue
				}
			} else {
				err = e.orders.Create(ctx, o)
			}
			if err != nil {
				ticket.Refund()
				return nil, fmt.Errorf("issuance: persist order: %w", err)
			}

			j := newJob(id, ticket)
			e.addJob(j)
			a := &admitted{order: o, job: j, plan: pl, adopted: donor != nil}
			e.auditAdmission(ctx, p, a, refusals)
			e.log.Info("issuance: order admitted", "order", id, "mode", p.mode, "names", p.cls.set.Key(),
				"provider", pl.provider.Name(), "class", class.String(), "renewal", p.cls.renewal,
				"ari_qualified", ari, "replaces", pl.replaces, "adopted", donor != nil,
				"wait_ms", now.Sub(p.now).Milliseconds())
			return a, nil
		}
	}
	sum := summarize(refusals)
	if sum == nil {
		sum = &core.AdmissionError{Kind: core.AdmissionProviderDown, RetryAfter: downRetryAfter(cfg), Reason: "no provider could take the request"}
	}
	e.auditRefusal(ctx, p, sum)
	return nil, sum
}

func orderTTL(cfg *core.Config) time.Duration {
	if d := cfg.Scheduler.OrderTTL; d > 0 {
		return d
	}
	return 15 * time.Minute
}

// auditAdmission records the admitted order and, when a fallback provider
// was chosen, a failover event.
func (e *Engine) auditAdmission(ctx context.Context, p admitParams, a *admitted, refusals []*core.AdmissionError) {
	o := a.order
	var parts []string
	switch {
	case p.cls.renewal && a.plan.ariQualified:
		parts = append(parts, "ARI-qualified renewal")
	case p.cls.renewal:
		parts = append(parts, "renewal")
	default:
		parts = append(parts, "new certificate")
	}
	if p.cls.emergency {
		parts = append(parts, fmt.Sprintf("emergency window %s", p.cls.window.Round(time.Minute)))
	}
	if a.plan.replaces != "" {
		parts = append(parts, "replaces "+a.plan.replaces)
	}
	if a.adopted {
		parts = append(parts, "adopted upstream order")
	}
	parts = append(parts, "class "+o.Class.String())
	ev := orderEvent(core.AuditOrder, o)
	ev.Decision, ev.Reason, ev.Result = core.AuditDecisionAllow, p.decision.Reason, core.AuditResultOK
	ev.Detail = strings.Join(parts, "; ")
	e.audit(ctx, ev)

	if a.plan.failover != "" {
		fo := orderEvent(core.AuditFailover, o)
		fo.Result = core.AuditResultOK
		fo.Reason = core.ReasonProviderUnavailable
		detail := a.plan.failover
		for _, r := range refusals {
			detail += fmt.Sprintf("; %s: %s (%s)", r.Provider, r.Kind, r.Reason)
		}
		fo.Detail = detail
		e.audit(ctx, fo)
	}
}

// auditRefusal records a request no provider admitted: a refused order.
func (e *Engine) auditRefusal(ctx context.Context, p admitParams, err error) {
	ev := core.AuditEvent{Type: core.AuditOrder, Mode: p.mode,
		SourceIP: ipString(p.src), Names: p.cls.set.Names(), Decision: core.AuditDecisionDeny,
		Result: core.AuditResultDenied, GrantID: p.decision.GrantID, Reason: core.ReasonRateLimited}
	if ae := core.AsAdmissionError(err); ae != nil {
		ev.Provider = ae.Provider
		if ae.Kind == core.AdmissionProviderDown {
			ev.Reason = core.ReasonProviderUnavailable
		}
		ev.Detail = fmt.Sprintf("%s; retry after %s", ae.Reason, ae.RetryAfter.Round(time.Second))
	} else {
		ev.Detail = err.Error()
	}
	e.audit(ctx, ev)
}
