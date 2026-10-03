package app

import (
	"context"
	"errors"
	"time"

	"tls-broker/internal/core"
	"tls-broker/internal/metrics"
)

// The engines below do not take a metrics.Recorder; these decorators record
// what docs/observability.md lists for them at the port boundary.

// meteredDNS records DNS-01 present durations and failures.
type meteredDNS struct {
	next  core.DNSEngine
	m     metrics.Recorder
	clock core.Clock
}

func (d *meteredDNS) Present(ctx context.Context, owner, record, value string) (string, error) {
	start := d.clock.Now()
	id, err := d.next.Present(ctx, owner, record, value)
	d.m.DNS01Present(d.clock.Now().Sub(start), err == nil)
	return id, err
}

func (d *meteredDNS) Cleanup(ctx context.Context, challengeID string) error {
	err := d.next.Cleanup(ctx, challengeID)
	if err != nil && !errors.Is(err, core.ErrNotFound) {
		d.m.DNS01CleanupFailure()
	}
	return err
}

func (d *meteredDNS) CleanupOwner(ctx context.Context, owner string) error {
	err := d.next.CleanupOwner(ctx, owner)
	if err != nil {
		d.m.DNS01CleanupFailure()
	}
	return err
}

func (d *meteredDNS) Reconcile(ctx context.Context) error { return d.next.Reconcile(ctx) }

// meteredProviders wraps every provider so failed upstream calls are counted
// by provider and error kind.
type meteredProviders struct {
	next core.Providers
	m    metrics.Recorder
}

func (p *meteredProviders) Get(name string) (core.Provider, bool) {
	pr, ok := p.next.Get(name)
	if !ok {
		return nil, false
	}
	return &meteredProvider{Provider: pr, m: p.m}, true
}

func (p *meteredProviders) Enabled() []core.Provider {
	list := p.next.Enabled()
	out := make([]core.Provider, len(list))
	for i, pr := range list {
		out[i] = &meteredProvider{Provider: pr, m: p.m}
	}
	return out
}

type meteredProvider struct {
	core.Provider
	m metrics.Recorder
}

func (p *meteredProvider) count(err error) {
	var pe *core.ProviderError
	if errors.As(err, &pe) {
		name := pe.Provider
		if name == "" {
			name = p.Name()
		}
		p.m.UpstreamError(name, pe.Kind)
	}
}

func (p *meteredProvider) AccountURL(ctx context.Context) (string, error) {
	u, err := p.Provider.AccountURL(ctx)
	p.count(err)
	return u, err
}

func (p *meteredProvider) NewOrder(ctx context.Context, names []string, replaces string) (core.UpstreamOrder, error) {
	o, err := p.Provider.NewOrder(ctx, names, replaces)
	p.count(err)
	return o, err
}

func (p *meteredProvider) GetOrder(ctx context.Context, orderURL string) (core.UpstreamOrder, error) {
	o, err := p.Provider.GetOrder(ctx, orderURL)
	p.count(err)
	return o, err
}

func (p *meteredProvider) DNSChallenges(ctx context.Context, order core.UpstreamOrder) ([]core.UpstreamChallenge, error) {
	c, err := p.Provider.DNSChallenges(ctx, order)
	p.count(err)
	return c, err
}

func (p *meteredProvider) Accept(ctx context.Context, ch core.UpstreamChallenge) error {
	err := p.Provider.Accept(ctx, ch)
	p.count(err)
	return err
}

func (p *meteredProvider) WaitReady(ctx context.Context, orderURL string) (core.UpstreamOrder, error) {
	o, err := p.Provider.WaitReady(ctx, orderURL)
	p.count(err)
	return o, err
}

func (p *meteredProvider) Finalize(ctx context.Context, orderURL string, csrDER []byte) (core.UpstreamOrder, error) {
	o, err := p.Provider.Finalize(ctx, orderURL, csrDER)
	p.count(err)
	return o, err
}

func (p *meteredProvider) WaitCertificate(ctx context.Context, orderURL string) ([]byte, error) {
	c, err := p.Provider.WaitCertificate(ctx, orderURL)
	p.count(err)
	return c, err
}

func (p *meteredProvider) RenewalInfo(ctx context.Context, ariCertID string) (core.RenewalInfo, error) {
	ri, err := p.Provider.RenewalInfo(ctx, ariCertID)
	p.count(err)
	return ri, err
}

// issueMetrics passes every event to the audit log and turns the issuance
// engine's "issue" events into tlsbroker_issuance_total and
// tlsbroker_issuance_duration_seconds (class and admission time come from
// the order row).
type issueMetrics struct {
	next   core.Auditor
	m      metrics.Recorder
	orders core.OrderStore
	clock  core.Clock
}

func (a *issueMetrics) Record(ctx context.Context, ev core.AuditEvent) {
	a.next.Record(ctx, ev)
	if ev.Type != core.AuditIssue || ev.OrderID == "" {
		return
	}
	var result metrics.IssueResult
	switch ev.Result {
	case core.AuditResultOK:
		result = metrics.IssueOK
	case core.AuditResultFailed:
		result = metrics.IssueFailed
	default:
		return
	}
	o, err := a.orders.Get(context.WithoutCancel(ctx), ev.OrderID)
	if err != nil {
		return
	}
	d := max(a.clock.Now().Sub(o.CreatedAt), time.Duration(0))
	a.m.Issuance(ev.Provider, ev.Mode, o.Class, result, d)
}
