package issuance

import (
	"context"
	"errors"
	"fmt"
	"time"

	"tls-broker/internal/core"
	"tls-broker/internal/names"
)

// classification is what the engine knows about a lineage before choosing a
// provider (architecture §8).
type classification struct {
	set     names.Set
	key     string
	lineage core.Lineage
	// newest is the newest certificate of the lineage from any provider;
	// nil for a first issuance.
	newest *core.Certificate
	// renewal: a certificate of this lineage exists.
	renewal bool
	// emergency: now is inside the emergency window of the newest
	// certificate (or past its expiry).
	emergency bool
	// window is the emergency window that was applied.
	window time.Duration
}

// classify observes the request on the lineage and classifies it.
func (e *Engine) classify(ctx context.Context, cfg *core.Config, set names.Set, now time.Time) (classification, error) {
	c := classification{set: set, key: set.Key()}
	lin, err := e.lineages.Observe(ctx, c.key, now)
	if err != nil {
		return c, fmt.Errorf("issuance: lineage: %w", err)
	}
	c.lineage = lin
	newest, err := e.certs.Newest(ctx, c.key, "")
	switch {
	case errors.Is(err, core.ErrNotFound):
		return c, nil
	case err != nil:
		return c, fmt.Errorf("issuance: newest certificate: %w", err)
	}
	c.newest, c.renewal = newest, true
	c.window = core.EmergencyWindow(cfg.Emergency, newest.Lifetime(), lin.Interval(cfg.Emergency.DefaultInterval))
	c.emergency = !now.Before(newest.NotAfter.Add(-c.window))
	return c, nil
}

// plan is one provider the engine may ask for admission, with everything
// that depends on the provider.
type plan struct {
	provider core.Provider
	// predecessor is the certificate to name in `replaces`; nil for none.
	predecessor *core.Certificate
	replaces    string
	// ariQualified: the provider exempts ARI renewals and now is inside the
	// predecessor's suggested window.
	ariQualified bool
	class        core.PriorityClass
	// plainClass is the class to use when the order loses its ARI
	// qualification (alreadyReplaced retry).
	plainClass core.PriorityClass
	// failover is non-empty when this plan is not the preferred provider:
	// the reason it is being tried, for the audit log.
	failover string
}

// plans returns the providers to try, in order (architecture §8/§9):
//
//	new certificate:  primary, then every other enabled provider
//	renewal:          the lineage's provider only — plus the others when
//	                  inside the emergency window (emergency switch)
//	lineage provider no longer enabled: like a new certificate
func (e *Engine) plans(ctx context.Context, cfg *core.Config, c classification, mode core.Mode, background bool, clientReplaces string, now time.Time) ([]plan, error) {
	enabled := e.providers.Enabled()
	if len(enabled) == 0 {
		return nil, &core.AdmissionError{Kind: core.AdmissionProviderDown, RetryAfter: downRetryAfter(cfg),
			Reason: "no upstream provider is enabled"}
	}
	var sticky core.Provider
	if c.renewal {
		for _, p := range enabled {
			if p.Name() == c.newest.Provider {
				sticky = p
			}
		}
	}
	var order []core.Provider
	switch {
	case sticky == nil:
		order = enabled
	case c.emergency:
		order = append([]core.Provider{sticky}, without(enabled, sticky)...)
	default:
		order = []core.Provider{sticky}
	}

	out := make([]plan, 0, len(order))
	for i, p := range order {
		pl := plan{provider: p}
		pl.predecessor, pl.replaces, pl.ariQualified = e.replacesFor(ctx, p, c, clientReplaces, now)
		pl.plainClass = priorityClass(mode, c, background, false)
		pl.class = priorityClass(mode, c, background, pl.ariQualified)
		switch {
		case i == 0 && sticky == nil && c.renewal:
			pl.failover = fmt.Sprintf("lineage provider %q is no longer enabled", c.newest.Provider)
		case i > 0 && sticky != nil:
			pl.failover = fmt.Sprintf("emergency switch from %q (%s of lifetime left)", sticky.Name(),
				c.newest.NotAfter.Sub(now).Round(time.Minute))
		case i > 0:
			pl.failover = fmt.Sprintf("primary %q refused the request", order[0].Name())
		}
		out = append(out, pl)
	}
	return out, nil
}

func without(list []core.Provider, p core.Provider) []core.Provider {
	out := make([]core.Provider, 0, len(list))
	for _, q := range list {
		if q != p {
			out = append(out, q)
		}
	}
	return out
}

// priorityClass applies architecture §10.
func priorityClass(mode core.Mode, c classification, background, ari bool) core.PriorityClass {
	if ari {
		return core.ClassARIRenewal
	}
	if mode == core.ModeDirect {
		switch {
		case c.renewal && c.emergency:
			return core.ClassDirectEmergency
		case background:
			return core.ClassDirectBackground
		default:
			return core.ClassDirectMiss
		}
	}
	if c.renewal && c.emergency {
		return core.ClassACMEEmergency
	}
	return core.ClassACMEOrdinary
}

// replacesFor resolves the predecessor to name in `replaces` for a provider
// (architecture §8 "ARI rules"): the client's `replaces` when it names a
// certificate the broker obtained from this provider that is unreplaced,
// unexpired and shares a name; otherwise the newest unreplaced certificate
// of the lineage from this provider. The predecessor must come from the
// provider's current account. ARI qualification needs the provider to
// exempt ARI renewals and now inside the suggested window.
func (e *Engine) replacesFor(ctx context.Context, p core.Provider, c classification, clientReplaces string, now time.Time) (pred *core.Certificate, replaces string, qualified bool) {
	caps := p.Caps()
	if !caps.ARI {
		return nil, "", false
	}
	if clientReplaces != "" {
		cert, err := e.certs.GetByARICertID(ctx, clientReplaces)
		if err == nil && cert.Provider == p.Name() && cert.ReplacedByID == "" &&
			cert.NotAfter.After(now) && cert.Names.Overlaps(c.set) {
			pred = cert
		}
	}
	if pred == nil {
		cert, err := e.certs.NewestUnreplaced(ctx, c.key, p.Name(), now)
		if err != nil {
			return nil, "", false
		}
		pred = cert
	}
	if pred.ARICertID == "" {
		return nil, "", false
	}
	if pred.AccountURL != "" {
		if acct, err := p.AccountURL(ctx); err == nil && acct != pred.AccountURL {
			// Issued by an earlier account: the CA would refuse `replaces`.
			return nil, "", false
		}
	}
	replaces = pred.ARICertID
	if caps.ARIExempt {
		if ri, err := e.fetchRenewalInfo(ctx, p, pred, now); err == nil && ri.InWindow(now) {
			qualified = true
		}
	}
	return pred, replaces, qualified
}

// downRetryAfter is the Retry-After used when no provider can be asked.
func downRetryAfter(cfg *core.Config) time.Duration {
	if d := cfg.Scheduler.DownRetryAfter; d > 0 {
		return d
	}
	return time.Minute
}

// summarize combines the refusals of every eligible provider into the one
// error the client sees: provider_down only when all were down, otherwise
// the rate_limited/busy refusal with the smallest Retry-After.
func summarize(refusals []*core.AdmissionError) *core.AdmissionError {
	if len(refusals) == 0 {
		return nil
	}
	allDown := true
	for _, r := range refusals {
		if r.Kind != core.AdmissionProviderDown {
			allDown = false
		}
	}
	var best *core.AdmissionError
	for _, r := range refusals {
		if !allDown && r.Kind == core.AdmissionProviderDown {
			continue
		}
		if best == nil || r.RetryAfter < best.RetryAfter {
			best = r
		}
	}
	out := *best
	if len(refusals) > 1 {
		out.Provider = ""
	}
	if out.RetryAfter <= 0 {
		out.RetryAfter = time.Minute
	}
	return &out
}
