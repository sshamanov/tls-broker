package issuance

import (
	"context"
	"errors"
	"fmt"
	"time"

	"tls-broker/internal/core"
)

// ariEntry is a cached renewal-information answer.
type ariEntry struct {
	info  core.RenewalInfo
	until time.Time
}

// RenewalInfo implements core.Issuer. A client asking about its certificate
// is the "check" signal of the lineage, so the request is observed before the
// provider is asked.
func (e *Engine) RenewalInfo(ctx context.Context, ariCertID string) (core.RenewalInfo, error) {
	cert, err := e.certs.GetByARICertID(ctx, ariCertID)
	if err != nil {
		return core.RenewalInfo{}, err
	}
	now := e.clock.Now()
	if _, err := e.lineages.Observe(ctx, cert.Names.Key(), now); err != nil {
		e.log.Warn("issuance: observe lineage", "set", cert.Names.Key(), "err", err)
	}
	p, ok := e.providers.Get(cert.Provider)
	if !ok {
		return core.RenewalInfo{}, fmt.Errorf("certificate %s: provider %q is not configured: %w", cert.ID, cert.Provider, core.ErrNotFound)
	}
	return e.fetchRenewalInfo(ctx, p, cert, now)
}

// fetchRenewalInfo returns the renewal information of a certificate from its
// provider, cached until the provider's Retry-After (or the configured ARI
// poll interval when the CA gives none). A provider without ARI, or one that
// does not know the certificate, gets a synthesized window.
func (e *Engine) fetchRenewalInfo(ctx context.Context, p core.Provider, cert *core.Certificate, now time.Time) (core.RenewalInfo, error) {
	cfg := e.cfg.Current()
	e.mu.Lock()
	ent, ok := e.ari[cert.ARICertID]
	e.mu.Unlock()
	if ok && now.Before(ent.until) {
		info := ent.info
		info.RetryAfter = ent.until.Sub(now)
		return info, nil
	}

	var info core.RenewalInfo
	if p.Caps().ARI && cert.ARICertID != "" {
		ri, err := p.RenewalInfo(ctx, cert.ARICertID)
		e.report(ctx, p.Name(), err)
		switch pe := core.AsProviderError(err); {
		case err == nil:
			info = ri
		case pe != nil && pe.Kind == core.ProviderRejected:
			info = e.synthesizeWindow(ctx, cfg, cert)
		default:
			return core.RenewalInfo{}, err
		}
	} else {
		info = e.synthesizeWindow(ctx, cfg, cert)
	}
	if info.RetryAfter <= 0 {
		info.RetryAfter = cfg.Direct.ARIPollInterval
		if info.RetryAfter <= 0 {
			info.RetryAfter = 6 * time.Hour
		}
	}
	e.mu.Lock()
	for id, c := range e.ari {
		if !now.Before(c.until) {
			delete(e.ari, id)
		}
	}
	e.ari[cert.ARICertID] = ariEntry{info: info, until: now.Add(info.RetryAfter)}
	e.mu.Unlock()
	return info, nil
}

// synthesizeWindow builds a renewal window for a certificate whose CA gives
// none: it opens at DirectConfig.RenewFraction of the lifetime and closes
// where the emergency window begins (architecture §8, §11).
func (e *Engine) synthesizeWindow(ctx context.Context, cfg *core.Config, cert *core.Certificate) core.RenewalInfo {
	life := cert.Lifetime()
	frac := cfg.Direct.RenewFraction
	if frac <= 0 || frac >= 1 {
		frac = 2.0 / 3.0
	}
	interval := cfg.Emergency.DefaultInterval
	if lin, err := e.lineages.Get(ctx, cert.Names.Key()); err == nil {
		interval = lin.Interval(cfg.Emergency.DefaultInterval)
	} else if !errors.Is(err, core.ErrNotFound) {
		e.log.Warn("issuance: read lineage", "set", cert.Names.Key(), "err", err)
	}
	start := cert.NotBefore.Add(time.Duration(frac * float64(life)))
	end := cert.NotAfter.Add(-core.EmergencyWindow(cfg.Emergency, life, interval))
	if !end.After(start) {
		end = start.Add(24 * time.Hour)
		if end.After(cert.NotAfter) {
			end = cert.NotAfter
		}
	}
	return core.RenewalInfo{WindowStart: start, WindowEnd: end}
}
