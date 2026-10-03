package issuance

import (
	"context"
	"crypto"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"
	"time"

	"tls-broker/internal/core"
	"tls-broker/internal/names"
)

// Finalize implements core.Issuer (architecture §7.2).
func (e *Engine) Finalize(ctx context.Context, req core.FinalizeRequest) (*core.Order, error) {
	cfg := e.cfg.Current()
	o, err := e.orders.Get(ctx, req.OrderID)
	if err != nil {
		return nil, err
	}
	if o.Mode != core.ModeACME || o.AccountID != req.AccountID {
		return nil, fmt.Errorf("order %q for account %q: %w", req.OrderID, req.AccountID, core.ErrNotFound)
	}

	// 1. The gate again, for the address finalizing now: the front end's
	// decision when it ran the gate, otherwise the engine asks — except for
	// a retry of an already accepted CSR, which is a poll.
	d := req.Decision
	if !o.Finalized() && !d.Allowed && d.Reason == "" {
		if d, err = e.gate.Authorize(ctx, core.ModeACME, req.SourceIP, o.Names); err != nil {
			return nil, fmt.Errorf("issuance: gate: %w", err)
		}
	}
	if !o.Finalized() && !d.Allowed {
		ev := orderEvent(core.AuditGate, o)
		ev.SourceIP, ev.Visibility = ipString(req.SourceIP), core.AuditVisibilityAdmin
		ev.Decision, ev.Reason, ev.Result, ev.Detail = core.AuditDecisionDeny, d.Reason, core.AuditResultDenied, "finalize: "+d.Detail
		e.audit(ctx, ev)
		return nil, denied(d)
	}

	// 2–3. The CSR: well-formed, signed, exactly the order's identifiers.
	if _, err := parseCSR(req.CSRDER, o.Names); err != nil {
		return nil, err
	}

	// 4. Idempotency by CSR hash. From here the CSR is persisted and the
	// issuance runs to completion without the client.
	now := e.clock.Now()
	o, first, err := e.orders.BeginFinalize(ctx, o.ID, core.CSRHash(req.CSRDER), req.CSRDER, now)
	if err != nil {
		return nil, err
	}
	if o.Status.Terminal() {
		return o, nil
	}
	j := e.lookupJob(o.ID)
	if first {
		if j == nil {
			// Nothing in memory: the order was prepared and nobody has
			// touched it since (its reservation may survive from before a
			// restart).
			j = newJob(o.ID, e.reattach(ctx, o.ID))
			if o.Prep == core.PrepPrepared {
				j.prepared = true
				j.prepOnce.Do(func() { close(j.prepDone) })
			}
			e.addJob(j)
		}
		if j.requestFinalize() {
			e.spawn(func() { e.finalizeOrder(j) })
		}
	}

	// 5. Hold the request for a bounded time; "processing" tells the
	// client to poll.
	return e.waitOrder(ctx, j, o.ID, cfg.Scheduler.FinalizeWait)
}

// waitOrder waits until the order's job ends, d has passed on the clock, or
// ctx is done, and returns the order as it is then.
func (e *Engine) waitOrder(ctx context.Context, j *job, id string, d time.Duration) (*core.Order, error) {
	if j != nil {
		select {
		case <-j.done:
		case <-e.clock.After(d):
		case <-ctx.Done():
		}
	}
	return e.orders.Get(context.WithoutCancel(ctx), id)
}

// finalizeOrder sends the recorded CSR upstream, waits for the certificate,
// verifies it and stores it (architecture §7.2 steps 6–8). It runs under a
// background context: once a CSR is recorded the issuance finishes whether
// or not the client is still waiting. It returns the certificate with its
// chain, or the cause of failure (the order is then invalid, or left for
// recovery when the engine is shutting down).
func (e *Engine) finalizeOrder(j *job) (*core.Certificate, error) {
	ctx, cancel := e.bgContext()
	defer cancel()

	o, err := e.orders.Get(ctx, j.id)
	if err != nil {
		e.log.Error("issuance: load order for finalize", "order", j.id, "err", err)
		e.endJob(j)
		return nil, err
	}
	if o.Status != core.OrderProcessing || o.UpstreamOrderURL == "" || len(o.CSRDER) == 0 {
		err := fmt.Errorf("issuance: order %s cannot be finalized (status %s, prep %s)", o.ID, o.Status, o.Prep)
		e.endJob(j)
		return nil, err
	}
	p, err := e.provider(o.Provider)
	if err != nil {
		return nil, e.failOrder(ctx, j, o, err)
	}
	csr, err := x509.ParseCertificateRequest(o.CSRDER)
	if err != nil {
		return nil, e.failOrder(ctx, j, o, core.NewProblem(core.ProblemBadCSR, "stored CSR cannot be parsed"))
	}

	started := e.clock.Now()
	_, err = p.Finalize(ctx, o.UpstreamOrderURL, o.CSRDER)
	e.report(ctx, p.Name(), err)
	e.log.Debug("issuance: upstream finalize (CSR sent)", "order", o.ID, "provider", p.Name(),
		"upstream_order", o.UpstreamOrderURL, "err", err)
	if err != nil {
		if pe := core.AsProviderError(err); (pe != nil && pe.AffectsHealth()) || isCtxErr(err) {
			if isCtxErr(err) && e.closing() {
				return nil, e.failOrder(ctx, j, o, err) // left for recovery
			}
			// The CSR may have been accepted: ask before giving up.
			got, gerr := p.GetOrder(ctx, o.UpstreamOrderURL)
			e.report(ctx, p.Name(), gerr)
			if gerr == nil && (got.Status == core.UpstreamProcessing || got.Status == core.UpstreamValid) {
				err = nil
			}
		}
		if err != nil {
			return nil, e.failOrder(ctx, j, o, err)
		}
	}

	chain, err := p.WaitCertificate(ctx, o.UpstreamOrderURL)
	e.report(ctx, p.Name(), err)
	e.log.Debug("issuance: upstream certificate", "order", o.ID, "provider", p.Name(), "bytes", len(chain),
		"duration_ms", e.clock.Now().Sub(started).Milliseconds(), "err", err)
	if err != nil {
		return nil, e.failOrder(ctx, j, o, err)
	}
	now := e.clock.Now()
	leaf, err := verifyChain(chain, csr, o.Names, now)
	if err != nil {
		return nil, e.failOrder(ctx, j, o, core.NewProblem(core.ProblemServerInternal,
			"the certificate returned by the certificate authority failed verification: %v", err))
	}

	cert := &core.Certificate{
		ID: core.NewID(), OrderID: o.ID, Mode: o.Mode, Names: o.Names, Provider: o.Provider,
		Serial: serialHex(leaf), NotBefore: leaf.NotBefore, NotAfter: leaf.NotAfter, IssuedAt: now, ChainPEM: chain,
	}
	if id, err := core.ARICertID(leaf); err == nil {
		cert.ARICertID = id
	}
	if acct, err := p.AccountURL(ctx); err == nil {
		cert.AccountURL = acct
	}
	if o.UpstreamReplaces != "" {
		if pred, err := e.certs.GetByARICertID(ctx, o.UpstreamReplaces); err == nil {
			cert.ReplacesID = pred.ID
		}
	}

	bctx := context.WithoutCancel(ctx)
	if err := e.orders.Complete(bctx, o.ID, cert, now); err != nil {
		// The certificate exists at the CA: its budget is spent whatever
		// happened locally.
		j.getTicket().Commit()
		return nil, e.failOrder(bctx, j, o, fmt.Errorf("store certificate: %w", err))
	}
	j.getTicket().Commit()

	ev := orderEvent(core.AuditIssue, o)
	ev.Decision, ev.Result, ev.CertificateID = core.AuditDecisionAllow, core.AuditResultOK, cert.ID
	notAfter := cert.NotAfter
	ev.CertNotAfter = &notAfter
	detail := "serial " + cert.Serial
	if cert.ReplacesID != "" {
		detail += "; replaces certificate " + cert.ReplacesID
	}
	if o.ARIQualified {
		detail += "; ARI-qualified"
	}
	ev.Detail = detail
	e.audit(bctx, ev)
	e.log.Info("issuance: certificate issued", "order", o.ID, "provider", o.Provider, "names", o.Names.Key(),
		"not_after", cert.NotAfter, "certificate", cert.ID, "serial", cert.Serial,
		"finalize_ms", now.Sub(started).Milliseconds(), "order_age_ms", now.Sub(o.CreatedAt).Milliseconds())
	e.endJob(j)
	return cert, nil
}

// parseCSR checks a finalize CSR: it parses, its signature verifies, it has
// only DNS names, and those (plus the common name) are exactly the order's
// identifier set. Violations are badCSR problems.
func parseCSR(der []byte, set names.Set) (*x509.CertificateRequest, error) {
	csr, err := x509.ParseCertificateRequest(der)
	if err != nil {
		return nil, core.NewProblem(core.ProblemBadCSR, "the CSR cannot be parsed")
	}
	if err := csr.CheckSignature(); err != nil {
		return nil, core.NewProblem(core.ProblemBadCSR, "the CSR signature is invalid")
	}
	if len(csr.IPAddresses)+len(csr.EmailAddresses)+len(csr.URIs) > 0 {
		return nil, core.NewProblem(core.ProblemBadCSR, "the CSR contains identifiers that are not DNS names")
	}
	raw := append([]string(nil), csr.DNSNames...)
	if cn := strings.TrimSpace(csr.Subject.CommonName); cn != "" {
		raw = append(raw, cn)
	}
	got, err := names.NewSet(raw...)
	if err != nil {
		return nil, core.NewProblem(core.ProblemBadCSR, "the CSR names are invalid: %v", err)
	}
	if !got.Equal(set) {
		return nil, core.NewProblem(core.ProblemBadCSR, "the CSR names (%s) do not match the order identifiers (%s)", got.Key(), set.Key())
	}
	return csr, nil
}

// verifyChain checks what the CA returned (architecture §7.2 step 7): a PEM
// chain whose leaf carries the CSR's public key and exactly the order's
// names, is not expired, and whose links verify.
func verifyChain(chainPEM []byte, csr *x509.CertificateRequest, set names.Set, now time.Time) (*x509.Certificate, error) {
	certs, err := parsePEMChain(chainPEM)
	if err != nil {
		return nil, err
	}
	leaf := certs[0]
	pub, ok := leaf.PublicKey.(interface{ Equal(crypto.PublicKey) bool })
	if !ok || !pub.Equal(csr.PublicKey) {
		return nil, errors.New("leaf public key does not match the CSR")
	}
	got, err := names.NewSet(leaf.DNSNames...)
	if err != nil {
		return nil, fmt.Errorf("leaf names: %w", err)
	}
	if !got.Equal(set) {
		return nil, fmt.Errorf("leaf names %s do not match the order identifiers %s", got.Key(), set.Key())
	}
	if !now.Before(leaf.NotAfter) {
		return nil, fmt.Errorf("leaf expired at %s", leaf.NotAfter.Format(time.RFC3339))
	}
	for i := 0; i+1 < len(certs); i++ {
		if err := certs[i].CheckSignatureFrom(certs[i+1]); err != nil {
			return nil, fmt.Errorf("chain link %d: %w", i, err)
		}
	}
	return leaf, nil
}

// parsePEMChain parses a PEM certificate chain, leaf first.
func parsePEMChain(chainPEM []byte) ([]*x509.Certificate, error) {
	var out []*x509.Certificate
	rest := chainPEM
	for {
		var b *pem.Block
		b, rest = pem.Decode(rest)
		if b == nil {
			break
		}
		if b.Type != "CERTIFICATE" {
			return nil, fmt.Errorf("unexpected PEM block %q in chain", b.Type)
		}
		c, err := x509.ParseCertificate(b.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parse certificate: %w", err)
		}
		out = append(out, c)
	}
	if len(out) == 0 {
		return nil, errors.New("no certificates in chain")
	}
	return out, nil
}

// serialHex formats a serial as core.Certificate.Serial: lowercase hex, no
// leading zeros.
func serialHex(c *x509.Certificate) string {
	s := strings.TrimLeft(hex.EncodeToString(c.SerialNumber.Bytes()), "0")
	if s == "" {
		return "0"
	}
	return s
}
