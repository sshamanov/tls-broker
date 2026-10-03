package acmesrv

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"tls-broker/internal/core"
	"tls-broker/internal/httpx"
	"tls-broker/internal/names"
)

// identifierObj is an ACME identifier.
type identifierObj struct {
	Type  string `json:"type"`
	Value string `json:"value"`
}

// orderObj is the RFC 8555 §7.1.3 order object. Field order puts status
// first, which keeps line-oriented parsers (acme.sh) on the order's status.
type orderObj struct {
	Status         string          `json:"status"`
	Expires        string          `json:"expires,omitempty"`
	Identifiers    []identifierObj `json:"identifiers"`
	Authorizations []string        `json:"authorizations"`
	Finalize       string          `json:"finalize"`
	Certificate    string          `json:"certificate,omitempty"`
	Replaces       string          `json:"replaces,omitempty"`
	Error          *core.Problem   `json:"error,omitempty"`
}

// challengeObj is the synthetic dns-01 challenge of an authorization.
type challengeObj struct {
	Type      string `json:"type"`
	Status    string `json:"status"`
	URL       string `json:"url"`
	Token     string `json:"token"`
	Validated string `json:"validated"`
}

// authzObj is the RFC 8555 §7.1.4 authorization object.
type authzObj struct {
	Status     string         `json:"status"`
	Expires    string         `json:"expires"`
	Identifier identifierObj  `json:"identifier"`
	Challenges []challengeObj `json:"challenges"`
	Wildcard   bool           `json:"wildcard,omitempty"`
}

func (x *exchange) authzURL(orderID string, i int) string {
	return x.url(pathAuthz + orderID + "/" + strconv.Itoa(i))
}

func (x *exchange) challengeURL(orderID string, i int) string {
	return x.url(pathChallenge + orderID + "/" + strconv.Itoa(i))
}

// expiredProblem is what an order that was never finalized shows once its
// TTL has passed, before the issuer's sweep marks it invalid.
func expiredProblem() *core.Problem {
	return malformed("order expired before it was finalized; create a new order")
}

// effectiveStatus is the order status a client sees at now.
func effectiveStatus(o *core.Order, now time.Time) (core.OrderStatus, *core.Problem) {
	if o.Status == core.OrderReady && !now.Before(o.ExpiresAt) {
		return core.OrderInvalid, expiredProblem()
	}
	return o.Status, o.Error
}

func (s *Server) orderJSON(x *exchange, o *core.Order) orderObj {
	status, prob := effectiveStatus(o, s.clock.Now())
	obj := orderObj{
		Status:   string(status),
		Expires:  rfc3339(o.ExpiresAt),
		Finalize: x.orderURL(o.ID) + "/finalize",
		Error:    prob,
	}
	for i, n := range o.Names.Names() {
		obj.Identifiers = append(obj.Identifiers, identifierObj{Type: "dns", Value: n})
		obj.Authorizations = append(obj.Authorizations, x.authzURL(o.ID, i))
	}
	if status == core.OrderValid && o.CertificateID != "" {
		obj.Certificate = x.url(pathCert + o.CertificateID)
	}
	if s.replacesHonoured(x, o) {
		obj.Replaces = o.Replaces
	}
	return obj
}

// replacesHonoured reports whether the client's `replaces` is being acted on:
// it names a certificate the broker issued and, once the upstream order
// exists, that order replaces the same certificate. A `replaces` the broker
// ignores (architecture §8) is not echoed.
func (s *Server) replacesHonoured(x *exchange, o *core.Order) bool {
	if o.Replaces == "" {
		return false
	}
	if o.UpstreamReplaces != "" || o.Prep != core.PrepIntent {
		return o.UpstreamReplaces == o.Replaces
	}
	_, err := s.o.Certificates.GetByARICertID(x.ctx, o.Replaces)
	return err == nil
}

// writeOrder writes an order with the Retry-After that tells a client how
// soon to poll a processing order.
func (s *Server) writeOrder(x *exchange, status int, o *core.Order) {
	obj := s.orderJSON(x, o)
	if obj.Status == string(core.OrderProcessing) {
		retryAfter(x.w, x.cfg.Scheduler.ProcessingRetryAfter)
	}
	s.writeJSON(x, status, obj)
}

// ownedOrder loads an ACME order of the requesting account. Orders of other
// accounts are reported as not found, like unknown ones.
func (s *Server) ownedOrder(x *exchange, acct *core.ACMEAccount, id string) (*core.Order, *core.Problem) {
	o, err := s.o.Orders.Get(x.ctx, id)
	if err == nil && (o.Mode != core.ModeACME || o.AccountID != acct.ID) {
		err = core.ErrNotFound
	}
	if errors.Is(err, core.ErrNotFound) {
		return nil, malformed("order not found").WithStatus(http.StatusNotFound)
	}
	if err != nil {
		s.log.ErrorContext(x.ctx, "order lookup failed", "order", id, "err", err)
		return nil, core.NewProblem(core.ProblemServerInternal, "internal error")
	}
	return o, nil
}

// ---- newOrder ---------------------------------------------------------------

type newOrderRequest struct {
	Identifiers []identifierObj `json:"identifiers"`
	NotBefore   string          `json:"notBefore"`
	NotAfter    string          `json:"notAfter"`
	Replaces    string          `json:"replaces"`
	// Profile is accepted and ignored: the broker chooses the upstream
	// profile from the provider configuration.
	Profile string `json:"profile"`
}

// parseIdentifiers normalizes the requested identifiers and checks managed
// zones. A rejection carries one subproblem per offending identifier and the
// gate reason vocabulary for the audit record.
func parseIdentifiers(cfg *core.Config, ids []identifierObj) (names.Set, *core.Problem, string) {
	if len(ids) == 0 {
		return names.Set{}, malformed("newOrder needs at least one identifier"), core.ReasonInvalidIdentifier
	}
	if len(ids) > MaxIdentifiers {
		return names.Set{}, core.NewProblem(core.ProblemRejectedIdentifier, "at most %d identifiers per order", MaxIdentifiers),
			core.ReasonInvalidIdentifier
	}
	zones := cfg.ManagedZones()
	var subs []core.Subproblem
	unsupported, outside := 0, 0
	normalized := make([]string, 0, len(ids))
	for _, id := range ids {
		ident := &core.ProblemIdentifier{Type: id.Type, Value: id.Value}
		if id.Type != "dns" {
			unsupported++
			subs = append(subs, core.Subproblem{Type: core.ProblemUnsupportedIdentifier, Identifier: ident,
				Detail: fmt.Sprintf("identifier type %q is not supported; only dns", id.Type)})
			continue
		}
		n, err := names.Normalize(id.Value)
		if err != nil {
			detail := "invalid DNS name"
			var ne *names.Error
			if errors.As(err, &ne) {
				detail = ne.Reason
			}
			subs = append(subs, core.Subproblem{Type: core.ProblemRejectedIdentifier, Identifier: ident, Detail: detail})
			continue
		}
		if !zones.Contains(n) {
			outside++
			subs = append(subs, core.Subproblem{Type: core.ProblemRejectedIdentifier, Identifier: ident,
				Detail: core.ErrOutsideManagedZones.Error()})
			continue
		}
		normalized = append(normalized, n)
	}
	if len(subs) > 0 {
		typ, reason := core.ProblemRejectedIdentifier, core.ReasonInvalidIdentifier
		if unsupported == len(subs) {
			typ = core.ProblemUnsupportedIdentifier
		} else if outside == len(subs) {
			reason = core.ReasonOutsideManagedZone
		}
		p := core.NewProblem(typ, "%d of %d identifiers cannot be issued by this broker", len(subs), len(ids))
		p.Subproblems = subs
		return names.Set{}, p, reason
	}
	set, err := names.NewSet(normalized...)
	if err != nil {
		return names.Set{}, core.ProblemFromError(err), core.ReasonInvalidIdentifier
	}
	return set, nil, ""
}

// reasonText explains a gate reason to an ACME client.
func reasonText(d core.Decision, src netip.Addr) string {
	switch d.Reason {
	case core.ReasonDNSMismatch:
		if d.Name != "" {
			return fmt.Sprintf("%s does not resolve to the requesting address %s and no IP grant covers it", d.Name, src)
		}
		return fmt.Sprintf("the identifiers do not all resolve to the requesting address %s and no IP grant covers it", src)
	case core.ReasonWildcardGrantRequired:
		return fmt.Sprintf("wildcard identifiers need an IP grant with wildcard permission for %s", src)
	case core.ReasonDNSFailure:
		return "public DNS could not be resolved; retry later"
	case core.ReasonOutsideManagedZone:
		return "an identifier is outside the zones managed by this broker"
	case core.ReasonNotIPv4:
		return "the request did not come from a usable IPv4 address"
	case core.ReasonInvalidIdentifier:
		return "an identifier is invalid"
	}
	return "the request is not authorized"
}

// gateDenied builds the problem for a gate denial and records it.
func (s *Server) gateDenied(x *exchange, d core.Decision, src netip.Addr, set names.Set, orderID string) *core.Problem {
	detail := fmt.Sprintf("denied by the broker's authorization gate (reason %s): %s", d.Reason, reasonText(d, src))
	if d.Detail != "" && d.Reason != core.ReasonDNSFailure {
		// A resolver failure's detail is the DoH client's error text (URLs,
		// dial errors); it goes to the audit log below, not to the client.
		detail += " (" + d.Detail + ")"
	}
	p := core.NewProblem(core.ProblemUnauthorized, "%s", detail)
	if d.Name != "" {
		p.Subproblems = []core.Subproblem{{Type: core.ProblemUnauthorized, Detail: reasonText(d, src),
			Identifier: &core.ProblemIdentifier{Type: "dns", Value: d.Name}}}
	}
	ev := core.AuditEvent{Type: core.AuditGate, Visibility: core.AuditVisibilityAdmin, Names: set.Names(),
		Decision: core.AuditDecisionDeny, Reason: d.Reason, Result: core.AuditResultDenied, OrderID: orderID, Detail: d.Detail}
	if src.IsValid() {
		ev.SourceIP = src.String()
	}
	s.audit(x.ctx, ev)
	return p
}

// authorize asks the gate about set for the request's source address. A nil
// problem means allowed.
func (s *Server) authorize(x *exchange, set names.Set, orderID string) (core.Decision, netip.Addr, *core.Problem) {
	src, ok := httpx.SourceIP(x.ctx)
	if !ok {
		d := core.Decision{Reason: core.ReasonNotIPv4}
		s.met.GateDecision(core.ModeACME, false, d.Reason)
		return d, src, s.gateDenied(x, d, src, set, orderID)
	}
	d, err := s.o.Gate.Authorize(x.ctx, core.ModeACME, src, set)
	if err != nil {
		s.log.ErrorContext(x.ctx, "gate failed", "err", err)
		return d, src, core.NewProblem(core.ProblemServerInternal, "authorization could not be decided; retry later").
			WithStatus(http.StatusServiceUnavailable).WithRetryAfter(30 * time.Second)
	}
	s.met.GateDecision(core.ModeACME, d.Allowed, d.Reason)
	if !d.Allowed {
		return d, src, s.gateDenied(x, d, src, set, orderID)
	}
	return d, src, nil
}

// newOrder handles RFC 8555 §7.4 newOrder (architecture §7.1). The request
// may be held while the issuer waits for an admission slot.
func (s *Server) newOrder(x *exchange) {
	a := s.authenticate(x, useKID)
	if a == nil {
		return
	}
	p := s.newOrderAuthed(x, a)
	s.met.Request(core.ModeACME, outcome(p))
	if p != nil {
		s.problem(x, p)
	}
}

func (s *Server) newOrderAuthed(x *exchange, a *authed) *core.Problem {
	var req newOrderRequest
	if a.postAsGet() || json.Unmarshal(a.payload, &req) != nil {
		return malformed("newOrder payload must be a JSON object with identifiers")
	}
	if req.NotBefore != "" || req.NotAfter != "" {
		return malformed("notBefore and notAfter are not supported")
	}
	set, p, reason := parseIdentifiers(x.cfg, req.Identifiers)
	if p != nil {
		ev := core.AuditEvent{Type: core.AuditGate, Visibility: core.AuditVisibilityAdmin, Decision: core.AuditDecisionDeny,
			Reason: reason, Result: core.AuditResultDenied, Detail: p.Detail}
		if src, ok := httpx.SourceIP(x.ctx); ok {
			ev.SourceIP = src.String()
		}
		for _, id := range req.Identifiers {
			ev.Names = append(ev.Names, id.Value)
		}
		s.audit(x.ctx, ev)
		return p
	}
	dec, src, p := s.authorize(x, set, "")
	if p != nil {
		return p
	}
	o, err := s.o.Issuer.Admit(x.ctx, core.AdmitRequest{
		AccountID: a.account.ID, Names: set, Replaces: req.Replaces, SourceIP: src, Decision: dec,
	})
	if err != nil {
		p := core.ProblemFromError(err)
		if ae := core.AsAdmissionError(err); ae != nil {
			reason := core.ReasonRateLimited
			if ae.Kind == core.AdmissionProviderDown {
				reason = core.ReasonProviderUnavailable
			}
			s.audit(x.ctx, core.AuditEvent{Type: core.AuditRateLimit, Visibility: core.AuditVisibilityAdmin,
				SourceIP: src.String(), Names: set.Names(), Provider: ae.Provider, Reason: reason,
				Result: core.AuditResultDenied, Detail: string(ae.Kind) + ": " + ae.Reason})
		} else if core.AsProblem(err) == nil && p.Status >= 500 && p.RetryAfter == 0 {
			s.log.ErrorContext(x.ctx, "admit failed", "err", err)
		}
		return p
	}
	x.w.Header().Set("Location", x.orderURL(o.ID))
	s.writeOrder(x, http.StatusCreated, o)
	return nil
}

// order serves POST-as-GET on an order: its current state, with
// Retry-After while it is processing.
func (s *Server) order(x *exchange, id string) {
	a := s.authenticate(x, useKID)
	if a == nil {
		return
	}
	o, p := s.ownedOrder(x, a.account, id)
	if p != nil {
		s.problem(x, p)
		return
	}
	s.writeOrder(x, http.StatusOK, o)
}

// ---- finalize ---------------------------------------------------------------

// decodeCSR decodes the finalize csr field (base64url DER; padding
// tolerated) and checks that it is a self-signed PKCS#10 request. Matching
// the names against the order is the issuer's job.
func decodeCSR(field string) ([]byte, *core.Problem) {
	der, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(field, "="))
	if err != nil || len(der) == 0 {
		return nil, core.NewProblem(core.ProblemBadCSR, "csr must be a base64url-encoded DER certificate request")
	}
	csr, err := x509.ParseCertificateRequest(der)
	if err != nil {
		return nil, core.NewProblem(core.ProblemBadCSR, "csr could not be parsed")
	}
	if err := csr.CheckSignature(); err != nil {
		return nil, core.NewProblem(core.ProblemBadCSR, "csr signature is invalid")
	}
	return der, nil
}

// finalize handles RFC 8555 §7.4 finalize (architecture §7.2).
func (s *Server) finalize(x *exchange, id string) {
	a := s.authenticate(x, useKID)
	if a == nil {
		return
	}
	p := s.finalizeAuthed(x, a, id)
	s.met.Request(core.ModeACME, outcome(p))
	if p != nil {
		s.problem(x, p)
	}
}

func (s *Server) finalizeAuthed(x *exchange, a *authed, id string) *core.Problem {
	o, p := s.ownedOrder(x, a.account, id)
	if p != nil {
		return p
	}
	var req struct {
		CSR string `json:"csr"`
	}
	if a.postAsGet() || json.Unmarshal(a.payload, &req) != nil {
		return malformed("finalize payload must be a JSON object with csr")
	}
	csrDER, p := decodeCSR(req.CSR)
	if p != nil {
		return s.finalizeRejected(x, o, p)
	}
	var dec core.Decision
	switch status, _ := effectiveStatus(o, s.clock.Now()); {
	case status == core.OrderInvalid && !o.Finalized():
		return s.finalizeRejected(x, o, core.NewProblem(core.ProblemOrderNotReady,
			"order is invalid and cannot be finalized; create a new order"))
	case status == core.OrderReady:
		// Architecture §7.2 step 1: the gate is asked again for the source
		// that sends the CSR; the decision is handed to the issuer so it is
		// not asked twice. Retries of an accepted CSR skip this.
		var p *core.Problem
		if dec, _, p = s.authorize(x, o.Names, o.ID); p != nil {
			return p
		}
	}
	src, _ := httpx.SourceIP(x.ctx)
	res, err := s.o.Issuer.Finalize(x.ctx, core.FinalizeRequest{
		OrderID: o.ID, AccountID: a.account.ID, CSRDER: csrDER, SourceIP: src, Decision: dec,
	})
	switch {
	case err == nil:
	case errors.Is(err, core.ErrExpired):
		return s.finalizeRejected(x, o, core.NewProblem(core.ProblemOrderNotReady,
			"order expired before it was finalized; create a new order"))
	case errors.Is(err, core.ErrNotFound):
		return malformed("order not found").WithStatus(http.StatusNotFound)
	default:
		p := core.ProblemFromError(err)
		if p.Type == core.ProblemBadCSR {
			return s.finalizeRejected(x, o, p)
		}
		if core.AsProblem(err) == nil && p.Status >= 500 && p.RetryAfter == 0 {
			s.log.ErrorContext(x.ctx, "finalize failed", "order", o.ID, "err", err)
		}
		return p
	}
	x.w.Header().Set("Location", x.orderURL(res.ID))
	s.writeOrder(x, http.StatusOK, res)
	return nil
}

// finalizeRejected records a finalize request refused at the protocol level
// (bad CSR, CSR mismatch, order not ready) and returns the problem.
func (s *Server) finalizeRejected(x *exchange, o *core.Order, p *core.Problem) *core.Problem {
	ev := core.AuditEvent{Type: core.AuditOrder, Visibility: core.AuditVisibilityAdmin, Names: o.Names.Names(),
		Provider: o.Provider, Result: core.AuditResultFailed, OrderID: o.ID, Detail: "finalize refused: " + p.Error()}
	if src, ok := httpx.SourceIP(x.ctx); ok {
		ev.SourceIP = src.String()
	}
	s.audit(x.ctx, ev)
	return p
}

// ---- authorizations and challenges ------------------------------------------

// orderItem resolves an authorization or challenge path to the owned order
// and identifier index.
func (s *Server) orderItem(x *exchange, a *authed, orderID, idx string) (*core.Order, int, *core.Problem) {
	o, p := s.ownedOrder(x, a.account, orderID)
	if p != nil {
		if p.Status >= 500 {
			return nil, 0, p
		}
		return nil, 0, malformed("authorization not found").WithStatus(http.StatusNotFound)
	}
	i, err := strconv.Atoi(idx)
	if err != nil || i < 0 || i >= o.Names.Len() || strconv.Itoa(i) != idx {
		return nil, 0, malformed("authorization not found").WithStatus(http.StatusNotFound)
	}
	return o, i, nil
}

// challengeToken is a stable synthetic token: base64url of 256 bits derived
// from the order and identifier (Certbot requires at least 128 bits).
func challengeToken(orderID string, i int) string {
	sum := sha256.Sum256([]byte("acmesrv-token:" + orderID + ":" + strconv.Itoa(i)))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func (s *Server) challengeJSON(x *exchange, o *core.Order, i int) challengeObj {
	return challengeObj{Type: "dns-01", Status: "valid", URL: x.challengeURL(o.ID, i),
		Token: challengeToken(o.ID, i), Validated: rfc3339(o.CreatedAt)}
}

func (s *Server) authzJSON(x *exchange, o *core.Order, i int) authzObj {
	name := o.Names.Names()[i]
	return authzObj{
		Status:     "valid",
		Expires:    rfc3339(o.ExpiresAt),
		Identifier: identifierObj{Type: "dns", Value: names.Base(name)},
		Challenges: []challengeObj{s.challengeJSON(x, o, i)},
		Wildcard:   names.IsWildcard(name),
	}
}

// authorization serves POST-as-GET on an authorization, and accepts
// deactivation (RFC 8555 §7.5.2), which is answered but changes nothing:
// the authorization is synthetic and belongs to its order only.
func (s *Server) authorization(x *exchange, orderID, idx string) {
	a := s.authenticate(x, useKID)
	if a == nil {
		return
	}
	o, i, p := s.orderItem(x, a, orderID, idx)
	if p != nil {
		s.problem(x, p)
		return
	}
	obj := s.authzJSON(x, o, i)
	if !a.postAsGet() {
		var req struct {
			Status string `json:"status"`
		}
		if err := json.Unmarshal(a.payload, &req); err != nil {
			s.problem(x, malformed("authorization update payload is not a JSON object"))
			return
		}
		switch req.Status {
		case "":
		case "deactivated":
			obj.Status = "deactivated"
		default:
			s.problem(x, malformed("an authorization can only be deactivated"))
			return
		}
	}
	s.writeJSON(x, http.StatusOK, obj)
}

// challenge answers both POST-as-GET and a challenge response ("{}") with
// the same already valid challenge; clients never need to respond.
func (s *Server) challenge(x *exchange, orderID, idx string) {
	a := s.authenticate(x, useKID)
	if a == nil {
		return
	}
	o, i, p := s.orderItem(x, a, orderID, idx)
	if p != nil {
		s.problem(x, p)
		return
	}
	x.w.Header().Add("Link", `<`+x.authzURL(o.ID, i)+`>;rel="up"`)
	s.writeJSON(x, http.StatusOK, s.challengeJSON(x, o, i))
}

// ---- certificate ------------------------------------------------------------

// certificate serves the chain (leaf and intermediates, no root) to the
// account that ordered it (RFC 8555 §7.4.2).
func (s *Server) certificate(x *exchange, id string) {
	a := s.authenticate(x, useKID)
	if a == nil {
		return
	}
	notFound := malformed("certificate not found").WithStatus(http.StatusNotFound)
	cert, err := s.o.Certificates.Get(x.ctx, id)
	if err != nil {
		if !errors.Is(err, core.ErrNotFound) {
			s.fail(x, err)
			return
		}
		s.problem(x, notFound)
		return
	}
	if cert.Mode != core.ModeACME || len(cert.ChainPEM) == 0 {
		s.problem(x, notFound)
		return
	}
	if _, p := s.ownedOrder(x, a.account, cert.OrderID); p != nil {
		s.problem(x, notFound)
		return
	}
	h := x.w.Header()
	h.Set("Content-Type", "application/pem-certificate-chain")
	h.Set("Content-Length", strconv.Itoa(len(cert.ChainPEM)))
	x.w.WriteHeader(http.StatusOK)
	_, _ = x.w.Write(cert.ChainPEM)
}
