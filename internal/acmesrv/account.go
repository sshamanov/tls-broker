package acmesrv

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	jose "github.com/go-jose/go-jose/v4"

	"tls-broker/internal/core"
)

// Contact limits. Contacts are metadata only (architecture §6).
const (
	maxContacts      = 10
	maxContactLength = 320
)

// accountObj is the RFC 8555 §7.1.2 account object.
type accountObj struct {
	Status  string   `json:"status"`
	Contact []string `json:"contact,omitempty"`
	Orders  string   `json:"orders"`
}

func (s *Server) accountJSON(x *exchange, a *core.ACMEAccount) accountObj {
	return accountObj{Status: string(a.Status), Contact: a.Contact, Orders: x.accountURL(a.ID) + "/orders"}
}

// accountRequest is the payload of newAccount and of an account update.
// Unknown fields (externalAccountBinding, the ACMEv1 "resource", ...) are
// ignored.
type accountRequest struct {
	Contact              *[]string `json:"contact"`
	TermsOfServiceAgreed *bool     `json:"termsOfServiceAgreed"`
	OnlyReturnExisting   bool      `json:"onlyReturnExisting"`
	Status               string    `json:"status"`
}

func checkContacts(c []string) *core.Problem {
	if len(c) > maxContacts {
		return core.NewProblem(core.ProblemInvalidContact, "at most %d contacts are accepted", maxContacts)
	}
	for _, v := range c {
		if !strings.HasPrefix(strings.ToLower(v), "mailto:") {
			return core.NewProblem(core.ProblemUnsupportedContact, "only mailto: contacts are supported, got %q", v)
		}
		if len(v) <= len("mailto:") || len(v) > maxContactLength || strings.ContainsAny(v, " \t\r\n,") {
			return core.NewProblem(core.ProblemInvalidContact, "contact %q is not a valid mailto: URL", v)
		}
	}
	return nil
}

// newAccount creates an account or finds the existing one for the key
// (RFC 8555 §7.3, §7.3.1).
func (s *Server) newAccount(x *exchange) {
	a := s.authenticate(x, useJWK)
	if a == nil {
		return
	}
	var req accountRequest
	if !a.postAsGet() {
		if err := json.Unmarshal(a.payload, &req); err != nil {
			s.problem(x, malformed("newAccount payload is not a JSON account object"))
			return
		}
	}
	existing, err := s.o.Accounts.GetByThumbprint(x.ctx, a.thumbprint)
	switch {
	case err == nil:
		s.existingAccount(x, existing)
		return
	case !errors.Is(err, core.ErrNotFound):
		s.fail(x, err)
		return
	}
	if req.OnlyReturnExisting {
		s.problem(x, core.NewProblem(core.ProblemAccountDoesNotExist, "no account exists for this key"))
		return
	}
	var contact []string
	if req.Contact != nil {
		contact = *req.Contact
	}
	if p := checkContacts(contact); p != nil {
		s.problem(x, p)
		return
	}
	jwk, err := publicJWK(a.jwk)
	if err != nil {
		s.fail(x, err)
		return
	}
	acct := &core.ACMEAccount{
		ID: core.NewID(), Thumbprint: a.thumbprint, JWK: jwk, Status: core.AccountValid,
		Contact: contact, CreatedAt: s.clock.Now(),
	}
	if err := s.o.Accounts.Create(x.ctx, acct); err != nil {
		if errors.Is(err, core.ErrConflict) {
			// Lost a race with a concurrent newAccount for the same key.
			if existing, gerr := s.o.Accounts.GetByThumbprint(x.ctx, a.thumbprint); gerr == nil {
				s.existingAccount(x, existing)
				return
			}
		}
		s.fail(x, err)
		return
	}
	x.w.Header().Set("Location", x.accountURL(acct.ID))
	s.writeJSON(x, http.StatusCreated, s.accountJSON(x, acct))
}

// existingAccount answers newAccount for a key that is already registered:
// 200 with the account's Location (Certbot turns this into "already
// registered"), or unauthorized for a deactivated account.
func (s *Server) existingAccount(x *exchange, acct *core.ACMEAccount) {
	x.w.Header().Set("Location", x.accountURL(acct.ID))
	if acct.Status != core.AccountValid {
		s.problem(x, core.NewProblem(core.ProblemUnauthorized, "account is %s", acct.Status))
		return
	}
	s.writeJSON(x, http.StatusOK, s.accountJSON(x, acct))
}

// account fetches (POST-as-GET or "{}"), updates the contact of, or
// deactivates an account (RFC 8555 §7.3.2, §7.3.6).
func (s *Server) account(x *exchange, id string) {
	a := s.authenticate(x, useKID)
	if a == nil {
		return
	}
	if a.account.ID != id {
		s.problem(x, core.NewProblem(core.ProblemUnauthorized, "the request is signed by a different account"))
		return
	}
	acct := a.account
	if !a.postAsGet() {
		var req accountRequest
		if err := json.Unmarshal(a.payload, &req); err != nil {
			s.problem(x, malformed("account update payload is not a JSON object"))
			return
		}
		changed := false
		switch req.Status {
		case "", string(core.AccountValid):
		case string(core.AccountDeactivated):
			acct.Status, changed = core.AccountDeactivated, true
		default:
			s.problem(x, malformed("an account status can only be changed to deactivated"))
			return
		}
		if req.Contact != nil {
			if p := checkContacts(*req.Contact); p != nil {
				s.problem(x, p)
				return
			}
			acct.Contact, changed = *req.Contact, true
		}
		if changed {
			if err := s.o.Accounts.Update(x.ctx, acct); err != nil {
				s.fail(x, err)
				return
			}
		}
	}
	x.w.Header().Set("Location", x.accountURL(acct.ID))
	s.writeJSON(x, http.StatusOK, s.accountJSON(x, acct))
}

// accountOrders serves the account's orders list. The broker does not keep
// a per-account history clients could use, so the list is always empty
// (RFC 8555 lets the server page and trim it).
func (s *Server) accountOrders(x *exchange, id string) {
	a := s.authenticate(x, useKID)
	if a == nil {
		return
	}
	if a.account.ID != id {
		s.problem(x, core.NewProblem(core.ProblemUnauthorized, "the request is signed by a different account"))
		return
	}
	s.writeJSON(x, http.StatusOK, map[string][]string{"orders": {}})
}

// keyChange rolls the account key over (RFC 8555 §7.3.5). The outer JWS is
// signed by the current key (kid); its payload is an inner JWS signed by the
// new key (jwk) whose payload names the account and the old key.
func (s *Server) keyChange(x *exchange) {
	a := s.authenticate(x, useKID)
	if a == nil {
		return
	}
	inner, prob := parseJWS(a.payload)
	if prob != nil {
		s.problem(x, malformed("inner keyChange JWS: %s", prob.Detail))
		return
	}
	if inner.jwk == nil {
		s.problem(x, malformed("inner keyChange JWS must carry the new key as jwk"))
		return
	}
	if want := x.url(pathKeyChange); inner.hdr.URL != want {
		s.problem(x, malformed("inner keyChange JWS url must be %q", want))
		return
	}
	// The inner JWS should omit "nonce"; one that carries it is accepted and
	// the value ignored, it protects nothing here.
	payload, prob := inner.verify(inner.jwk)
	if prob != nil {
		s.problem(x, malformed("inner keyChange JWS: %s", prob.Detail))
		return
	}
	var req struct {
		Account string          `json:"account"`
		OldKey  json.RawMessage `json:"oldKey"`
	}
	if err := json.Unmarshal(payload, &req); err != nil {
		s.problem(x, malformed("keyChange payload must be {account, oldKey}"))
		return
	}
	acct := a.account
	if req.Account != x.accountURL(acct.ID) {
		s.problem(x, core.NewProblem(core.ProblemUnauthorized, "keyChange account does not match the signing account"))
		return
	}
	var old jose.JSONWebKey
	if err := old.UnmarshalJSON(req.OldKey); err != nil {
		s.problem(x, malformed("keyChange oldKey is not a JWK"))
		return
	}
	oldTP, err := thumbprint(&old)
	if err != nil || oldTP != acct.Thumbprint {
		s.problem(x, core.NewProblem(core.ProblemUnauthorized, "keyChange oldKey is not the account's current key"))
		return
	}
	newTP, err := thumbprint(inner.jwk)
	if err != nil {
		s.problem(x, core.NewProblem(core.ProblemBadPublicKey, "new key thumbprint could not be computed"))
		return
	}
	if newTP == acct.Thumbprint {
		s.problem(x, malformed("the new key is the same as the current key"))
		return
	}
	if other, err := s.o.Accounts.GetByThumbprint(x.ctx, newTP); err == nil {
		s.keyInUse(x, other.ID)
		return
	} else if !errors.Is(err, core.ErrNotFound) {
		s.fail(x, err)
		return
	}
	jwk, err := publicJWK(inner.jwk)
	if err != nil {
		s.fail(x, err)
		return
	}
	if err := s.o.Accounts.UpdateKey(x.ctx, acct.ID, jwk, newTP); err != nil {
		if errors.Is(err, core.ErrConflict) {
			if other, gerr := s.o.Accounts.GetByThumbprint(x.ctx, newTP); gerr == nil {
				s.keyInUse(x, other.ID)
				return
			}
		}
		s.fail(x, err)
		return
	}
	acct.JWK, acct.Thumbprint = jwk, newTP
	x.w.Header().Set("Location", x.accountURL(acct.ID))
	s.writeJSON(x, http.StatusOK, s.accountJSON(x, acct))
}

// keyInUse answers 409 with the Location of the account that already holds
// the new key (RFC 8555 §7.3.5).
func (s *Server) keyInUse(x *exchange, otherID string) {
	x.w.Header().Set("Location", x.accountURL(otherID))
	s.problem(x, malformed("the new key is already bound to another account").WithStatus(http.StatusConflict))
}
