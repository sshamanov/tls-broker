package acmesrv

import (
	"encoding/base64"
	"errors"
	"net/http"
	"strings"

	"tls-broker/internal/core"
)

type suggestedWindow struct {
	Start string `json:"start"`
	End   string `json:"end"`
}

type renewalInfoObj struct {
	SuggestedWindow suggestedWindow `json:"suggestedWindow"`
	ExplanationURL  string          `json:"explanationURL,omitempty"`
}

// validCertID checks the RFC 9773 §4.1 form: base64url(AKI) "." base64url(serial).
func validCertID(id string) bool {
	aki, serial, ok := strings.Cut(id, ".")
	if !ok || aki == "" || serial == "" {
		return false
	}
	_, err1 := base64.RawURLEncoding.DecodeString(aki)
	_, err2 := base64.RawURLEncoding.DecodeString(serial)
	return err1 == nil && err2 == nil
}

// renewalInfo serves RFC 9773 renewal information: an unauthenticated GET,
// answered from the upstream CA that issued the certificate through the
// issuer, with the CA's Retry-After (or ARIRetryAfter).
func (s *Server) renewalInfo(x *exchange, certID string) {
	if !validCertID(certID) {
		s.problem(x, malformed("renewalInfo certificate identifier must be base64url(AKI).base64url(serial)"))
		return
	}
	ri, err := s.o.Issuer.RenewalInfo(x.ctx, certID)
	if errors.Is(err, core.ErrNotFound) {
		s.problem(x, malformed("this broker did not issue a certificate with that identifier").WithStatus(http.StatusNotFound))
		return
	}
	if err != nil {
		s.fail(x, err)
		return
	}
	ra := ri.RetryAfter
	if ra <= 0 {
		ra = s.o.ARIRetryAfter
	}
	retryAfter(x.w, ra)
	s.writeJSON(x, http.StatusOK, renewalInfoObj{
		SuggestedWindow: suggestedWindow{Start: rfc3339(ri.WindowStart), End: rfc3339(ri.WindowEnd)},
		ExplanationURL:  ri.ExplanationURL,
	})
}
