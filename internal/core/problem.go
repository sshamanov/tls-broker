package core

import (
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"tls-broker/internal/names"
)

// ACME problem types (RFC 8555 §6.7, RFC 9773 for alreadyReplaced).
const (
	problemNS = "urn:ietf:params:acme:error:"

	ProblemAccountDoesNotExist     = problemNS + "accountDoesNotExist"
	ProblemAlreadyReplaced         = problemNS + "alreadyReplaced"
	ProblemAlreadyRevoked          = problemNS + "alreadyRevoked"
	ProblemBadCSR                  = problemNS + "badCSR"
	ProblemBadNonce                = problemNS + "badNonce"
	ProblemBadPublicKey            = problemNS + "badPublicKey"
	ProblemBadRevocationReason     = problemNS + "badRevocationReason"
	ProblemBadSignatureAlgorithm   = problemNS + "badSignatureAlgorithm"
	ProblemCAA                     = problemNS + "caa"
	ProblemCompound                = problemNS + "compound"
	ProblemConnection              = problemNS + "connection"
	ProblemDNS                     = problemNS + "dns"
	ProblemExternalAccountRequired = problemNS + "externalAccountRequired"
	ProblemIncorrectResponse       = problemNS + "incorrectResponse"
	ProblemInvalidContact          = problemNS + "invalidContact"
	ProblemMalformed               = problemNS + "malformed"
	ProblemOrderNotReady           = problemNS + "orderNotReady"
	ProblemRateLimited             = problemNS + "rateLimited"
	ProblemRejectedIdentifier      = problemNS + "rejectedIdentifier"
	ProblemServerInternal          = problemNS + "serverInternal"
	ProblemTLS                     = problemNS + "tls"
	ProblemUnauthorized            = problemNS + "unauthorized"
	ProblemUnsupportedContact      = problemNS + "unsupportedContact"
	ProblemUnsupportedIdentifier   = problemNS + "unsupportedIdentifier"
	ProblemUserActionRequired      = problemNS + "userActionRequired"
)

// ProblemContentType is the media type of a serialized Problem.
const ProblemContentType = "application/problem+json"

// Problem is an RFC 7807 problem document with the ACME extensions. It is the
// error type shown to ACME clients, the form in which upstream CA errors are
// carried (ProviderError.Problem), and the form in which an order's failure
// is stored (Order.Error). It implements error.
//
// The JSON encoding is the wire format. RetryAfter is not part of the
// document; an HTTP layer turns it into a Retry-After header.
type Problem struct {
	Type        string       `json:"type"`
	Detail      string       `json:"detail,omitempty"`
	Status      int          `json:"status,omitempty"` // HTTP status
	Subproblems []Subproblem `json:"subproblems,omitempty"`

	// RetryAfter > 0 asks the client to wait that long before retrying.
	RetryAfter time.Duration `json:"-"`
}

// Subproblem is a per-identifier problem inside a Problem.
type Subproblem struct {
	Type       string             `json:"type"`
	Detail     string             `json:"detail,omitempty"`
	Identifier *ProblemIdentifier `json:"identifier,omitempty"`
}

// ProblemIdentifier is an ACME identifier object ({"type":"dns","value":...}).
type ProblemIdentifier struct {
	Type  string `json:"type"`
	Value string `json:"value"`
}

func (p *Problem) Error() string {
	t := strings.TrimPrefix(p.Type, problemNS)
	if p.Detail == "" {
		return t
	}
	return t + ": " + p.Detail
}

// Is makes errors.Is(err, &Problem{Type: X}) match any problem of type X.
func (p *Problem) Is(target error) bool {
	t, ok := target.(*Problem)
	return ok && t.Type == p.Type && (t.Detail == "" || t.Detail == p.Detail)
}

// NewProblem builds a problem with the default HTTP status for its type.
func NewProblem(typ, format string, args ...any) *Problem {
	return &Problem{Type: typ, Detail: fmt.Sprintf(format, args...), Status: ProblemStatus(typ)}
}

// WithRetryAfter returns a copy of p with RetryAfter set.
func (p *Problem) WithRetryAfter(d time.Duration) *Problem {
	c := *p
	c.RetryAfter = d
	return &c
}

// WithStatus returns a copy of p with the HTTP status set.
func (p *Problem) WithStatus(status int) *Problem {
	c := *p
	c.Status = status
	return &c
}

// ProblemStatus is the default HTTP status for an ACME problem type.
func ProblemStatus(typ string) int {
	switch typ {
	case ProblemAccountDoesNotExist, ProblemBadCSR, ProblemBadNonce, ProblemBadPublicKey,
		ProblemBadRevocationReason, ProblemBadSignatureAlgorithm, ProblemInvalidContact,
		ProblemMalformed, ProblemRejectedIdentifier, ProblemUnsupportedContact,
		ProblemUnsupportedIdentifier, ProblemAlreadyRevoked, ProblemConnection, ProblemDNS,
		ProblemTLS, ProblemIncorrectResponse, ProblemCompound:
		return http.StatusBadRequest
	case ProblemUnauthorized, ProblemOrderNotReady, ProblemCAA,
		ProblemExternalAccountRequired, ProblemUserActionRequired:
		return http.StatusForbidden
	case ProblemAlreadyReplaced:
		return http.StatusConflict
	case ProblemRateLimited:
		return http.StatusTooManyRequests
	default:
		return http.StatusInternalServerError
	}
}

// AsProblem returns the *Problem in err's chain, or nil.
func AsProblem(err error) *Problem {
	var p *Problem
	if errors.As(err, &p) {
		return p
	}
	return nil
}

// ProblemFromError maps any error to the problem an ACME client should see.
// It never returns nil for a non-nil error and never leaks internal error
// text: unknown errors become serverInternal with a fixed detail.
//
//	*Problem (anywhere in the chain)  -> that problem
//	*AdmissionError rate_limited/busy -> rateLimited, 429, Retry-After
//	*AdmissionError provider_down     -> serverInternal, 503, Retry-After
//	*ProviderError rate_limited       -> rateLimited, 429, Retry-After
//	*ProviderError busy/down          -> serverInternal, 503, Retry-After
//	*ProviderError rejected           -> the CA's problem type and detail when
//	                                     present, else serverInternal 500
//	names.ErrInvalid                  -> rejectedIdentifier
//	ErrOutsideManagedZones            -> rejectedIdentifier
//	ErrCSRMismatch                    -> badCSR (a terminal error for the
//	                                     client: acme.sh retries orderNotReady
//	                                     ten times, which can never succeed)
//	ErrExpired, ErrNotFound           -> malformed, 404
//	anything else                     -> serverInternal, 500
func ProblemFromError(err error) *Problem {
	if err == nil {
		return nil
	}
	if p := AsProblem(err); p != nil {
		return p
	}
	if ae := AsAdmissionError(err); ae != nil {
		if ae.Kind == AdmissionProviderDown {
			return (&Problem{Type: ProblemServerInternal, Detail: "certificate authority is temporarily unavailable",
				Status: http.StatusServiceUnavailable}).WithRetryAfter(ae.RetryAfter)
		}
		detail := "issuance is rate limited by the broker to protect the certificate authority"
		if ae.Reason != "" {
			detail += ": " + ae.Reason
		}
		return NewProblem(ProblemRateLimited, "%s", detail).WithRetryAfter(ae.RetryAfter)
	}
	if pe := AsProviderError(err); pe != nil {
		switch pe.Kind {
		case ProviderRateLimited:
			return NewProblem(ProblemRateLimited, "the certificate authority is rate limiting").WithRetryAfter(pe.RetryAfter)
		case ProviderBusy, ProviderDown:
			return (&Problem{Type: ProblemServerInternal, Detail: "certificate authority is temporarily unavailable",
				Status: http.StatusServiceUnavailable}).WithRetryAfter(pe.RetryAfter)
		default:
			if pe.Problem != nil && strings.HasPrefix(pe.Problem.Type, problemNS) {
				return &Problem{Type: pe.Problem.Type, Detail: "certificate authority: " + pe.Problem.Detail,
					Status: ProblemStatus(pe.Problem.Type), Subproblems: pe.Problem.Subproblems}
			}
			return NewProblem(ProblemServerInternal, "the certificate authority refused the request")
		}
	}
	var ne *names.Error
	switch {
	case errors.As(err, &ne):
		return NewProblem(ProblemRejectedIdentifier, "%s", ne.Error())
	case errors.Is(err, names.ErrInvalid), errors.Is(err, names.ErrEmptySet):
		return NewProblem(ProblemRejectedIdentifier, "invalid identifier")
	case errors.Is(err, ErrOutsideManagedZones):
		return NewProblem(ProblemRejectedIdentifier, "identifier is outside the zones managed by this broker")
	case errors.Is(err, ErrCSRMismatch):
		return NewProblem(ProblemBadCSR, "the order was already finalized with a different CSR; create a new order for a new key")
	case errors.Is(err, ErrExpired):
		return NewProblem(ProblemMalformed, "expired").WithStatus(http.StatusNotFound)
	case errors.Is(err, ErrNotFound):
		return NewProblem(ProblemMalformed, "not found").WithStatus(http.StatusNotFound)
	}
	return NewProblem(ProblemServerInternal, "internal error")
}
