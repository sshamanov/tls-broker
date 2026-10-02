package core

import (
	"errors"
	"fmt"
	"time"
)

// Sentinel errors. Implementations may wrap them; callers test with errors.Is.
var (
	// ErrNotFound: the requested entity does not exist.
	ErrNotFound = errors.New("not found")
	// ErrConflict: a uniqueness rule or a state precondition was violated;
	// nothing was changed.
	ErrConflict = errors.New("conflict")
	// ErrExpired: the entity exists but its lifetime is over (an order past
	// ExpiresAt, a session past ExpiresAt).
	ErrExpired = errors.New("expired")
	// ErrCSRMismatch: finalize was retried with a CSR different from the one
	// already recorded for the order.
	ErrCSRMismatch = errors.New("order was already finalized with a different CSR")
	// ErrInvalidCredentials: unknown user or wrong password. Deliberately
	// does not say which.
	ErrInvalidCredentials = errors.New("invalid credentials")
	// ErrDirectoryUnavailable: LDAP is unreachable, misconfigured or not
	// configured; the credentials were not checked.
	ErrDirectoryUnavailable = errors.New("directory unavailable")
	// ErrOutsideManagedZones: a name does not belong to any managed zone.
	ErrOutsideManagedZones = errors.New("name is outside managed zones")
	// ErrDNSPropagation: a TXT value was written but did not become visible
	// in public DNS within the configured time.
	ErrDNSPropagation = errors.New("TXT record did not become visible in public DNS")
	// ErrResolver: every DoH resolver failed (transport or server failure).
	// A name that simply does not exist is not an error.
	ErrResolver = errors.New("DNS resolution failed")
)

// ProviderErrorKind classifies a failure of an upstream CA call. The scheduler
// and the issuance engine act on the kind, never on message text.
type ProviderErrorKind string

const (
	// ProviderRateLimited: the CA refused with a rate limit (ACME
	// rateLimited, HTTP 429). RetryAfter is authoritative when set.
	ProviderRateLimited ProviderErrorKind = "rate_limited"
	// ProviderBusy: the CA asked to back off without a rate limit (HTTP 503
	// with Retry-After, ACME serverInternal with Retry-After). Short-lived.
	ProviderBusy ProviderErrorKind = "busy"
	// ProviderDown: the CA is unreachable or failing (transport error,
	// timeout, 5xx without Retry-After).
	ProviderDown ProviderErrorKind = "down"
	// ProviderRejected: the CA understood the request and refused it for a
	// reason that retrying will not fix (bad CSR, CAA, validation failed,
	// unknown order). Says nothing about provider health.
	ProviderRejected ProviderErrorKind = "rejected"
	// ProviderAlreadyReplaced: newOrder with `replaces` was refused because
	// the certificate already has a replacement order (ACME
	// alreadyReplaced). The engine retries once without replaces. Says
	// nothing about provider health.
	ProviderAlreadyReplaced ProviderErrorKind = "already_replaced"
)

// ProviderError is the error type of every Provider method (context errors
// excepted, which are returned as they are).
type ProviderError struct {
	Provider string            // provider name
	Kind     ProviderErrorKind // what happened
	// RetryAfter is how long the CA asked us to wait, measured from when
	// the error was produced; 0 means the CA did not say.
	RetryAfter time.Duration
	// Problem is the ACME problem document from the CA, when there was one.
	Problem *Problem
	// Err is the underlying error (transport error and the like), if any.
	Err error
}

func (e *ProviderError) Error() string {
	msg := fmt.Sprintf("provider %s: %s", e.Provider, e.Kind)
	if e.Problem != nil {
		msg += ": " + e.Problem.Error()
	} else if e.Err != nil {
		msg += ": " + e.Err.Error()
	}
	if e.RetryAfter > 0 {
		msg += fmt.Sprintf(" (retry after %s)", e.RetryAfter)
	}
	return msg
}

// Unwrap returns the underlying error.
func (e *ProviderError) Unwrap() error { return e.Err }

// AffectsHealth reports whether this error says something about the health
// of the provider (rate limited, busy, down) as opposed to this one request.
func (e *ProviderError) AffectsHealth() bool {
	switch e.Kind {
	case ProviderRateLimited, ProviderBusy, ProviderDown:
		return true
	}
	return false
}

// AsProviderError returns the *ProviderError in err's chain, or nil.
func AsProviderError(err error) *ProviderError {
	var pe *ProviderError
	if errors.As(err, &pe) {
		return pe
	}
	return nil
}

// AdmissionKind says why the scheduler refused admission.
type AdmissionKind string

const (
	// AdmissionRateLimited: a local rate budget is exhausted, or the
	// provider told us it is rate limiting. Downstream: 429 rateLimited.
	AdmissionRateLimited AdmissionKind = "rate_limited"
	// AdmissionBusy: no concurrency slot became free within the wait.
	// Downstream: 429 rateLimited with a short Retry-After.
	AdmissionBusy AdmissionKind = "provider_busy"
	// AdmissionProviderDown: the provider's circuit is open because of an
	// outage. Downstream: 503 when no other provider can take the request.
	AdmissionProviderDown AdmissionKind = "provider_down"
)

// AdmissionError is returned by Scheduler.Acquire when it refuses, and by
// Issuer methods when no provider could admit the request.
type AdmissionError struct {
	Kind     AdmissionKind
	Provider string // provider that refused; empty when it summarizes several
	// RetryAfter is a hint for the caller, always > 0.
	RetryAfter time.Duration
	// Reason is a short operator-readable explanation, for example
	// "certificates per registered domain example.com".
	Reason string
}

func (e *AdmissionError) Error() string {
	return fmt.Sprintf("admission refused (%s, provider %q, retry after %s): %s", e.Kind, e.Provider, e.RetryAfter, e.Reason)
}

// AsAdmissionError returns the *AdmissionError in err's chain, or nil.
func AsAdmissionError(err error) *AdmissionError {
	var ae *AdmissionError
	if errors.As(err, &ae) {
		return ae
	}
	return nil
}
