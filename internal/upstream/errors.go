package upstream

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-acme/lego/v5/acme"

	"tls-broker/internal/core"
)

// maxRetryAfter bounds a Retry-After in seconds form so absurd values do not
// overflow time.Duration.
const maxRetryAfter = 30 * 24 * time.Hour

// parseRetryAfter reads a Retry-After header (RFC 9110 §10.2.3): either
// delay-seconds or an HTTP-date, the latter measured from now. Empty,
// malformed and past values give 0.
func parseRetryAfter(v string, now time.Time) time.Duration {
	v = strings.TrimSpace(v)
	if v == "" {
		return 0
	}
	if n, err := strconv.ParseInt(v, 10, 64); err == nil {
		if n <= 0 {
			return 0
		}
		if n > int64(maxRetryAfter/time.Second) {
			return maxRetryAfter
		}
		return time.Duration(n) * time.Second
	}
	if t, err := http.ParseTime(v); err == nil {
		if d := t.Sub(now); d > 0 {
			return min(d, maxRetryAfter)
		}
	}
	return 0
}

// toProblem converts lego's problem document.
func toProblem(pd *acme.ProblemDetails) *core.Problem {
	if pd == nil {
		return nil
	}
	p := &core.Problem{Type: pd.Type, Detail: pd.Detail, Status: pd.HTTPStatus}
	if p.Status == 0 {
		p.Status = core.ProblemStatus(pd.Type)
	}
	for _, sp := range pd.SubProblems {
		s := core.Subproblem{Type: sp.Type, Detail: sp.Detail}
		if sp.Identifier.Value != "" {
			s.Identifier = &core.ProblemIdentifier{Type: sp.Identifier.Type, Value: sp.Identifier.Value}
		}
		p.Subproblems = append(p.Subproblems, s)
	}
	return p
}

// classify turns the error of a lego call into the error a Provider method
// returns: ctx's error when ctx is done, otherwise a *core.ProviderError.
//
//	alreadyReplaced (409)                         -> already_replaced
//	rateLimited, or HTTP 429                      -> rate_limited (+Retry-After)
//	HTTP 503 or serverInternal, with Retry-After  -> busy (+Retry-After)
//	transport error, timeout, other 5xx           -> down
//	badNonce still failing after lego's retries   -> down
//	other 4xx, or a problem inside a 2xx answer   -> rejected (problem kept)
//	anything else (garbage 2xx body, ...)         -> down
func (p *ACMEProvider) classify(ctx context.Context, c *capture, err error) error {
	if err == nil {
		return nil
	}
	if cerr := ctx.Err(); cerr != nil {
		return cerr
	}
	if pe := core.AsProviderError(err); pe != nil {
		return pe
	}
	pe := &core.ProviderError{Provider: p.cfg.Name, Err: err}
	status, ra, replaced := 0, "", (*acme.ProblemDetails)(nil)
	if c != nil {
		status, ra, replaced = c.snapshot()
	}
	pe.RetryAfter = parseRetryAfter(ra, p.clock.Now())

	var pd *acme.ProblemDetails
	if replaced != nil {
		pd = replaced
	} else if errors.As(err, &pd) && pd.HTTPStatus != 0 && !errors.Is(err, errBlockedRetry) {
		status = pd.HTTPStatus
	}
	pe.Problem = toProblem(pd)
	typ := ""
	if pd != nil {
		typ = pd.Type
	}

	switch {
	case typ == acme.AlreadyReplacedErrorType:
		pe.Kind = core.ProviderAlreadyReplaced
	case typ == acme.RateLimitedErrorType || status == http.StatusTooManyRequests:
		pe.Kind = core.ProviderRateLimited
	case (status == http.StatusServiceUnavailable || typ == acme.ServerInternalErrorType) && pe.RetryAfter > 0:
		pe.Kind = core.ProviderBusy
	case typ == acme.BadNonceErrorType:
		pe.Kind = core.ProviderDown
	case status >= 500 || status == 0:
		pe.Kind = core.ProviderDown
	case status >= 400:
		pe.Kind = core.ProviderRejected
		if pe.Problem == nil {
			pe.Problem = core.NewProblem(core.ProblemMalformed, "certificate authority answered HTTP %d", status).WithStatus(status)
		}
	case pe.Problem != nil:
		// A problem carried inside a successful answer: the order's or
		// challenge's own error.
		pe.Kind = core.ProviderRejected
	default:
		pe.Kind = core.ProviderDown
	}
	return pe
}

// rejected builds a ProviderRejected error decided locally or from a
// resource's state.
func (p *ACMEProvider) rejected(prob *core.Problem) error {
	return &core.ProviderError{Provider: p.cfg.Name, Kind: core.ProviderRejected, Problem: prob}
}

// down builds a ProviderDown error for a local timeout or failure.
func (p *ACMEProvider) down(format string, args ...any) error {
	return &core.ProviderError{Provider: p.cfg.Name, Kind: core.ProviderDown, Err: fmt.Errorf(format, args...)}
}
