package acmesrv

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"tls-broker/internal/core"
	"tls-broker/internal/httpx"
	"tls-broker/internal/metrics"
)

// PathPrefix is the path of the ACME API below the external URL: the
// directory is ExternalURL + PathPrefix + "/directory".
const PathPrefix = "/acme"

// Resource paths below the ACME base URL.
const (
	pathDirectory   = "/directory"
	pathNewNonce    = "/new-nonce"
	pathNewAccount  = "/new-account"
	pathNewOrder    = "/new-order"
	pathKeyChange   = "/key-change"
	pathRevokeCert  = "/revoke-cert"
	pathRenewalInfo = "/renewal-info"
	pathAccount     = "/acct/"
	pathOrder       = "/order/"
	pathAuthz       = "/authz/"
	pathChallenge   = "/chall/"
	pathCert        = "/cert/"
)

// Defaults for Options.
const (
	DefaultNonceTTL      = time.Hour
	DefaultMaxNonces     = 100_000
	DefaultMaxBodyBytes  = 64 << 10
	DefaultARIRetryAfter = 6 * time.Hour
	// MaxIdentifiers is the largest identifier set a newOrder may carry
	// (the same limit as Let's Encrypt).
	MaxIdentifiers = 100
)

// Options configure a Server. Config, Accounts, Orders, Certificates, Gate
// and Issuer are required.
type Options struct {
	Config       core.ConfigSource
	Accounts     core.AccountStore
	Orders       core.OrderStore
	Certificates core.CertificateStore
	Gate         core.Gate
	Issuer       core.Issuer
	// Auditor records protocol-level refusals (gate denials, admission
	// refusals, rejected finalize requests). nil records nothing.
	Auditor core.Auditor
	// Metrics counts newOrder/finalize outcomes and gate decisions; nil
	// means metrics.Nop.
	Metrics metrics.Recorder
	// Clock defaults to core.SystemClock.
	Clock  core.Clock
	Logger *slog.Logger
	// TermsOfService is published as meta.termsOfService when set. Clients
	// then ask their user to agree; the answer is accepted either way.
	TermsOfService string
	// NonceTTL is how long an issued nonce stays usable (DefaultNonceTTL).
	NonceTTL time.Duration
	// MaxNonces bounds outstanding nonces; the oldest are evicted first
	// (DefaultMaxNonces).
	MaxNonces int
	// MaxBodyBytes bounds every request body (DefaultMaxBodyBytes).
	MaxBodyBytes int64
	// ARIRetryAfter is the Retry-After of a renewalInfo response when the
	// upstream CA gave none (DefaultARIRetryAfter).
	ARIRetryAfter time.Duration
}

// Server is the downstream ACME server. It is an http.Handler serving every
// path below PathPrefix; mount it at PathPrefix + "/".
type Server struct {
	o      Options
	clock  core.Clock
	log    *slog.Logger
	met    metrics.Recorder
	nonces *noncePool
}

// New builds a Server.
func New(o Options) (*Server, error) {
	if o.Config == nil || o.Accounts == nil || o.Orders == nil || o.Certificates == nil || o.Gate == nil || o.Issuer == nil {
		return nil, errors.New("acmesrv: Config, Accounts, Orders, Certificates, Gate and Issuer are required")
	}
	if o.Clock == nil {
		o.Clock = core.SystemClock{}
	}
	if o.Logger == nil {
		o.Logger = slog.Default()
	}
	if o.Metrics == nil {
		o.Metrics = metrics.Nop{}
	}
	if o.NonceTTL <= 0 {
		o.NonceTTL = DefaultNonceTTL
	}
	if o.MaxNonces <= 0 {
		o.MaxNonces = DefaultMaxNonces
	}
	if o.MaxBodyBytes <= 0 {
		o.MaxBodyBytes = DefaultMaxBodyBytes
	}
	if o.ARIRetryAfter <= 0 {
		o.ARIRetryAfter = DefaultARIRetryAfter
	}
	return &Server{
		o: o, clock: o.Clock, log: o.Logger, met: o.Metrics,
		nonces: newNoncePool(o.Clock, o.NonceTTL, o.MaxNonces),
	}, nil
}

// exchange is one request being served.
type exchange struct {
	w    http.ResponseWriter
	r    *http.Request
	ctx  context.Context
	cfg  *core.Config
	base string // absolute ACME base URL, e.g. https://broker.example.com/acme
	path string // request path below the base, e.g. /order/abc
}

// url returns the absolute URL of a resource path below the base.
func (x *exchange) url(path string) string { return x.base + path }

func (x *exchange) accountURL(id string) string { return x.url(pathAccount + id) }
func (x *exchange) orderURL(id string) string   { return x.url(pathOrder + id) }

// baseOf returns the absolute ACME base URL and its path for a configuration.
func baseOf(cfg *core.Config) (base, path string) {
	ext := strings.TrimRight(cfg.Server.ExternalURL, "/")
	base = ext + PathPrefix
	if u, err := url.Parse(base); err == nil {
		path = u.Path
	} else {
		path = PathPrefix
	}
	return base, path
}

// ServeHTTP implements http.Handler.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	cfg := s.o.Config.Current()
	base, prefix := baseOf(cfg)
	x := &exchange{w: w, r: r, ctx: r.Context(), cfg: cfg, base: base}

	// Headers every response carries: a fresh nonce (so a client never has
	// to ask for one after an error, in particular after badNonce) and the
	// directory link (RFC 8555 §7.1).
	h := w.Header()
	h.Set("Replay-Nonce", s.nonces.New())
	h.Add("Link", `<`+x.url(pathDirectory)+`>;rel="index"`)
	h.Set("Cache-Control", "no-store")

	if !strings.HasPrefix(r.URL.Path, prefix+"/") {
		s.notFound(x)
		return
	}
	x.path = strings.TrimPrefix(r.URL.Path, prefix)
	r.Body = http.MaxBytesReader(w, r.Body, s.o.MaxBodyBytes)

	switch x.path {
	case pathDirectory:
		if s.method(x, http.MethodGet, http.MethodHead) {
			s.directory(x)
		}
		return
	case pathNewNonce:
		if s.method(x, http.MethodGet, http.MethodHead) {
			s.newNonce(x)
		}
		return
	case pathNewAccount:
		if s.method(x, http.MethodPost) {
			s.newAccount(x)
		}
		return
	case pathNewOrder:
		if s.method(x, http.MethodPost) {
			s.newOrder(x)
		}
		return
	case pathKeyChange:
		if s.method(x, http.MethodPost) {
			s.keyChange(x)
		}
		return
	case pathRevokeCert:
		// Not in the directory; a client that guesses the path is told
		// plainly that revocation is not offered (architecture §24).
		s.problem(x, core.NewProblem(core.ProblemUnauthorized,
			"certificate revocation is not offered by this broker; revoke directly with the certificate authority if needed"))
		return
	}

	segs := strings.Split(strings.TrimPrefix(x.path, "/"), "/")
	for _, seg := range segs {
		if seg == "" {
			s.notFound(x)
			return
		}
	}
	switch {
	case segs[0] == "acct" && len(segs) == 2:
		if s.method(x, http.MethodPost) {
			s.account(x, segs[1])
		}
	case segs[0] == "acct" && len(segs) == 3 && segs[2] == "orders":
		if s.method(x, http.MethodPost) {
			s.accountOrders(x, segs[1])
		}
	case segs[0] == "order" && len(segs) == 2:
		if s.method(x, http.MethodPost) {
			s.order(x, segs[1])
		}
	case segs[0] == "order" && len(segs) == 3 && segs[2] == "finalize":
		if s.method(x, http.MethodPost) {
			s.finalize(x, segs[1])
		}
	case segs[0] == "authz" && len(segs) == 3:
		if s.method(x, http.MethodPost) {
			s.authorization(x, segs[1], segs[2])
		}
	case segs[0] == "chall" && len(segs) == 3:
		if s.method(x, http.MethodPost) {
			s.challenge(x, segs[1], segs[2])
		}
	case segs[0] == "cert" && len(segs) == 2:
		if s.method(x, http.MethodPost) {
			s.certificate(x, segs[1])
		}
	case segs[0] == "renewal-info" && len(segs) == 2:
		if s.method(x, http.MethodGet, http.MethodHead) {
			s.renewalInfo(x, segs[1])
		}
	default:
		s.notFound(x)
	}
}

// method answers 405 unless the request uses one of the allowed methods.
func (s *Server) method(x *exchange, allowed ...string) bool {
	for _, m := range allowed {
		if x.r.Method == m {
			return true
		}
	}
	x.w.Header().Set("Allow", strings.Join(allowed, ", "))
	detail := "method " + x.r.Method + " is not allowed here"
	if len(allowed) == 1 && allowed[0] == http.MethodPost {
		detail += "; ACME resources are fetched with POST-as-GET"
	}
	s.problem(x, core.NewProblem(core.ProblemMalformed, "%s", detail).WithStatus(http.StatusMethodNotAllowed))
	return false
}

func (s *Server) notFound(x *exchange) {
	s.problem(x, core.NewProblem(core.ProblemMalformed, "no such resource").WithStatus(http.StatusNotFound))
}

// problem writes an ACME problem document.
func (s *Server) problem(x *exchange, p *core.Problem) {
	httpx.WriteProblem(x.w, p)
}

// fail writes the problem for an error, logging errors that are not already
// client-facing problems.
func (s *Server) fail(x *exchange, err error) *core.Problem {
	p := core.ProblemFromError(err)
	if core.AsProblem(err) == nil && p.Type == core.ProblemServerInternal && p.Status >= 500 && p.RetryAfter == 0 {
		s.log.ErrorContext(x.ctx, "acme request failed", "path", x.path, "err", err)
	}
	s.problem(x, p)
	return p
}

// writeJSON writes a JSON resource.
func (s *Server) writeJSON(x *exchange, status int, v any) {
	b, err := json.Marshal(v)
	if err != nil {
		s.fail(x, err)
		return
	}
	h := x.w.Header()
	h.Set("Content-Type", "application/json")
	h.Set("Content-Length", strconv.Itoa(len(b)))
	x.w.WriteHeader(status)
	if x.r.Method != http.MethodHead {
		_, _ = x.w.Write(b)
	}
}

// retryAfter sets a Retry-After header in whole seconds, rounded up.
func retryAfter(w http.ResponseWriter, d time.Duration) {
	if d > 0 {
		w.Header().Set("Retry-After", strconv.FormatInt(int64((d+time.Second-1)/time.Second), 10))
	}
}

// audit records an event when an Auditor is configured.
func (s *Server) audit(ctx context.Context, ev core.AuditEvent) {
	if s.o.Auditor != nil {
		ev.Mode = core.ModeACME
		s.o.Auditor.Record(ctx, ev)
	}
}

// outcome classifies a problem for the requests_total metric.
func outcome(p *core.Problem) metrics.Outcome {
	switch {
	case p == nil:
		return metrics.OutcomeOK
	case p.Type == core.ProblemRateLimited:
		return metrics.OutcomeRateLimited
	case p.Status == http.StatusServiceUnavailable:
		return metrics.OutcomeUnavailable
	case p.Type == core.ProblemUnauthorized:
		return metrics.OutcomeDenied
	}
	return metrics.OutcomeError
}

// ---- directory and nonces ---------------------------------------------------

type directoryMeta struct {
	TermsOfService          string `json:"termsOfService,omitempty"`
	ExternalAccountRequired bool   `json:"externalAccountRequired"`
}

type directoryDoc struct {
	NewNonce    string        `json:"newNonce"`
	NewAccount  string        `json:"newAccount"`
	NewOrder    string        `json:"newOrder"`
	KeyChange   string        `json:"keyChange"`
	RenewalInfo string        `json:"renewalInfo"`
	Meta        directoryMeta `json:"meta"`
}

func (s *Server) directory(x *exchange) {
	s.writeJSON(x, http.StatusOK, directoryDoc{
		NewNonce:    x.url(pathNewNonce),
		NewAccount:  x.url(pathNewAccount),
		NewOrder:    x.url(pathNewOrder),
		KeyChange:   x.url(pathKeyChange),
		RenewalInfo: x.url(pathRenewalInfo),
		Meta:        directoryMeta{TermsOfService: s.o.TermsOfService},
	})
}

// newNonce answers HEAD with 200 and GET with 204 (RFC 8555 §7.2); the nonce
// itself is the Replay-Nonce header every response carries.
func (s *Server) newNonce(x *exchange) {
	if x.r.Method == http.MethodHead {
		x.w.WriteHeader(http.StatusOK)
		return
	}
	x.w.WriteHeader(http.StatusNoContent)
}

// rfc3339 formats a time for ACME objects: UTC, whole seconds.
func rfc3339(t time.Time) string { return t.UTC().Truncate(time.Second).Format(time.RFC3339) }
