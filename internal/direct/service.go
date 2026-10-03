package direct

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/netip"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"golang.org/x/sync/singleflight"

	"tls-broker/internal/core"
	"tls-broker/internal/metrics"
	"tls-broker/internal/names"
)

// DefaultKeepGenerations is how many generations per identifier stay on disk
// when Options.KeepGenerations is 0.
const DefaultKeepGenerations = 3

// Retry hints used when nothing more specific is known.
const (
	// gateRetryAfter is suggested when the gate could not decide (DNS
	// failure, store error).
	gateRetryAfter = time.Minute
	// minARIRecheck bounds how soon renewal information is fetched again
	// when the CA asks for a very short Retry-After.
	minARIRecheck = time.Minute
)

// Options configure a Service.
type Options struct {
	Config   core.ConfigSource // required
	Issuer   core.Issuer       // required
	Gate     core.Gate         // required
	Entries  core.DirectStore  // required
	Lineages core.LineageStore // required
	// Certificates, when set, lets startup repair find the certificate
	// row of a generation it falls back to.
	Certificates core.CertificateStore
	Auditor      core.Auditor     // nil: no audit records
	Metrics      metrics.Recorder // nil: metrics.Nop
	Clock        core.Clock       // nil: core.SystemClock
	Logger       *slog.Logger     // nil: slog.Default()
	// KeepGenerations is how many generations per identifier stay on disk
	// (the active one always does); 0 means DefaultKeepGenerations.
	KeepGenerations int
	// NewKey generates a cache object's private key; nil uses
	// rsa.GenerateKey. Tests inject pre-generated keys.
	NewKey func(bits int) (*rsa.PrivateKey, error)
}

// Service is the direct certificate cache (architecture §11–12, §20). It is
// safe for concurrent use. Create it with New, call Verify once at startup
// before serving, and Close at shutdown.
type Service struct {
	cfg      core.ConfigSource
	issuer   core.Issuer
	gate     core.Gate
	entries  core.DirectStore
	lineages core.LineageStore
	certs    core.CertificateStore
	auditor  core.Auditor
	metrics  metrics.Recorder
	clock    core.Clock
	log      *slog.Logger
	keep     int
	newKey   func(bits int) (*rsa.PrivateKey, error)

	ctx    context.Context // cancelled by Close; parent of every job
	cancel context.CancelFunc
	wg     sync.WaitGroup
	// jobs collapses every issuance and renewal of one identifier into a
	// single job: the key is the identifier.
	jobs singleflight.Group

	mu     sync.Mutex
	closed bool
	gens   map[string]*Generation // last loaded generation per identifier
	holds  map[string]hold        // failure backoff per identifier
	rotate map[string]bool        // key rotation requested
	// waiting counts callers of start per identifier that have not received
	// their result yet; a start that finds none begins a new job.
	waiting map[string]int
}

// hold is the backoff after a failed attempt: until then no new attempt is
// made and requests without a valid certificate get problem.
type hold struct {
	problem *core.Problem
	until   time.Time
}

// trigger describes the request that started a job.
type trigger struct {
	src      netip.Addr
	decision core.Decision
	at       time.Time
}

// Cert is a certificate served to a client: the active generation of an
// identifier.
type Cert struct {
	Identifier string // normalized, "*.example.com" for a wildcard
	Generation int
	KeyPEM     []byte
	ChainPEM   []byte
	// ModTime is when the generation was written.
	ModTime  time.Time
	NotAfter time.Time
	Serial   string // leaf serial, lowercase hex
}

// ETag is the entity tag of the tar response. It changes whenever the
// generation changes (new number or new certificate), so a device polling
// with If-None-Match gets 304 until there is something new.
func (c *Cert) ETag() string { return fmt.Sprintf(`"%d-%s"`, c.Generation, c.Serial) }

// New returns a Service. It starts no goroutines.
func New(o Options) (*Service, error) {
	if o.Config == nil || o.Issuer == nil || o.Gate == nil || o.Entries == nil || o.Lineages == nil {
		return nil, errors.New("direct: Config, Issuer, Gate, Entries and Lineages are required")
	}
	s := &Service{
		cfg: o.Config, issuer: o.Issuer, gate: o.Gate, entries: o.Entries, lineages: o.Lineages,
		certs: o.Certificates, auditor: o.Auditor, metrics: o.Metrics, clock: o.Clock, log: o.Logger,
		keep: o.KeepGenerations, newKey: o.NewKey,
		gens: map[string]*Generation{}, holds: map[string]hold{}, rotate: map[string]bool{}, waiting: map[string]int{},
	}
	if s.metrics == nil {
		s.metrics = metrics.Nop{}
	}
	if s.clock == nil {
		s.clock = core.SystemClock{}
	}
	if s.log == nil {
		s.log = slog.Default()
	}
	if s.keep <= 0 {
		s.keep = DefaultKeepGenerations
	}
	if s.newKey == nil {
		s.newKey = func(bits int) (*rsa.PrivateKey, error) { return rsa.GenerateKey(rand.Reader, bits) }
	}
	s.ctx, s.cancel = context.WithCancel(context.Background())
	return s, nil
}

// Close cancels running jobs and waits for them to finish.
func (s *Service) Close() {
	s.mu.Lock()
	s.closed = true
	s.mu.Unlock()
	s.cancel()
	s.wg.Wait()
}

// Files returns the generation manager for the current data directory.
func (s *Service) Files() *Files {
	return NewFiles(filepath.Join(s.cfg.Current().DataDir, "certs"), s.keep)
}

func (s *Service) audit(ctx context.Context, ev core.AuditEvent) {
	if s.auditor != nil {
		s.auditor.Record(ctx, ev)
	}
}

// ---------------------------------------------------------------------------
// Fetch
// ---------------------------------------------------------------------------

// Get serves one fetch of an identifier ("foo.example.com" or
// "*.example.com", not yet normalized) by the source address src.
//
// The identifier is validated and must lie in a managed zone; then the gate
// decides. A valid cached certificate is returned at once; if its renewal is
// due (ARI window or the configured share of its lifetime, or the emergency
// window) one background job renews it. Without a valid certificate the
// request waits for one synchronous issuance, bounded by ctx.
//
// Errors are *core.Problem with Status set: 404 invalid or outside the
// managed zones, 403 denied by the gate, 429 rate limited, 503 no valid
// certificate and issuance not possible now (with RetryAfter).
func (s *Service) Get(ctx context.Context, src netip.Addr, raw string) (*Cert, error) {
	cfg := s.cfg.Current()
	ev := core.AuditEvent{Type: core.AuditDirectFetch, Mode: core.ModeDirect, Visibility: core.AuditVisibilityAdmin}
	if src.IsValid() {
		ev.SourceIP = src.String()
	}
	deny := func(reason string, p *core.Problem) (*Cert, error) {
		ev.Decision, ev.Reason, ev.Result = core.AuditDecisionDeny, reason, core.AuditResultDenied
		if ev.Detail == "" {
			ev.Detail = p.Detail
		}
		s.audit(ctx, ev)
		return nil, p
	}

	id, err := names.Normalize(raw)
	if err != nil {
		ev.Detail = "invalid identifier " + truncate(raw, 80)
		return deny(core.ReasonInvalidIdentifier, notFound("invalid identifier"))
	}
	ev.Names = []string{id}
	if !cfg.ManagedZones().Contains(id) {
		return deny(core.ReasonOutsideManagedZone, notFound("identifier is outside the zones managed by this broker"))
	}
	if !src.Is4() {
		return deny(core.ReasonNotIPv4, forbidden("the source address is not a usable IPv4 address"))
	}
	set, err := names.NewSet(id)
	if err != nil {
		return deny(core.ReasonInvalidIdentifier, notFound("invalid identifier"))
	}
	dec, err := s.gate.Authorize(ctx, core.ModeDirect, src, set)
	if err != nil {
		ev.Detail = "authorization failed: " + err.Error()
		ev.Decision, ev.Result = core.AuditDecisionDeny, core.AuditResultFailed
		s.audit(ctx, ev)
		return nil, unavailable("authorization could not be decided; retry later", gateRetryAfter)
	}
	s.metrics.GateDecision(core.ModeDirect, dec.Allowed, dec.Reason)
	ev.GrantID, ev.Reason = dec.GrantID, dec.Reason
	if !dec.Allowed {
		ev.Detail = dec.Detail
		switch dec.Reason {
		case core.ReasonDNSFailure:
			return deny(dec.Reason, unavailable("DNS resolution failed while authorizing; retry later", gateRetryAfter))
		case core.ReasonOutsideManagedZone, core.ReasonInvalidIdentifier:
			return deny(dec.Reason, notFound("identifier is not served by this broker"))
		}
		return deny(dec.Reason, forbidden("not authorized for "+id+" ("+dec.Reason+")"))
	}
	ev.Decision = core.AuditDecisionAllow

	now := s.clock.Now()
	lin, err := s.lineages.Observe(ctx, set.Key(), now)
	if err != nil {
		s.log.Warn("direct: lineage observation failed", "identifier", id, "err", err)
	}
	t := trigger{src: src, decision: dec, at: now}
	entry, err := s.entry(ctx, id)
	if err != nil {
		ev.Result, ev.Detail = core.AuditResultFailed, "reading cache entry: "+err.Error()
		s.audit(ctx, ev)
		return nil, unavailable("the certificate cache is unavailable", cfg.Scheduler.BusyRetryAfter)
	}
	gen := s.loadGen(cfg, id, entry)

	if gen != nil && now.Before(gen.Leaf().NotAfter) {
		s.metrics.DirectCacheHit()
		if err := s.entries.TouchFetch(ctx, id, now, src); err != nil {
			s.log.Warn("direct: recording fetch failed", "identifier", id, "err", err)
		}
		ev.Detail = fmt.Sprintf("hit: generation %d", gen.Number)
		interval := lin.Interval(cfg.Emergency.DefaultInterval)
		if why := s.maintenanceDue(cfg, id, entry, gen, now, interval); why != "" {
			if _, started := s.start(id, t); started {
				ev.Detail += "; background job started: " + why
			}
		}
		return s.served(ctx, ev, id, gen)
	}

	s.metrics.DirectCacheMiss()
	kind := "miss"
	if gen != nil {
		kind = "expired"
	}
	if p := s.held(cfg, id, entry, now); p != nil {
		ev.Result, ev.Detail = core.AuditResultFailed, kind+": in backoff after a failed attempt"
		s.audit(ctx, ev)
		return nil, p
	}
	var res singleflight.Result
	ch, _ := s.start(id, t)
	select {
	case res = <-ch:
	case <-ctx.Done():
		ev.Result, ev.Detail = core.AuditResultFailed, kind+": request ended while issuance was running"
		s.audit(context.WithoutCancel(ctx), ev)
		return nil, unavailable("issuance is in progress; retry later", cfg.Scheduler.BusyRetryAfter)
	}
	// Whatever the job reports, serve what is now on disk if it is valid.
	now = s.clock.Now()
	entry, _ = s.entry(ctx, id)
	if gen := s.loadGen(cfg, id, entry); gen != nil && now.Before(gen.Leaf().NotAfter) {
		if err := s.entries.TouchFetch(ctx, id, now, src); err != nil {
			s.log.Warn("direct: recording fetch failed", "identifier", id, "err", err)
		}
		ev.Detail = fmt.Sprintf("%s: issued generation %d", kind, gen.Number)
		return s.served(ctx, ev, id, gen)
	}
	p := issueProblem(cfg, res.Err)
	if res.Err == nil {
		p = s.held(cfg, id, entry, now)
		if p == nil {
			p = unavailable("no valid certificate is available; retry later", cfg.Direct.RetryBackoff)
		}
	}
	ev.Result, ev.Detail = core.AuditResultFailed, kind+": "+errText(res.Err, p)
	s.audit(ctx, ev)
	return nil, p
}

func (s *Service) served(ctx context.Context, ev core.AuditEvent, id string, g *Generation) (*Cert, error) {
	leaf := g.Leaf()
	na := leaf.NotAfter
	ev.Result, ev.Visibility, ev.CertNotAfter = core.AuditResultOK, core.AuditVisibilityAll, &na
	s.audit(ctx, ev)
	return &Cert{
		Identifier: id, Generation: g.Number, KeyPEM: g.KeyPEM, ChainPEM: g.ChainPEM,
		ModTime: g.ModTime, NotAfter: leaf.NotAfter, Serial: leaf.SerialNumber.Text(16),
	}, nil
}

// entry returns the cache entry, nil when there is none.
func (s *Service) entry(ctx context.Context, id string) (*core.DirectEntry, error) {
	e, err := s.entries.Get(ctx, id)
	if errors.Is(err, core.ErrNotFound) {
		return nil, nil
	}
	return e, err
}

// loadGen returns the entry's active generation, nil when there is none or
// it cannot be loaded.
func (s *Service) loadGen(cfg *core.Config, id string, e *core.DirectEntry) *Generation {
	if e == nil || e.Generation == 0 {
		return nil
	}
	s.mu.Lock()
	g := s.gens[id]
	s.mu.Unlock()
	if g != nil && g.Number == e.Generation {
		return g
	}
	g, err := NewFiles(filepath.Join(cfg.DataDir, "certs"), s.keep).Load(id, e.Generation)
	if err != nil {
		s.log.Error("direct: active generation unusable; treating as a cache miss",
			"identifier", id, "generation", e.Generation, "err", err)
		return nil
	}
	s.mu.Lock()
	s.gens[id] = g
	s.mu.Unlock()
	return g
}

// ---------------------------------------------------------------------------
// Renewal policy
// ---------------------------------------------------------------------------

func fractionRenewAt(cfg *core.Config, leaf *x509.Certificate) time.Time {
	life := leaf.NotAfter.Sub(leaf.NotBefore)
	return leaf.NotBefore.Add(time.Duration(cfg.Direct.RenewFraction * float64(life)))
}

// inEmergency reports whether now is inside the certificate's emergency
// window (architecture §8) for the lineage's check interval.
func inEmergency(cfg *core.Config, leaf *x509.Certificate, now time.Time, interval time.Duration) bool {
	w := core.EmergencyWindow(cfg.Emergency, leaf.NotAfter.Sub(leaf.NotBefore), interval)
	return !now.Before(leaf.NotAfter.Add(-w))
}

// renewalDue reports whether the certificate should be renewed now: RenewAt
// (ARI window start, else the configured share of the lifetime) has passed,
// or the emergency window has begun.
func renewalDue(cfg *core.Config, e *core.DirectEntry, leaf *x509.Certificate, now time.Time, interval time.Duration) bool {
	at := e.RenewAt
	if at.IsZero() {
		at = fractionRenewAt(cfg, leaf)
	}
	return !now.Before(at) || inEmergency(cfg, leaf, now, interval)
}

func ariDue(e *core.DirectEntry, leaf *x509.Certificate, now time.Time) bool {
	return len(leaf.AuthorityKeyId) > 0 && !now.Before(e.NextARICheckAt)
}

// maintenanceDue says why a background job should run for a served
// certificate, or "" when none is needed.
func (s *Service) maintenanceDue(cfg *core.Config, id string, e *core.DirectEntry, g *Generation, now time.Time, interval time.Duration) string {
	leaf := g.Leaf()
	if renewalDue(cfg, e, leaf, now, interval) && s.held(cfg, id, e, now) == nil {
		if inEmergency(cfg, leaf, now, interval) {
			return "renewal (emergency window)"
		}
		return "renewal"
	}
	if ariDue(e, leaf, now) {
		return "renewal information check"
	}
	return ""
}

func backoff(cfg *core.Config, failures int) time.Duration {
	d := cfg.Direct.RetryBackoff
	for i := 1; i < failures && d < cfg.Direct.RetryBackoffMax; i++ {
		d *= 2
	}
	return min(d, cfg.Direct.RetryBackoffMax)
}

// held returns the problem to answer while the identifier is backing off
// after a failed attempt, nil when an attempt may be made.
func (s *Service) held(cfg *core.Config, id string, e *core.DirectEntry, now time.Time) *core.Problem {
	s.mu.Lock()
	h, ok := s.holds[id]
	s.mu.Unlock()
	if ok && now.Before(h.until) {
		return h.problem.WithRetryAfter(h.until.Sub(now))
	}
	if !ok && e != nil && e.Failures > 0 { // after a restart: persisted backoff
		if until := e.LastAttemptAt.Add(backoff(cfg, e.Failures)); now.Before(until) {
			return unavailable("no valid certificate is available and the last issuance attempt failed", until.Sub(now))
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// Jobs
// ---------------------------------------------------------------------------

var errClosed = errors.New("direct: service is closed")

// start runs (or joins) the identifier's job and returns a channel that
// receives its result, and whether this call started the job rather than
// joining one already running. At most one job per identifier runs at a
// time.
func (s *Service) start(id string, t trigger) (<-chan singleflight.Result, bool) {
	out := make(chan singleflight.Result, 1)
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		out <- singleflight.Result{Err: errClosed}
		return out, false
	}
	s.wg.Add(1)
	started := s.waiting[id] == 0
	s.waiting[id]++
	s.mu.Unlock()
	ch := s.jobs.DoChan(id, func() (any, error) { return nil, s.run(id, t) })
	go func() {
		defer s.wg.Done()
		res := <-ch
		s.mu.Lock()
		if s.waiting[id]--; s.waiting[id] == 0 {
			delete(s.waiting, id)
		}
		s.mu.Unlock()
		out <- res
	}()
	return out, started
}

// jobTimeout bounds one job: the whole upstream budget of an issuance. A
// client waits at most DirectConfig.IssueTimeout; the job continues so the
// certificate is not lost once the CSR was sent.
func jobTimeout(cfg *core.Config) time.Duration {
	return cfg.Scheduler.AdmitWait + cfg.Upstream.PrepareTimeout + cfg.Upstream.IssueTimeout
}

// run is the job of one identifier. It re-reads the state (another job may
// have finished just before), refreshes renewal information when due, and
// issues when there is no valid certificate, renewal is due or a key
// rotation was requested — unless the identifier is backing off.
func (s *Service) run(id string, t trigger) error {
	cfg := s.cfg.Current()
	ctx, cancel := context.WithTimeout(s.ctx, jobTimeout(cfg))
	defer cancel()

	e, err := s.entry(ctx, id)
	if err != nil {
		return err
	}
	g := s.loadGen(cfg, id, e)
	now := s.clock.Now()
	valid := g != nil && now.Before(g.Leaf().NotAfter)

	s.mu.Lock()
	rotate := s.rotate[id]
	delete(s.rotate, id)
	s.mu.Unlock()

	emergency := false
	if valid && !rotate {
		if ariDue(e, g.Leaf(), now) {
			s.refreshARI(ctx, cfg, e, g, now)
		}
		interval := cfg.Emergency.DefaultInterval
		if lin, err := s.lineages.Get(ctx, id); err == nil {
			interval = lin.Interval(interval)
		}
		if !renewalDue(cfg, e, g.Leaf(), now, interval) {
			return nil
		}
		emergency = inEmergency(cfg, g.Leaf(), now, interval)
	}
	if !rotate {
		if p := s.held(cfg, id, e, now); p != nil {
			return p
		}
	}

	key := (*rsa.PrivateKey)(nil)
	if g != nil && !rotate {
		key = g.Key // normal renewal reuses the key
	} else if key, err = s.newKey(cfg.Direct.RSABits); err != nil {
		return s.failed(ctx, cfg, id, e, t, now, valid, fmt.Errorf("generating key: %w", err))
	}
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: id}, DNSNames: []string{id},
	}, key)
	if err != nil {
		return s.failed(ctx, cfg, id, e, t, now, valid, fmt.Errorf("creating CSR: %w", err))
	}
	s.log.Info("direct: issuing", "identifier", id, "background", valid, "emergency", emergency,
		"rotate", rotate, "reuse_key", g != nil && !rotate)
	cert, err := s.issuer.Issue(ctx, core.IssueRequest{
		Identifier: id, CSRDER: csr, SourceIP: t.src, Decision: t.decision, Background: valid,
	})
	now = s.clock.Now()
	if err != nil {
		if s.ctx.Err() != nil { // shutting down: not the upstream's fault
			return err
		}
		return s.failed(ctx, cfg, id, e, t, now, valid, err)
	}
	f := NewFiles(filepath.Join(cfg.DataDir, "certs"), s.keep)
	ng, err := f.Write(id, key, cert.ChainPEM, now)
	if err != nil {
		s.audit(ctx, core.AuditEvent{Type: core.AuditError, Mode: core.ModeDirect, Names: []string{id},
			Provider: cert.Provider, CertificateID: cert.ID, Result: core.AuditResultFailed,
			Detail: "issued certificate could not be stored: " + err.Error()})
		return s.failed(ctx, cfg, id, e, t, now, valid, fmt.Errorf("storing generation: %w", err))
	}
	leaf := ng.Leaf()
	ne := core.DirectEntry{Identifier: id, CreatedAt: now, LastFetchAt: t.at, LastFetchIP: t.src}
	if e != nil {
		ne = *e
	}
	ne.Generation, ne.CertificateID, ne.Provider = ng.Number, cert.ID, cert.Provider
	ne.NotBefore, ne.NotAfter = leaf.NotBefore, leaf.NotAfter
	ne.RenewAt, ne.NextARICheckAt = fractionRenewAt(cfg, leaf), time.Time{}
	ne.LastAttemptAt, ne.LastError, ne.Failures, ne.UpdatedAt = now, "", 0, now
	if err := s.entries.Put(ctx, &ne); err != nil {
		// The files are the truth; Verify adopts the generation at the
		// next start. Keep the older generations until then.
		s.log.Error("direct: saving cache entry failed", "identifier", id, "generation", ng.Number, "err", err)
		return err
	}
	s.mu.Lock()
	s.gens[id] = ng
	delete(s.holds, id)
	s.mu.Unlock()
	if err := f.Prune(id); err != nil {
		s.log.Warn("direct: pruning generations failed", "identifier", id, "err", err)
	}
	s.metrics.CertExpiry(id, leaf.NotAfter)
	if valid {
		s.metrics.DirectRenewal(metrics.IssueOK)
	}
	s.log.Info("direct: stored generation", "identifier", id, "generation", ng.Number,
		"provider", cert.Provider, "not_after", leaf.NotAfter)
	return nil
}

// failed records a failed attempt (entry fields and in-memory backoff) and
// returns err.
func (s *Service) failed(ctx context.Context, cfg *core.Config, id string, e *core.DirectEntry, t trigger, now time.Time, background bool, err error) error {
	ne := core.DirectEntry{Identifier: id, CreatedAt: now, LastFetchAt: t.at, LastFetchIP: t.src}
	if e != nil {
		ne = *e
	}
	ne.LastAttemptAt, ne.LastError, ne.UpdatedAt = now, truncate(err.Error(), 500), now
	ne.Failures++
	if perr := s.entries.Put(ctx, &ne); perr != nil {
		s.log.Error("direct: saving cache entry failed", "identifier", id, "err", perr)
	}
	p := issueProblem(cfg, err)
	until := now.Add(backoff(cfg, ne.Failures))
	if r := now.Add(p.RetryAfter); r.After(until) {
		until = r
	}
	s.mu.Lock()
	s.holds[id] = hold{problem: p, until: until}
	s.mu.Unlock()
	if background {
		s.metrics.DirectRenewal(metrics.IssueFailed)
	}
	s.log.Warn("direct: issuance failed", "identifier", id, "background", background,
		"failures", ne.Failures, "retry_at", until, "err", err)
	return err
}

// refreshARI fetches renewal information for the active certificate and
// stores the resulting RenewAt and NextARICheckAt. Without usable renewal
// information RenewAt stays as it is (the configured share of the
// lifetime).
func (s *Service) refreshARI(ctx context.Context, cfg *core.Config, e *core.DirectEntry, g *Generation, now time.Time) {
	leaf := g.Leaf()
	next := now.Add(cfg.Direct.ARIPollInterval)
	if ariID, err := core.ARICertID(leaf); err == nil {
		info, err := s.issuer.RenewalInfo(ctx, ariID)
		switch {
		case err != nil:
			s.log.Info("direct: no renewal information", "identifier", e.Identifier, "err", err)
		case !info.WindowStart.IsZero():
			e.RenewAt = info.WindowStart
			if info.RetryAfter > 0 {
				next = now.Add(max(info.RetryAfter, minARIRecheck))
			}
		}
	}
	if e.RenewAt.IsZero() {
		e.RenewAt = fractionRenewAt(cfg, leaf)
	}
	e.NextARICheckAt, e.UpdatedAt = next, now
	if err := s.entries.Put(ctx, e); err != nil {
		s.log.Warn("direct: saving renewal schedule failed", "identifier", e.Identifier, "err", err)
	}
}

// Rotate replaces the identifier's private key: it issues a new certificate
// for a freshly generated key synchronously, bypassing the failure backoff,
// and makes it the active generation. It is the explicit admin action of
// architecture §11; normal renewals reuse the key. It waits for a job that
// is already running and then runs its own.
func (s *Service) Rotate(ctx context.Context, identifier string) error {
	id, err := names.Normalize(identifier)
	if err != nil {
		return err
	}
	if !s.cfg.Current().ManagedZones().Contains(id) {
		return core.ErrOutsideManagedZones
	}
	t := trigger{decision: core.Decision{Allowed: true, Detail: "explicit key rotation"}, at: s.clock.Now()}
	for range 5 {
		s.mu.Lock()
		s.rotate[id] = true
		s.mu.Unlock()
		var res singleflight.Result
		ch, _ := s.start(id, t)
		select {
		case res = <-ch:
		case <-ctx.Done():
			return ctx.Err()
		}
		s.mu.Lock()
		pending := s.rotate[id]
		s.mu.Unlock()
		if !pending { // a job took the request; its result is ours
			return res.Err
		}
	}
	s.mu.Lock()
	delete(s.rotate, id)
	s.mu.Unlock()
	return errors.New("direct: key rotation could not start; retry")
}

// ---------------------------------------------------------------------------
// Problems
// ---------------------------------------------------------------------------

func notFound(detail string) *core.Problem {
	return core.NewProblem(core.ProblemRejectedIdentifier, "%s", detail).WithStatus(http.StatusNotFound)
}

func forbidden(detail string) *core.Problem {
	return core.NewProblem(core.ProblemUnauthorized, "%s", detail).WithStatus(http.StatusForbidden)
}

func unavailable(detail string, retry time.Duration) *core.Problem {
	return core.NewProblem(core.ProblemServerInternal, "%s", detail).
		WithStatus(http.StatusServiceUnavailable).WithRetryAfter(retry)
}

// issueProblem maps an issuance failure to what the client sees: 429 when the
// broker or the CA rate-limits, 503 otherwise, always with a Retry-After.
func issueProblem(cfg *core.Config, err error) *core.Problem {
	retry := cfg.Direct.RetryBackoff
	if p := core.AsProblem(err); p != nil && (p.Status == http.StatusTooManyRequests || p.Status == http.StatusServiceUnavailable) {
		if p.RetryAfter <= 0 {
			p = p.WithRetryAfter(retry)
		}
		return p // a backoff hold, or a problem the engine already classified
	}
	ae, pe := core.AsAdmissionError(err), core.AsProviderError(err)
	switch {
	case ae != nil && ae.Kind != core.AdmissionProviderDown,
		pe != nil && pe.Kind == core.ProviderRateLimited:
		p := core.ProblemFromError(err)
		if p.RetryAfter <= 0 {
			p = p.WithRetryAfter(cfg.Scheduler.RateLimitRetryAfter)
		}
		return p
	case ae != nil && ae.RetryAfter > 0:
		retry = ae.RetryAfter
	case pe != nil && pe.RetryAfter > 0:
		retry = pe.RetryAfter
	case errors.Is(err, context.DeadlineExceeded), errors.Is(err, context.Canceled):
		return unavailable("issuance did not finish in time; retry later", cfg.Scheduler.BusyRetryAfter)
	}
	return unavailable("no valid certificate is available and issuance is not possible now", retry)
}

func errText(err error, p *core.Problem) string {
	if err != nil {
		return err.Error()
	}
	return p.Detail
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return strings.ToValidUTF8(s[:n], "") + "..."
}
