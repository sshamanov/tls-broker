package issuance

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"sync"
	"time"

	"tls-broker/internal/core"
	"tls-broker/internal/names"
)

// Housekeeping horizons used by Sweep.
const (
	// KeepFinishedOrders is how long valid and invalid orders are kept
	// after their last change before Sweep deletes them. Clients download
	// their certificate within minutes of finalize; a week leaves plenty of
	// room for operators to inspect failures.
	KeepFinishedOrders = 7 * 24 * time.Hour
	// KeepExpiredChains is how long after a certificate's expiry its PEM
	// chain is kept in the database. Metadata is kept forever.
	KeepExpiredChains = 30 * 24 * time.Hour
)

// Options are the dependencies of an Engine. All but Auditor and Logger are
// required.
type Options struct {
	Config    core.ConfigSource
	Clock     core.Clock // nil: core.SystemClock
	Orders    core.OrderStore
	Certs     core.CertificateStore
	Lineages  core.LineageStore
	Providers core.Providers
	DNS       core.DNSEngine
	Scheduler core.Scheduler
	Gate      core.Gate
	Auditor   core.Auditor // nil: no audit records
	Logger    *slog.Logger // nil: slog.Default()
}

// Engine implements core.Issuer. Create it with New, call Recover once before
// serving, Sweep periodically, and Close on shutdown.
type Engine struct {
	cfg       core.ConfigSource
	clock     core.Clock
	orders    core.OrderStore
	certs     core.CertificateStore
	lineages  core.LineageStore
	providers core.Providers
	dns       core.DNSEngine
	sched     core.Scheduler
	gate      core.Gate
	auditor   core.Auditor
	log       *slog.Logger

	// bg is the parent of every background context. Close cancels it once
	// the shutdown grace is over; work interrupted that way is left for
	// Recover rather than failed.
	bg     context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup

	mu   sync.Mutex
	jobs map[string]*job     // in-flight orders by ID
	ari  map[string]ariEntry // renewal information cache by ARI cert ID
}

var _ core.Issuer = (*Engine)(nil)

// New builds an engine. It does no I/O; call Recover to resume persisted
// work.
func New(opts Options) (*Engine, error) {
	switch {
	case opts.Config == nil, opts.Orders == nil, opts.Certs == nil, opts.Lineages == nil,
		opts.Providers == nil, opts.DNS == nil, opts.Scheduler == nil, opts.Gate == nil:
		return nil, errors.New("issuance: Config, Orders, Certs, Lineages, Providers, DNS, Scheduler and Gate are required")
	}
	e := &Engine{
		cfg: opts.Config, clock: opts.Clock, orders: opts.Orders, certs: opts.Certs, lineages: opts.Lineages,
		providers: opts.Providers, dns: opts.DNS, sched: opts.Scheduler, gate: opts.Gate,
		auditor: opts.Auditor, log: opts.Logger,
		jobs: map[string]*job{}, ari: map[string]ariEntry{},
	}
	if e.clock == nil {
		e.clock = core.SystemClock{}
	}
	if e.log == nil {
		e.log = slog.Default()
	}
	e.bg, e.cancel = context.WithCancel(context.Background())
	return e, nil
}

// Close waits for background work (preparations and finalizations) to
// finish. When ctx ends first, the remaining work is interrupted and left in
// its persisted state for the next Recover; Close then still waits for the
// goroutines to return. Idempotent.
func (e *Engine) Close(ctx context.Context) error {
	done := make(chan struct{})
	go func() {
		e.wg.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-ctx.Done():
		e.cancel()
		<-done
	}
	e.cancel()
	return nil
}

// closing reports whether Close has interrupted background work.
func (e *Engine) closing() bool { return e.bg.Err() != nil }

// spawn runs f in a tracked goroutine.
func (e *Engine) spawn(f func()) {
	e.wg.Add(1)
	go func() {
		defer e.wg.Done()
		f()
	}()
}

// bgContext returns a context for one background step, detached from any
// request and bounded by UpstreamConfig.PrepareTimeout.
func (e *Engine) bgContext() (context.Context, context.CancelFunc) {
	d := e.cfg.Current().Upstream.PrepareTimeout
	if d <= 0 {
		d = 10 * time.Minute
	}
	return context.WithTimeout(e.bg, d)
}

// ---------------------------------------------------------------------------
// Jobs: the in-memory side of an in-flight order
// ---------------------------------------------------------------------------

// job is the in-memory state of one non-terminal order: its ticket and the
// hand-off between preparation and finalize. Exactly one goroutine at a time
// owns an order (running); the CSR may arrive while preparation runs, in
// which case the preparing goroutine continues into finalize.
type job struct {
	id     string
	ticket core.Ticket
	// prepDone is closed when preparation ended (prepared or failed).
	prepDone chan struct{}
	// done is closed when the order is terminal or abandoned.
	done chan struct{}

	mu       sync.Mutex
	prepared bool // preparation succeeded
	finalize bool // a CSR has been recorded
	running  bool // a goroutine owns the order
	finished bool

	prepOnce, doneOnce sync.Once
}

func newJob(id string, t core.Ticket) *job {
	if t == nil {
		t = noTicket{}
	}
	return &job{id: id, ticket: t, prepDone: make(chan struct{}), done: make(chan struct{})}
}

// markPrepared records a successful preparation and reports whether the
// caller must continue into finalize (a CSR was recorded meanwhile). When it
// returns false the caller releases ownership.
func (j *job) markPrepared() (continueToFinalize bool) {
	j.mu.Lock()
	defer j.mu.Unlock()
	j.prepared = true
	if j.finalize && !j.finished {
		continueToFinalize = true
	} else {
		j.running = false
	}
	j.prepOnce.Do(func() { close(j.prepDone) })
	return continueToFinalize
}

// requestFinalize records that a CSR exists and reports whether the caller
// must start the finalize goroutine (preparation is done and nobody owns the
// order).
func (j *job) requestFinalize() (start bool) {
	j.mu.Lock()
	defer j.mu.Unlock()
	j.finalize = true
	if j.prepared && !j.running && !j.finished {
		j.running = true
		return true
	}
	return false
}

// finish marks the order terminal and wakes every waiter. Idempotent.
func (j *job) finish() {
	j.mu.Lock()
	j.finished = true
	j.running = false
	j.mu.Unlock()
	j.prepOnce.Do(func() { close(j.prepDone) })
	j.doneOnce.Do(func() { close(j.done) })
}

// setTicket replaces the job's ticket (after re-admission).
func (j *job) setTicket(t core.Ticket) {
	j.mu.Lock()
	defer j.mu.Unlock()
	j.ticket = t
}

func (j *job) getTicket() core.Ticket {
	j.mu.Lock()
	defer j.mu.Unlock()
	return j.ticket
}

// addJob registers a job; a job for the same ID must not exist.
func (e *Engine) addJob(j *job) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.jobs[j.id] = j
}

// lookupJob returns the job of an order, if one is in memory.
func (e *Engine) lookupJob(id string) *job {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.jobs[id]
}

// takeJob removes and returns the job of an order, if any.
func (e *Engine) takeJob(id string) *job {
	e.mu.Lock()
	defer e.mu.Unlock()
	j := e.jobs[id]
	delete(e.jobs, id)
	return j
}

// endJob finishes the job and drops it from the map.
func (e *Engine) endJob(j *job) {
	e.mu.Lock()
	if e.jobs[j.id] == j {
		delete(e.jobs, j.id)
	}
	e.mu.Unlock()
	j.finish()
}

// noTicket is the Ticket of an order whose reservation is already settled or
// never existed (ARI-qualified admissions reserve nothing).
type noTicket struct{}

func (noTicket) Ref() string   { return "" }
func (noTicket) OrderCreated() {}
func (noTicket) PrepDone()     {}
func (noTicket) Commit()       {}
func (noTicket) Refund()       {}

// reattach returns the ticket of a reservation that survived without its
// job (restart, or a job that was dropped), or a no-op ticket.
func (e *Engine) reattach(ctx context.Context, ref string) core.Ticket {
	t, err := e.sched.Reattach(ctx, ref)
	if err != nil {
		if !errors.Is(err, core.ErrNotFound) {
			e.log.Warn("issuance: reattach reservation", "ref", ref, "err", err)
		}
		return noTicket{}
	}
	return t
}

// ---------------------------------------------------------------------------
// Small helpers
// ---------------------------------------------------------------------------

// provider returns the provider by name or a ProviderError-free failure.
func (e *Engine) provider(name string) (core.Provider, error) {
	p, ok := e.providers.Get(name)
	if !ok {
		return nil, fmt.Errorf("issuance: provider %q is not configured", name)
	}
	return p, nil
}

// report feeds the provider circuit with the outcome of an upstream call.
func (e *Engine) report(ctx context.Context, provider string, err error) {
	e.sched.ReportProvider(context.WithoutCancel(ctx), provider, err)
}

// audit records an event when an auditor is configured.
func (e *Engine) audit(ctx context.Context, ev core.AuditEvent) {
	if e.auditor == nil {
		return
	}
	if ev.Visibility == "" {
		ev.Visibility = core.AuditVisibilityAll
	}
	e.auditor.Record(context.WithoutCancel(ctx), ev)
}

// orderEvent starts an audit event with the fields every order-related event
// shares.
func orderEvent(typ string, o *core.Order) core.AuditEvent {
	ev := core.AuditEvent{Type: typ, Mode: o.Mode, Names: o.Names.Names(), Provider: o.Provider,
		OrderID: o.ID, GrantID: o.GrantID}
	if o.SourceIP.IsValid() {
		ev.SourceIP = o.SourceIP.String()
	}
	return ev
}

func ipString(a netip.Addr) string {
	if !a.IsValid() {
		return ""
	}
	return a.String()
}

// checkRequest verifies what the caller promised: a non-empty normalized
// set inside the managed zones and an allowing decision. When the decision
// is zero (the caller did not run the gate) the engine runs it. A denial is
// returned as an unauthorized problem.
func (e *Engine) checkRequest(ctx context.Context, cfg *core.Config, mode core.Mode, src netip.Addr, set names.Set, d core.Decision) (core.Decision, error) {
	if set.IsZero() {
		return d, core.NewProblem(core.ProblemMalformed, "order has no identifiers")
	}
	if name, outside := cfg.ManagedZones().FirstOutside(set); outside {
		return d, &core.Problem{Type: core.ProblemRejectedIdentifier, Status: 400,
			Detail: fmt.Sprintf("%s is outside the zones managed by this broker", name)}
	}
	if !d.Allowed && d.Reason == "" {
		var err error
		if d, err = e.gate.Authorize(ctx, mode, src, set); err != nil {
			return d, fmt.Errorf("issuance: gate: %w", err)
		}
	}
	if !d.Allowed {
		return d, denied(d)
	}
	return d, nil
}

// denied turns a gate denial into the problem the client sees.
func denied(d core.Decision) *core.Problem {
	detail := "the source address is not authorized for the requested identifiers"
	if d.Name != "" {
		detail += ": " + d.Name
	}
	if d.Reason != "" {
		detail += " (" + d.Reason + ")"
	}
	return core.NewProblem(core.ProblemUnauthorized, "%s", detail)
}

// isCtxErr reports whether err is a context error (anywhere in its chain).
func isCtxErr(err error) bool {
	return errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded)
}

// failureProblem maps an error met during preparation or finalize to the
// Problem stored on the order.
func failureProblem(err error) *core.Problem {
	switch {
	case err == nil:
		return nil
	case isCtxErr(err):
		return core.NewProblem(core.ProblemServerInternal, "issuance was interrupted before it finished")
	case errors.Is(err, core.ErrDNSPropagation), errors.Is(err, core.ErrOutsideManagedZones):
		return &core.Problem{Type: core.ProblemDNS, Status: 500,
			Detail: "the DNS-01 challenge could not be published: " + err.Error()}
	}
	if p := core.AsProblem(err); p != nil {
		return p
	}
	if pe := core.AsProviderError(err); pe != nil || core.AsAdmissionError(err) != nil {
		return core.ProblemFromError(err)
	}
	if _, ok := err.(*dnsError); ok {
		return &core.Problem{Type: core.ProblemDNS, Status: 500, Detail: "the DNS-01 challenge could not be published"}
	}
	return core.NewProblem(core.ProblemServerInternal, "internal error during issuance")
}

// dnsError wraps a DNS engine failure so failureProblem can classify it.
type dnsError struct{ err error }

func (d *dnsError) Error() string { return "dns-01: " + d.err.Error() }
func (d *dnsError) Unwrap() error { return d.err }
