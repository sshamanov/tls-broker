package issuance_test

import (
	"context"
	"crypto/ecdsa"
	"errors"
	"io"
	"log/slog"
	"net/netip"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"tls-broker/internal/core"
	"tls-broker/internal/core/coretest"
	"tls-broker/internal/issuance"
	"tls-broker/internal/names"
	"tls-broker/internal/sched"
	"tls-broker/internal/store"
)

const day = 24 * time.Hour

var (
	srcIP   = netip.MustParseAddr("10.0.0.7")
	allowed = core.Decision{Allowed: true, Reason: core.ReasonDNSIPMatch}
	granted = core.Decision{Allowed: true, Reason: core.ReasonIPGrant, GrantID: 42}
)

// env wires the engine to a real SQLite store and a real scheduler, with
// fakes for the CAs, Route53, the public resolver, the gate and the clock.
type env struct {
	t         *testing.T
	ctx       context.Context
	clock     *coretest.FakeClock
	cfg       *coretest.FakeConfig
	st        *store.Store
	sched     *sched.Scheduler
	primary   *coretest.FakeCA
	fallback  *coretest.FakeCA
	providers *coretest.FakeProviders
	resolver  *coretest.FakeResolver
	dns       *coretest.FakeDNSEngine
	gate      *coretest.FakeGate
	auditor   *coretest.FakeAuditor
	eng       *issuance.Engine
	key       *ecdsa.PrivateKey
}

func newEnv(t *testing.T, mutate func(c *core.Config)) *env {
	t.Helper()
	cfg := coretest.NewConfig()
	if mutate != nil {
		mutate(cfg)
	}
	clock := coretest.NewFakeClock()
	st, err := store.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	resolver := coretest.NewFakeResolver()
	e := &env{
		t: t, ctx: context.Background(), clock: clock, cfg: coretest.NewFakeConfig(cfg), st: st,
		primary: coretest.NewFakeCA("primary", clock), fallback: coretest.NewFakeCA("fallback", clock),
		resolver: resolver, dns: coretest.NewFakeDNSEngine(resolver, clock),
		gate: coretest.NewFakeGate(), auditor: coretest.NewFakeAuditor(clock), key: coretest.GenKey(),
	}
	e.primary.SetTXTLookup(resolver.LookupTXT)
	e.fallback.SetTXTLookup(resolver.LookupTXT)
	e.fallback.SetCaps(core.ProviderCaps{ARI: true, ARIExempt: false, CAAIssuers: []string{"fallback.test"}, AccountURIHonoured: true})
	e.providers = coretest.NewFakeProviders(e.primary, e.fallback)
	e.start()
	return e
}

// start builds the scheduler and the engine on the current stores.
func (e *env) start() {
	e.t.Helper()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	s, err := sched.New(e.ctx, sched.Options{Config: e.cfg, Budgets: e.st.Budgets(), States: e.st.ProviderStates(),
		Clock: e.clock, Auditor: e.auditor, Logger: logger})
	if err != nil {
		e.t.Fatalf("sched.New: %v", err)
	}
	e.sched = s
	eng, err := issuance.New(issuance.Options{
		Config: e.cfg, Clock: e.clock, Orders: e.st.Orders(), Certs: e.st.Certificates(), Lineages: e.st.Lineages(),
		Providers: e.providers, DNS: e.dns, Scheduler: s, Gate: e.gate, Auditor: e.auditor, Logger: logger,
	})
	if err != nil {
		e.t.Fatalf("issuance.New: %v", err)
	}
	e.eng = eng
	e.t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = eng.Close(ctx)
		_ = s.Close()
	})
}

// crash stops the engine abruptly: background work is interrupted and left
// in its persisted state, like a process kill.
func (e *env) crash() {
	e.t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if err := e.eng.Close(ctx); err != nil {
		e.t.Fatalf("Close: %v", err)
	}
	_ = e.sched.Close()
}

// restart is crash followed by a fresh scheduler and engine with Recover.
func (e *env) restart() {
	e.t.Helper()
	e.crash()
	e.start()
	if err := e.eng.Recover(e.ctx); err != nil {
		e.t.Fatalf("Recover: %v", err)
	}
}

func (e *env) set(n ...string) names.Set { return names.MustSet(n...) }

func (e *env) admit(account string, n ...string) *core.Order {
	e.t.Helper()
	o, err := e.eng.Admit(e.ctx, core.AdmitRequest{AccountID: account, Names: e.set(n...), SourceIP: srcIP, Decision: allowed})
	if err != nil {
		e.t.Fatalf("Admit(%v): %v", n, err)
	}
	return o
}

func (e *env) order(id string) *core.Order {
	e.t.Helper()
	o, err := e.st.Orders().Get(e.ctx, id)
	if err != nil {
		e.t.Fatalf("Orders.Get(%s): %v", id, err)
	}
	return o
}

// waitOrder polls (in real time) until the order satisfies pred.
func (e *env) waitOrder(id string, what string, pred func(*core.Order) bool) *core.Order {
	e.t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		o := e.order(id)
		if pred(o) {
			return o
		}
		if time.Now().After(deadline) {
			e.t.Fatalf("order %s never became %s (status %s, prep %s, err %v)", id, what, o.Status, o.Prep, o.Error)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func (e *env) waitPrepared(id string) *core.Order {
	e.t.Helper()
	return e.waitOrder(id, "prepared", func(o *core.Order) bool { return o.Prep == core.PrepPrepared || o.Status == core.OrderInvalid })
}

func (e *env) waitTerminal(id string) *core.Order {
	e.t.Helper()
	return e.waitOrder(id, "terminal", func(o *core.Order) bool { return o.Status.Terminal() })
}

// waitUntil polls a condition in real time.
func (e *env) waitUntil(what string, cond func() bool) {
	e.t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			e.t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func (e *env) csr(o *core.Order) []byte { return coretest.MakeCSR(e.key, o.Names.Names()...) }

func (e *env) finalize(o *core.Order, csr []byte) (*core.Order, error) {
	e.t.Helper()
	return e.eng.Finalize(e.ctx, core.FinalizeRequest{OrderID: o.ID, AccountID: o.AccountID, CSRDER: csr, SourceIP: srcIP})
}

// issue runs the whole ACME flow for one account and set and returns the
// valid order and its certificate.
func (e *env) issue(account string, n ...string) (*core.Order, *core.Certificate) {
	e.t.Helper()
	o := e.admit(account, n...)
	e.waitPrepared(o.ID)
	got, err := e.finalize(o, e.csr(o))
	if err != nil {
		e.t.Fatalf("Finalize: %v", err)
	}
	if got.Status != core.OrderValid {
		e.t.Fatalf("order %s after finalize: status %s, error %v", o.ID, got.Status, got.Error)
	}
	return got, e.cert(got.CertificateID)
}

func (e *env) cert(id string) *core.Certificate {
	e.t.Helper()
	c, err := e.st.Certificates().Get(e.ctx, id)
	if err != nil {
		e.t.Fatalf("Certificates.Get(%s): %v", id, err)
	}
	return c
}

func (e *env) openRefs() []string {
	e.t.Helper()
	refs, err := e.sched.OpenRefs(e.ctx)
	if err != nil {
		e.t.Fatalf("OpenRefs: %v", err)
	}
	return refs
}

func (e *env) snapshot(provider string) core.ProviderSnapshot {
	e.t.Helper()
	for _, p := range e.sched.Snapshot().Providers {
		if p.Name == provider {
			return p
		}
	}
	e.t.Fatalf("provider %q not in snapshot", provider)
	return core.ProviderSnapshot{}
}

// budgetUsed returns the usage of one budget kind for a provider.
func (e *env) budgetUsed(provider string, kind core.BudgetKind) int {
	e.t.Helper()
	for _, b := range e.snapshot(provider).Budgets {
		if b.Kind == kind {
			return b.Used
		}
	}
	return 0
}

// down closes the provider's circuit as an outage signal would.
func (e *env) down(provider string) {
	ca := e.primary
	if provider == "fallback" {
		ca = e.fallback
	}
	e.sched.ReportProvider(e.ctx, provider, ca.Down())
}

func (e *env) events(typ string) []core.AuditEvent { return e.auditor.OfType(typ) }

// upstreamURLs returns the distinct upstream order URLs of all stored orders.
func (e *env) assertOneUpstreamPerOrder() {
	e.t.Helper()
	list, err := e.st.Orders().List(e.ctx, core.OrderFilter{Limit: 1000})
	if err != nil {
		e.t.Fatal(err)
	}
	owners := map[string]string{}
	for _, o := range list {
		if o.UpstreamOrderURL == "" || o.AdoptedByOrderID != "" {
			continue
		}
		if prev, ok := owners[o.UpstreamOrderURL]; ok {
			e.t.Errorf("upstream order %s is owned by both %s and %s", o.UpstreamOrderURL, prev, o.ID)
		}
		owners[o.UpstreamOrderURL] = o.ID
	}
	total := e.primary.Stats().OrdersCreated + e.fallback.Stats().OrdersCreated
	if total < len(owners) {
		e.t.Errorf("%d upstream orders at the CAs but %d distinct URLs owned", total, len(owners))
	}
}

func asAdmission(t *testing.T, err error) *core.AdmissionError {
	t.Helper()
	ae := core.AsAdmissionError(err)
	if ae == nil {
		t.Fatalf("expected *AdmissionError, got %T: %v", err, err)
	}
	return ae
}

func asProblem(t *testing.T, err error) *core.Problem {
	t.Helper()
	p := core.AsProblem(err)
	if p == nil {
		t.Fatalf("expected *Problem, got %T: %v", err, err)
	}
	return p
}

func isErr(t *testing.T, err, target error) {
	t.Helper()
	if !errors.Is(err, target) {
		t.Fatalf("expected %v, got %v", target, err)
	}
}

// blocker is a Present hook that parks every call until released (or its
// context ends) and tells the test when the first call arrived.
type blocker struct {
	entered chan struct{}
	release chan struct{}
	once    sync.Once
}

func newBlocker() *blocker {
	return &blocker{entered: make(chan struct{}), release: make(chan struct{})}
}

func (b *blocker) hook(ctx context.Context, owner, record, value string) error {
	b.once.Do(func() { close(b.entered) })
	select {
	case <-b.release:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (b *blocker) wait(t *testing.T) {
	t.Helper()
	select {
	case <-b.entered:
	case <-time.After(5 * time.Second):
		t.Fatal("Present was never called")
	}
}
