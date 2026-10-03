package issuance_test

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"tls-broker/internal/core"
	"tls-broker/internal/core/coretest"
	"tls-broker/internal/names"
)

func TestFinalizeSameCSRRetryReturnsExistingState(t *testing.T) {
	e := newEnv(t, nil)
	o := e.admit("acct", "www.example.com")
	e.waitPrepared(o.ID)
	csr := e.csr(o)
	first, err := e.finalize(o, csr)
	if err != nil || first.Status != core.OrderValid {
		t.Fatalf("first finalize: %v %+v", err, first)
	}
	second, err := e.finalize(o, csr)
	if err != nil || second.Status != core.OrderValid || second.CertificateID != first.CertificateID {
		t.Fatalf("retry: %v %+v", err, second)
	}
	if st := e.primary.Stats(); st.Finalizations != 1 || st.CertificatesIssued != 1 || st.OrdersCreated != 1 {
		t.Fatalf("upstream stats after retry: %+v", st)
	}
}

func TestFinalizeDifferentCSRRejected(t *testing.T) {
	e := newEnv(t, nil)
	o := e.admit("acct", "www.example.com")
	e.waitPrepared(o.ID)
	if _, err := e.finalize(o, e.csr(o)); err != nil {
		t.Fatal(err)
	}
	other := coretest.MakeCSR(coretest.GenKey(), "www.example.com")
	_, err := e.finalize(o, other)
	isErr(t, err, core.ErrCSRMismatch)
	if p := core.ProblemFromError(err); p.Type != core.ProblemOrderNotReady {
		t.Fatalf("client problem: %+v", p)
	}
	if st := e.primary.Stats(); st.Finalizations != 1 || st.Calls[coretest.OpFinalize] != 1 {
		t.Fatalf("a different CSR reached upstream: %+v", st)
	}
}

func TestFinalizeBadCSR(t *testing.T) {
	e := newEnv(t, nil)
	o := e.admit("acct", "www.example.com", "api.example.com")
	e.waitPrepared(o.ID)
	cases := map[string][]byte{
		"garbage":       []byte("not a csr"),
		"missing name":  coretest.MakeCSR(e.key, "www.example.com"),
		"extra name":    coretest.MakeCSR(e.key, "www.example.com", "api.example.com", "x.example.com"),
		"other name":    coretest.MakeCSR(e.key, "www.example.com", "mail.example.com"),
		"outside zones": coretest.MakeCSR(e.key, "www.example.com", "api.example.net"),
	}
	for name, csr := range cases {
		_, err := e.finalize(o, csr)
		if p := asProblem(t, err); p.Type != core.ProblemBadCSR {
			t.Fatalf("%s: %v", name, p)
		}
	}
	if got := e.order(o.ID); got.Status != core.OrderReady || got.CSRHash != "" {
		t.Fatalf("bad CSRs changed the order: %+v", got)
	}
	// The right CSR still works, with names in any order and case.
	csr := coretest.MakeCSR(e.key, "API.example.com", "www.example.com.")
	got, err := e.finalize(o, csr)
	if err != nil || got.Status != core.OrderValid {
		t.Fatalf("good CSR: %v %+v", err, got)
	}
	if e.primary.Stats().Calls[coretest.OpFinalize] != 1 {
		t.Fatal("bad CSRs reached upstream")
	}
}

func TestFinalizeBeforePreparationFinished(t *testing.T) {
	e := newEnv(t, nil)
	block := newBlocker()
	e.dns.OnPresent(block.hook)
	o := e.admit("acct", "www.example.com")
	block.wait(t)
	csr := e.csr(o)

	type res struct {
		o   *core.Order
		err error
	}
	ch := make(chan res, 1)
	go func() {
		got, err := e.finalize(o, csr)
		ch <- res{got, err}
	}()
	// Finalize holds for FinalizeWait on the clock, then answers processing.
	if !e.clock.BlockUntil(1, 5*time.Second) {
		t.Fatal("finalize did not arm its wait timer")
	}
	e.clock.Advance(20 * time.Second)
	r := <-ch
	if r.err != nil || r.o.Status != core.OrderProcessing || r.o.Prep == core.PrepPrepared {
		t.Fatalf("finalize during preparation: %v %+v", r.err, r.o)
	}
	if e.primary.Stats().Calls[coretest.OpFinalize] != 0 {
		t.Fatal("CSR sent upstream before the order was ready")
	}
	// A poll with the same CSR meanwhile returns processing too, at once.
	ch2 := make(chan res, 1)
	go func() {
		got, err := e.finalize(o, csr)
		ch2 <- res{got, err}
	}()
	if !e.clock.BlockUntil(1, 5*time.Second) {
		t.Fatal("poll did not arm its wait timer")
	}
	e.clock.Advance(20 * time.Second)
	if r := <-ch2; r.err != nil || r.o.Status != core.OrderProcessing {
		t.Fatalf("poll: %v %+v", r.err, r.o)
	}

	// Preparation completes: the recorded CSR is finalized without the client.
	close(block.release)
	got := e.waitTerminal(o.ID)
	if got.Status != core.OrderValid || got.CertificateID == "" {
		t.Fatalf("order after preparation: %+v %v", got, got.Error)
	}
	if st := e.primary.Stats(); st.Finalizations != 1 || st.OrdersCreated != 1 {
		t.Fatalf("stats: %+v", st)
	}
	if e.dns.ActiveCount() != 0 || len(e.openRefs()) != 0 {
		t.Fatal("cleanup or commit missing")
	}
	// Polling again returns the valid order.
	again, err := e.finalize(o, csr)
	if err != nil || again.Status != core.OrderValid || again.CertificateID != got.CertificateID {
		t.Fatalf("poll after valid: %v %+v", err, again)
	}
}

func TestFinalizeWrongAccountAndMissingOrder(t *testing.T) {
	e := newEnv(t, nil)
	o := e.admit("acct", "www.example.com")
	e.waitPrepared(o.ID)
	_, err := e.eng.Finalize(e.ctx, core.FinalizeRequest{OrderID: o.ID, AccountID: "other", CSRDER: e.csr(o), SourceIP: srcIP})
	isErr(t, err, core.ErrNotFound)
	_, err = e.eng.Finalize(e.ctx, core.FinalizeRequest{OrderID: "nope", AccountID: "acct", CSRDER: e.csr(o), SourceIP: srcIP})
	isErr(t, err, core.ErrNotFound)
}

func TestFinalizeRechecksGate(t *testing.T) {
	e := newEnv(t, nil)
	o := e.admit("acct", "www.example.com")
	e.waitPrepared(o.ID)
	other := netip.MustParseAddr("10.0.0.99")
	e.gate.DecideFunc(func(mode core.Mode, src netip.Addr, set names.Set) (core.Decision, error) {
		if src == other {
			return core.Decision{Allowed: false, Reason: core.ReasonDNSMismatch, Name: "www.example.com"}, nil
		}
		return allowed, nil
	})
	_, err := e.eng.Finalize(e.ctx, core.FinalizeRequest{OrderID: o.ID, AccountID: "acct", CSRDER: e.csr(o), SourceIP: other})
	if p := asProblem(t, err); p.Type != core.ProblemUnauthorized {
		t.Fatalf("finalize from an unauthorized address: %v", p)
	}
	if ev := e.events(core.AuditGate); len(ev) != 1 || ev[0].Decision != core.AuditDecisionDeny || ev[0].SourceIP != other.String() {
		t.Fatalf("gate audit: %+v", ev)
	}
	if got := e.order(o.ID); got.CSRHash != "" {
		t.Fatal("CSR recorded despite the denial")
	}
	got, err := e.finalize(o, e.csr(o))
	if err != nil || got.Status != core.OrderValid {
		t.Fatalf("finalize from the original address: %v", err)
	}
}

func TestFinalizeExpiredOrder(t *testing.T) {
	e := newEnv(t, nil)
	o := e.admit("acct", "www.example.com")
	e.waitPrepared(o.ID)
	e.clock.Advance(16 * time.Minute)
	// Before the sweep the store reports expiry itself.
	_, err := e.finalize(o, e.csr(o))
	isErr(t, err, core.ErrExpired)
	if err := e.eng.Sweep(e.ctx); err != nil {
		t.Fatal(err)
	}
	// After it, the invalid order is returned with its problem.
	got, err := e.finalize(o, e.csr(o))
	if err != nil || got.Status != core.OrderInvalid || got.Error == nil {
		t.Fatalf("finalize expired order: %v %+v", err, got)
	}
	if e.primary.Stats().Calls[coretest.OpFinalize] != 0 {
		t.Fatal("expired order was finalized upstream")
	}
}

func TestFinalizeUpstreamErrorAfterAcceptance(t *testing.T) {
	e := newEnv(t, nil)
	// The CA issues but the response is lost: the engine asks the order.
	e.primary.Inject(coretest.Fault{Op: coretest.OpFinalize, Err: e.primary.Down(), AfterEffect: true, Times: 1})
	o := e.admit("acct", "www.example.com")
	e.waitPrepared(o.ID)
	got, err := e.finalize(o, e.csr(o))
	if err != nil || got.Status != core.OrderValid {
		t.Fatalf("finalize with a lost response: %v %+v", err, got)
	}
	if st := e.primary.Stats(); st.Finalizations != 1 || st.Calls[coretest.OpGetOrder] < 1 {
		t.Fatalf("stats: %+v", st)
	}
}

func TestFinalizeUpstreamRejection(t *testing.T) {
	e := newEnv(t, nil)
	e.primary.Inject(coretest.Fault{Op: coretest.OpFinalize, Err: e.primary.Rejected(core.ProblemBadCSR, "key too small")})
	o := e.admit("acct", "www.example.com")
	e.waitPrepared(o.ID)
	csr := e.csr(o)
	got, err := e.finalize(o, csr)
	if err != nil || got.Status != core.OrderInvalid || got.Error == nil || got.Error.Type != core.ProblemBadCSR {
		t.Fatalf("finalize rejected upstream: %v %+v %v", err, got, got.Error)
	}
	if refs := e.openRefs(); len(refs) != 0 {
		t.Fatalf("budget not refunded: %v", refs)
	}
	if issues := e.events(core.AuditIssue); len(issues) != 1 || issues[0].Result != core.AuditResultFailed {
		t.Fatalf("issue audit: %+v", issues)
	}
	// The same CSR again returns the failed order; nothing new upstream.
	again, err := e.finalize(o, csr)
	if err != nil || again.Status != core.OrderInvalid {
		t.Fatalf("retry: %v %+v", err, again)
	}
	if st := e.primary.Stats(); st.Calls[coretest.OpFinalize] != 1 || st.OrdersCreated != 1 {
		t.Fatalf("stats: %+v", st)
	}
}

func TestFinalizeContinuesWithoutClient(t *testing.T) {
	e := newEnv(t, nil)
	e.primary.Inject(coretest.Fault{Op: coretest.OpWaitCertificate, Delay: time.Minute, Times: 1})
	o := e.admit("acct", "www.example.com")
	e.waitPrepared(o.ID)
	ctx, cancel := context.WithCancel(e.ctx)
	type res struct {
		o   *core.Order
		err error
	}
	ch := make(chan res, 1)
	go func() {
		got, err := e.eng.Finalize(ctx, core.FinalizeRequest{OrderID: o.ID, AccountID: "acct", CSRDER: e.csr(o), SourceIP: srcIP})
		ch <- res{got, err}
	}()
	// Two timers: the CA's delay and the finalize wait.
	if !e.clock.BlockUntil(2, 5*time.Second) {
		t.Fatal("timers not armed")
	}
	cancel()
	r := <-ch
	if r.err != nil || r.o.Status != core.OrderProcessing {
		t.Fatalf("finalize with a vanished client: %v %+v", r.err, r.o)
	}
	e.clock.Advance(time.Minute)
	got := e.waitTerminal(o.ID)
	if got.Status != core.OrderValid {
		t.Fatalf("order did not complete without the client: %+v %v", got, got.Error)
	}
}
