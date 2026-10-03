package issuance_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"tls-broker/internal/core"
	"tls-broker/internal/core/coretest"
)

// seedOrder writes an order row the way admission would and takes the
// matching reservation, to stage a crash state the fakes cannot freeze.
func (e *env) seedOrder(mode core.Mode, prep core.PrepState, upstreamURL string) *core.Order {
	e.t.Helper()
	now := e.clock.Now()
	o := &core.Order{ID: core.NewID(), Mode: mode, AccountID: "acct", Names: e.set("seed.example.com"), SourceIP: srcIP,
		Status: core.OrderReady, Prep: core.PrepIntent, Class: core.ClassACMEOrdinary, Provider: "primary",
		CreatedAt: now, ExpiresAt: now.Add(15 * time.Minute), UpdatedAt: now}
	if mode == core.ModeDirect {
		o.AccountID, o.Class = "", core.ClassDirectMiss
	}
	t, err := e.sched.Acquire(e.ctx, core.AdmissionRequest{Ref: o.ID, Provider: "primary", Names: o.Names, Class: o.Class})
	if err != nil {
		e.t.Fatal(err)
	}
	if err := e.st.Orders().Create(e.ctx, o); err != nil {
		e.t.Fatal(err)
	}
	if upstreamURL != "" {
		t.OrderCreated()
		if err := e.st.Orders().SetUpstream(e.ctx, o.ID, upstreamURL, "", now.Add(7*day), now); err != nil {
			e.t.Fatal(err)
		}
		o.Prep = core.PrepPreparing
	}
	if prep == core.PrepPrepared {
		if err := e.st.Orders().SetPrepared(e.ctx, o.ID, now); err != nil {
			e.t.Fatal(err)
		}
	}
	return e.order(o.ID)
}

func (e *env) budgetStates(ref string) map[core.BudgetKind]core.BudgetState {
	e.t.Helper()
	out := map[core.BudgetKind]core.BudgetState{}
	evs, err := e.st.Budgets().ListByRef(e.ctx, ref)
	if err != nil {
		e.t.Fatal(err)
	}
	for _, ev := range evs {
		out[ev.Kind] = ev.State
	}
	return out
}

func TestRecoverIntentWithoutUpstreamURL(t *testing.T) {
	e := newEnv(t, nil)
	o := e.seedOrder(core.ModeACME, core.PrepIntent, "")
	e.restart()
	got := e.order(o.ID)
	if got.Status != core.OrderInvalid || got.Prep != core.PrepFailed || got.Error == nil {
		t.Fatalf("intent order after restart: %+v", got)
	}
	// The new-order budget counts as spent; certificate budgets are back.
	states := e.budgetStates(o.ID)
	if states[core.BudgetNewOrder] != core.BudgetCommitted || len(states) != 1 {
		t.Fatalf("budget events: %v", states)
	}
	if refs := e.openRefs(); len(refs) != 0 {
		t.Fatalf("open reservations: %v", refs)
	}
	if e.primary.Stats().OrdersCreated != 0 {
		t.Fatal("recovery created an upstream order")
	}
	if ev := e.events(core.AuditIssue); len(ev) != 1 || ev[0].Result != core.AuditResultFailed {
		t.Fatalf("audit: %+v", ev)
	}
}

func TestRecoverResumesPreparation(t *testing.T) {
	e := newEnv(t, nil)
	block := newBlocker()
	e.dns.OnPresent(block.hook)
	o := e.admit("acct", "www.example.com")
	block.wait(t)
	// Crash while the TXT value is being published.
	e.crash()
	got := e.order(o.ID)
	if got.Status != core.OrderReady || got.Prep != core.PrepPreparing || got.UpstreamOrderURL == "" {
		t.Fatalf("order after crash: %+v", got)
	}
	if up := e.primary.Orders(); len(up) != 1 || up[0].Status != core.UpstreamPending {
		t.Fatalf("upstream after crash: %+v", up)
	}
	e.dns.OnPresent(nil)
	e.start()
	if err := e.eng.Recover(e.ctx); err != nil {
		t.Fatal(err)
	}
	got = e.waitPrepared(o.ID)
	if got.Status != core.OrderReady || got.Prep != core.PrepPrepared {
		t.Fatalf("resumed order: %+v %v", got, got.Error)
	}
	if st := e.primary.Stats(); st.OrdersCreated != 1 || st.Calls[coretest.OpGetOrder] < 1 {
		t.Fatalf("stats: %+v", st)
	}
	valid, err := e.finalize(got, e.csr(got))
	if err != nil || valid.Status != core.OrderValid {
		t.Fatalf("finalize after recovery: %v %+v", err, valid)
	}
	if len(e.openRefs()) != 0 || e.dns.ActiveCount() != 0 {
		t.Fatal("budget or DNS not settled after recovery")
	}
	e.assertOneUpstreamPerOrder()
}

func TestRecoverResumesPreparationWithRecordedCSR(t *testing.T) {
	e := newEnv(t, nil)
	block := newBlocker()
	e.dns.OnPresent(block.hook)
	o := e.admit("acct", "www.example.com")
	block.wait(t)
	csr := e.csr(o)
	ch := make(chan error, 1)
	go func() {
		_, err := e.finalize(o, csr)
		ch <- err
	}()
	if !e.clock.BlockUntil(1, 5*time.Second) {
		t.Fatal("finalize wait not armed")
	}
	e.clock.Advance(20 * time.Second)
	if err := <-ch; err != nil {
		t.Fatal(err)
	}
	e.crash()
	got := e.order(o.ID)
	if got.Status != core.OrderProcessing || got.Prep != core.PrepPreparing || len(got.CSRDER) == 0 {
		t.Fatalf("order after crash: %+v", got)
	}
	e.dns.OnPresent(nil)
	e.start()
	if err := e.eng.Recover(e.ctx); err != nil {
		t.Fatal(err)
	}
	got = e.waitTerminal(o.ID)
	if got.Status != core.OrderValid {
		t.Fatalf("order after recovery: %+v %v", got, got.Error)
	}
	if st := e.primary.Stats(); st.OrdersCreated != 1 || st.Finalizations != 1 {
		t.Fatalf("stats: %+v", st)
	}
}

func TestRecoverResumesFinalize(t *testing.T) {
	e := newEnv(t, nil)
	e.primary.Inject(coretest.Fault{Op: coretest.OpFinalize, Delay: time.Hour})
	o := e.admit("acct", "www.example.com")
	e.waitPrepared(o.ID)
	csr := e.csr(o)
	ch := make(chan *core.Order, 1)
	go func() {
		got, _ := e.finalize(o, csr)
		ch <- got
	}()
	if !e.clock.BlockUntil(2, 5*time.Second) {
		t.Fatal("timers not armed")
	}
	e.clock.Advance(20 * time.Second)
	if got := <-ch; got == nil || got.Status != core.OrderProcessing {
		t.Fatalf("finalize: %+v", got)
	}
	e.crash()
	got := e.order(o.ID)
	if got.Status != core.OrderProcessing || got.Prep != core.PrepPrepared || len(got.CSRDER) == 0 {
		t.Fatalf("order after crash: %+v", got)
	}
	if e.primary.Stats().Finalizations != 0 {
		t.Fatal("CSR was accepted before the crash")
	}
	e.primary.ClearFaults()
	e.start()
	if err := e.eng.Recover(e.ctx); err != nil {
		t.Fatal(err)
	}
	got = e.waitTerminal(o.ID)
	if got.Status != core.OrderValid || got.CertificateID == "" {
		t.Fatalf("order after recovery: %+v %v", got, got.Error)
	}
	cert := e.cert(got.CertificateID)
	if _, err := e.primary.VerifyChain(cert.ChainPEM, "www.example.com"); err != nil {
		t.Fatal(err)
	}
	if st := e.primary.Stats(); st.OrdersCreated != 1 || st.Finalizations != 1 {
		t.Fatalf("stats: %+v", st)
	}
	if len(e.openRefs()) != 0 {
		t.Fatal("reservation not committed after recovery")
	}
	// The client's poll finds the certificate.
	again, err := e.finalize(o, csr)
	if err != nil || again.Status != core.OrderValid {
		t.Fatalf("poll: %v %+v", err, again)
	}
}

func TestRecoverLeavesValidAndPreparedOrdersAlone(t *testing.T) {
	e := newEnv(t, nil)
	valid, cert := e.issue("acct", "www.example.com")
	ready := e.admit("other", "www.example.com")
	e.waitPrepared(ready.ID)
	e.restart()
	if got := e.order(valid.ID); got.Status != core.OrderValid || got.CertificateID != cert.ID {
		t.Fatalf("valid order changed: %+v", got)
	}
	got := e.order(ready.ID)
	if got.Status != core.OrderReady || got.Prep != core.PrepPrepared {
		t.Fatalf("prepared order changed: %+v", got)
	}
	if refs := e.openRefs(); len(refs) != 1 || refs[0] != ready.ID {
		t.Fatalf("open reservations: %v", refs)
	}
	// The waiting order can still be finalized, and settles its budget.
	fin, err := e.finalize(got, e.csr(got))
	if err != nil || fin.Status != core.OrderValid {
		t.Fatalf("finalize after restart: %v %+v", err, fin)
	}
	if len(e.openRefs()) != 0 {
		t.Fatal("reservation not settled")
	}
	if st := e.primary.Stats(); st.OrdersCreated != 2 {
		t.Fatalf("stats: %+v", st)
	}
}

func TestRecoverFailsDirectModeInFlight(t *testing.T) {
	e := newEnv(t, nil)
	up, err := e.primary.NewOrder(e.ctx, []string{"seed.example.com"}, "")
	if err != nil {
		t.Fatal(err)
	}
	preparing := e.seedOrder(core.ModeDirect, core.PrepPreparing, up.URL)
	up2, err := e.primary.NewOrder(e.ctx, []string{"seed.example.com"}, "")
	if err != nil {
		t.Fatal(err)
	}
	prepared := e.seedOrder(core.ModeDirect, core.PrepPrepared, up2.URL)
	e.restart()
	a, b := e.order(preparing.ID), e.order(prepared.ID)
	if a.Status != core.OrderInvalid || a.Prep != core.PrepFailed {
		t.Fatalf("preparing direct order: %+v", a)
	}
	if b.Status != core.OrderInvalid || b.Prep != core.PrepPrepared {
		t.Fatalf("prepared direct order: %+v", b)
	}
	if refs := e.openRefs(); len(refs) != 0 {
		t.Fatalf("open reservations: %v", refs)
	}
	for _, id := range []string{a.ID, b.ID} {
		if st := e.budgetStates(id); st[core.BudgetNewOrder] != core.BudgetCommitted || len(st) != 1 {
			t.Fatalf("budget of %s: %v", id, st)
		}
	}
	// The prepared one is adoptable by the next request for the set.
	o := e.admit("acct", "seed.example.com")
	if o.Prep != core.PrepPrepared || o.UpstreamOrderURL != up2.URL {
		t.Fatalf("adoption after recovery: %+v", o)
	}
}

func TestRecoverSettlesOrphanedReservations(t *testing.T) {
	e := newEnv(t, nil)
	// A reservation whose order was never written (crash between Acquire
	// and Create) and one whose order is valid but was never committed.
	if _, err := e.sched.Acquire(e.ctx, core.AdmissionRequest{Ref: "ghost", Provider: "primary", Names: e.set("g.example.com"), Class: core.ClassACMEOrdinary}); err != nil {
		t.Fatal(err)
	}
	valid, _ := e.issue("acct", "www.example.com")
	if _, err := e.sched.Acquire(e.ctx, core.AdmissionRequest{Ref: valid.ID, Provider: "primary", Names: valid.Names, Class: core.ClassACMEOrdinary}); err != nil {
		t.Fatal(err)
	}
	e.restart()
	if refs := e.openRefs(); len(refs) != 0 {
		t.Fatalf("open reservations after recovery: %v", refs)
	}
	if st := e.budgetStates("ghost"); len(st) != 0 {
		t.Fatalf("ghost reservation not released: %v", st)
	}
	if st := e.budgetStates(valid.ID); st[core.BudgetCertSet] != core.BudgetCommitted {
		t.Fatalf("valid order's reservation not committed: %v", st)
	}
}

func TestSweepExpiresAndCompacts(t *testing.T) {
	e := newEnv(t, nil)
	block := newBlocker()
	e.dns.OnPresent(block.hook)
	stuck := e.admit("a", "stuck.example.com")
	block.wait(t)
	e.dns.OnPresent(nil)
	valid, cert := e.issue("b", "done.example.com")
	waiting := e.admit("c", "wait.example.com")
	e.waitPrepared(waiting.ID)

	e.clock.Advance(16 * time.Minute)
	if err := e.eng.Sweep(e.ctx); err != nil {
		t.Fatal(err)
	}
	// Both unfinalized orders expired; the prepared one stays adoptable.
	if got := e.order(waiting.ID); got.Status != core.OrderInvalid || got.Prep != core.PrepPrepared {
		t.Fatalf("waiting order: %+v", got)
	}
	if got := e.order(stuck.ID); got.Status != core.OrderInvalid || got.Prep != core.PrepFailed {
		t.Fatalf("stuck order: %+v", got)
	}
	if refs := e.openRefs(); len(refs) != 0 {
		t.Fatalf("open reservations: %v", refs)
	}
	if e.budgetUsed("primary", core.BudgetCertSet) != 1 {
		t.Fatalf("cert_set usage %d, want 1 (the issued certificate)", e.budgetUsed("primary", core.BudgetCertSet))
	}
	// The stuck preparation finishes late and finds its order gone.
	close(block.release)
	e.waitUntil("stuck preparation to end", func() bool { return e.dns.ActiveCount() == 0 })
	if got := e.order(stuck.ID); got.Status != core.OrderInvalid {
		t.Fatalf("late preparation revived the order: %+v", got)
	}
	// The expired order's client gets the failure on finalize.
	fin, err := e.finalize(waiting, e.csr(waiting))
	if err != nil || fin.Status != core.OrderInvalid {
		t.Fatalf("finalize expired: %v %+v", err, fin)
	}

	// A week later finished orders are pruned; certificates stay.
	e.clock.Advance(8 * day)
	if err := e.eng.Sweep(e.ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := e.st.Orders().Get(e.ctx, valid.ID); !errors.Is(err, core.ErrNotFound) {
		t.Fatalf("valid order not pruned: %v", err)
	}
	if c := e.cert(cert.ID); len(c.ChainPEM) == 0 {
		t.Fatal("chain dropped before expiry")
	}
	// Long after expiry the chain is dropped, the metadata kept.
	e.clock.Set(cert.NotAfter.Add(31 * day))
	if err := e.eng.Sweep(e.ctx); err != nil {
		t.Fatal(err)
	}
	if c := e.cert(cert.ID); len(c.ChainPEM) != 0 || c.Serial == "" {
		t.Fatalf("chain retention: %+v", c)
	}
}

func TestCloseWaitsForBackgroundWork(t *testing.T) {
	e := newEnv(t, nil)
	e.primary.Inject(coretest.Fault{Op: coretest.OpWaitReady, Delay: time.Minute, Times: 1})
	o := e.admit("acct", "www.example.com")
	if !e.clock.BlockUntil(1, 5*time.Second) {
		t.Fatal("CA delay not armed")
	}
	done := make(chan struct{})
	go func() {
		_ = e.eng.Close(context.Background())
		close(done)
	}()
	select {
	case <-done:
		t.Fatal("Close returned while preparation was running")
	case <-time.After(50 * time.Millisecond):
	}
	e.clock.Advance(time.Minute)
	<-done
	if got := e.order(o.ID); got.Prep != core.PrepPrepared {
		t.Fatalf("order after graceful close: %+v", got)
	}
}
