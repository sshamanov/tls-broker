package issuance_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"tls-broker/internal/core"
	"tls-broker/internal/core/coretest"
)

func TestNewIssuance(t *testing.T) {
	e := newEnv(t, nil)
	o, err := e.eng.Admit(e.ctx, core.AdmitRequest{AccountID: "acct", Names: e.set("www.example.com"), SourceIP: srcIP, Decision: granted})
	if err != nil {
		t.Fatal(err)
	}
	if o.Status != core.OrderReady || o.Prep != core.PrepIntent || o.Provider != "primary" || o.Class != core.ClassACMEOrdinary {
		t.Fatalf("admitted order: %+v", o)
	}
	if o.GrantID != 42 || o.ARIQualified {
		t.Fatalf("grant/ARI not recorded: %+v", o)
	}
	o = e.waitPrepared(o.ID)
	if o.Prep != core.PrepPrepared || o.UpstreamOrderURL == "" || o.UpstreamReplaces != "" {
		t.Fatalf("prepared order: %+v", o)
	}
	if e.dns.ActiveCount() != 0 {
		t.Fatalf("TXT values left after preparation: %d", e.dns.ActiveCount())
	}
	if up := e.primary.Orders(); len(up) != 1 || up[0].Status != core.UpstreamReady {
		t.Fatalf("upstream orders: %+v", up)
	}
	// The slot is released after preparation; the reservation stays.
	if snap := e.snapshot("primary"); snap.SlotsInUse != 0 || snap.Reserved != 1 {
		t.Fatalf("after prep: slots %d reserved %d", snap.SlotsInUse, snap.Reserved)
	}

	got, err := e.finalize(o, e.csr(o))
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != core.OrderValid || got.CertificateID == "" || len(got.CSRDER) != 0 {
		t.Fatalf("finalized order: %+v", got)
	}
	cert := e.cert(got.CertificateID)
	leaf, err := e.primary.VerifyChain(cert.ChainPEM, "www.example.com")
	if err != nil {
		t.Fatalf("chain: %v", err)
	}
	if id, _ := core.ARICertID(leaf); id != cert.ARICertID || cert.Provider != "primary" || cert.AccountURL == "" || cert.Mode != core.ModeACME {
		t.Fatalf("certificate row: %+v", cert)
	}
	if !cert.NotAfter.Equal(leaf.NotAfter) || cert.ReplacesID != "" {
		t.Fatalf("certificate row: %+v", cert)
	}
	// Budget committed: nothing open, every bucket used once.
	if refs := e.openRefs(); len(refs) != 0 {
		t.Fatalf("open reservations after issue: %v", refs)
	}
	for _, k := range []core.BudgetKind{core.BudgetNewOrder, core.BudgetCertDomain, core.BudgetCertSet} {
		if e.budgetUsed("primary", k) != 1 {
			t.Fatalf("budget %s used %d, want 1", k, e.budgetUsed("primary", k))
		}
	}
	if lin, err := e.st.Lineages().Get(e.ctx, "www.example.com"); err != nil || lin.LastRequestAt.IsZero() {
		t.Fatalf("lineage not observed: %v %v", lin, err)
	}
	orders := e.events(core.AuditOrder)
	if len(orders) != 1 || orders[0].Decision != core.AuditDecisionAllow || orders[0].GrantID != 42 || orders[0].Reason != core.ReasonIPGrant {
		t.Fatalf("order audit: %+v", orders)
	}
	issues := e.events(core.AuditIssue)
	if len(issues) != 1 || issues[0].Result != core.AuditResultOK || issues[0].CertNotAfter == nil || issues[0].CertificateID != cert.ID ||
		issues[0].Visibility != core.AuditVisibilityAll {
		t.Fatalf("issue audit: %+v", issues)
	}
	e.assertOneUpstreamPerOrder()
}

func TestAdmitRejectsBadRequests(t *testing.T) {
	e := newEnv(t, nil)
	_, err := e.eng.Admit(e.ctx, core.AdmitRequest{AccountID: "a", Names: e.set("www.other.net"), SourceIP: srcIP, Decision: allowed})
	if p := asProblem(t, err); p.Type != core.ProblemRejectedIdentifier {
		t.Fatalf("outside zone: %v", p)
	}
	denyAll := core.Decision{Allowed: false, Reason: core.ReasonDNSMismatch, Name: "www.example.com"}
	_, err = e.eng.Admit(e.ctx, core.AdmitRequest{AccountID: "a", Names: e.set("www.example.com"), SourceIP: srcIP, Decision: denyAll})
	if p := asProblem(t, err); p.Type != core.ProblemUnauthorized {
		t.Fatalf("denied: %v", p)
	}
	// A zero decision makes the engine run the gate itself.
	e.gate.Decide(core.Decision{Allowed: false, Reason: core.ReasonWildcardGrantRequired})
	_, err = e.eng.Admit(e.ctx, core.AdmitRequest{AccountID: "a", Names: e.set("*.example.com"), SourceIP: srcIP})
	if p := asProblem(t, err); p.Type != core.ProblemUnauthorized || !strings.Contains(p.Detail, core.ReasonWildcardGrantRequired) {
		t.Fatalf("gate denial: %v", p)
	}
	if n := len(e.gate.Calls()); n != 1 {
		t.Fatalf("gate calls: %d", n)
	}
	if e.primary.Stats().OrdersCreated != 0 {
		t.Fatal("upstream order created for a rejected request")
	}
}

func TestAdmitReusesOpenOrder(t *testing.T) {
	e := newEnv(t, nil)
	a := e.admit("acct", "www.example.com", "example.com")
	b := e.admit("acct", "example.com", "www.example.com")
	if a.ID != b.ID {
		t.Fatalf("second newOrder got a different order: %s vs %s", a.ID, b.ID)
	}
	c := e.admit("other", "www.example.com", "example.com")
	if c.ID == a.ID {
		t.Fatal("another account was handed the first account's order")
	}
	e.waitPrepared(a.ID)
	e.waitPrepared(c.ID)
	if n := e.primary.Stats().OrdersCreated; n != 2 {
		t.Fatalf("upstream orders: %d, want 2", n)
	}
	e.assertOneUpstreamPerOrder()
}

func TestRenewalStaysOnItsProvider(t *testing.T) {
	e := newEnv(t, nil)
	e.providers.SetDisabled("primary", true)
	_, first := e.issue("acct", "www.example.com")
	if first.Provider != "fallback" {
		t.Fatalf("first certificate from %s", first.Provider)
	}
	e.providers.SetDisabled("primary", false)
	e.clock.Advance(30 * day)

	o := e.admit("acct", "www.example.com")
	if o.Provider != "fallback" || o.Class != core.ClassACMEOrdinary || o.ARIQualified {
		t.Fatalf("renewal order: provider %s class %s ari %v", o.Provider, o.Class, o.ARIQualified)
	}
	o = e.waitPrepared(o.ID)
	// `replaces` is inferred even though the fallback does not exempt ARI.
	if o.UpstreamReplaces != first.ARICertID {
		t.Fatalf("UpstreamReplaces %q, want %q", o.UpstreamReplaces, first.ARICertID)
	}
	up := e.fallback.Orders()
	if len(up) != 2 || up[1].Replaces != first.ARICertID || up[1].Exempt {
		t.Fatalf("fallback orders: %+v", up)
	}
	if e.primary.Stats().OrdersCreated != 0 {
		t.Fatal("renewal went to the primary")
	}
	if len(e.events(core.AuditFailover)) != 0 {
		t.Fatal("a sticky renewal was audited as failover")
	}
}

func TestARIQualifiedRenewal(t *testing.T) {
	e := newEnv(t, nil)
	_, c1 := e.issue("acct", "www.example.com")
	// FakeCA window: starts at 2/3 of the lifetime, 48 h long.
	e.clock.Advance(60*day + time.Hour)

	o := e.admit("acct", "www.example.com")
	if !o.ARIQualified || o.Class != core.ClassARIRenewal {
		t.Fatalf("not ARI-qualified: %+v", o)
	}
	// ARI-qualified admission reserves no budget.
	if refs := e.openRefs(); len(refs) != 0 {
		t.Fatalf("budget reserved for ARI renewal: %v", refs)
	}
	o = e.waitPrepared(o.ID)
	if o.UpstreamReplaces != c1.ARICertID {
		t.Fatalf("UpstreamReplaces %q, want %q", o.UpstreamReplaces, c1.ARICertID)
	}
	up := e.primary.Orders()
	if len(up) != 2 || !up[1].Exempt || up[1].Replaces != c1.ARICertID {
		t.Fatalf("upstream orders: %+v", up)
	}
	got, err := e.finalize(o, e.csr(o))
	if err != nil || got.Status != core.OrderValid {
		t.Fatalf("finalize: %v %+v", err, got)
	}
	c2 := e.cert(got.CertificateID)
	if c2.ReplacesID != c1.ID {
		t.Fatalf("c2.ReplacesID %q, want %q", c2.ReplacesID, c1.ID)
	}
	if e.cert(c1.ID).ReplacedByID != c2.ID {
		t.Fatal("predecessor not marked replaced")
	}
	// No budget event at all belongs to the exempt renewal.
	if evs, _ := e.st.Budgets().ListByRef(e.ctx, o.ID); len(evs) != 0 {
		t.Fatalf("budget events of ARI renewal: %+v", evs)
	}
	if ev := e.events(core.AuditOrder); !strings.Contains(ev[1].Detail, "ARI-qualified") {
		t.Fatalf("audit detail: %q", ev[1].Detail)
	}
}

func TestRenewalOutsideWindowIsOrdinary(t *testing.T) {
	e := newEnv(t, nil)
	_, c1 := e.issue("acct", "www.example.com")
	e.clock.Advance(10 * day)
	o := e.admit("acct", "www.example.com")
	if o.ARIQualified || o.Class != core.ClassACMEOrdinary {
		t.Fatalf("order: ari %v class %s", o.ARIQualified, o.Class)
	}
	if refs := e.openRefs(); len(refs) != 1 || refs[0] != o.ID {
		t.Fatalf("ordinary renewal should reserve budget: %v", refs)
	}
	o = e.waitPrepared(o.ID)
	up := e.primary.Orders()
	if o.UpstreamReplaces != c1.ARICertID || up[1].Exempt || up[1].Replaces != c1.ARICertID {
		t.Fatalf("replaces outside window: order %q upstream %+v", o.UpstreamReplaces, up[1])
	}
}

func TestClientReplaces(t *testing.T) {
	e := newEnv(t, nil)
	_, c1 := e.issue("acct", "www.example.com")
	e.clock.Advance(61 * day)

	// A valid client-supplied replaces is used as given.
	o, err := e.eng.Admit(e.ctx, core.AdmitRequest{AccountID: "acct", Names: e.set("www.example.com"), Replaces: c1.ARICertID, SourceIP: srcIP, Decision: allowed})
	if err != nil {
		t.Fatal(err)
	}
	if o.Replaces != c1.ARICertID || !o.ARIQualified {
		t.Fatalf("order: %+v", o)
	}
	o = e.waitPrepared(o.ID)
	if o.UpstreamReplaces != c1.ARICertID {
		t.Fatalf("UpstreamReplaces %q", o.UpstreamReplaces)
	}
	got, err := e.finalize(o, e.csr(o))
	if err != nil || got.Status != core.OrderValid {
		t.Fatalf("finalize: %v", err)
	}
	c2 := e.cert(got.CertificateID)

	// An unknown replaces is ignored, not rejected: the newest unreplaced
	// certificate is inferred.
	e.clock.Advance(time.Hour)
	o2, err := e.eng.Admit(e.ctx, core.AdmitRequest{AccountID: "other", Names: e.set("www.example.com"), Replaces: "bogus.AQID", SourceIP: srcIP, Decision: allowed})
	if err != nil {
		t.Fatal(err)
	}
	o2 = e.waitPrepared(o2.ID)
	if o2.Replaces != "bogus.AQID" || o2.UpstreamReplaces != c2.ARICertID || o2.ARIQualified {
		t.Fatalf("order 2: replaces %q upstream %q ari %v", o2.Replaces, o2.UpstreamReplaces, o2.ARIQualified)
	}
	e.assertOneUpstreamPerOrder()
}

func TestAlreadyReplacedFallsBackToOrdinaryRenewal(t *testing.T) {
	e := newEnv(t, nil)
	_, c1 := e.issue("acct", "www.example.com")
	e.clock.Advance(61 * day)
	// Account A opens the replacement order and never finalizes it.
	a := e.admit("acct", "www.example.com")
	a = e.waitPrepared(a.ID)
	if !a.ARIQualified || a.UpstreamReplaces != c1.ARICertID {
		t.Fatalf("order A: %+v", a)
	}
	// Account B asks for the same set: the CA refuses the second replaces.
	b := e.admit("other", "www.example.com")
	if !b.ARIQualified {
		t.Fatal("B should have been admitted as ARI-qualified")
	}
	b = e.waitPrepared(b.ID)
	if b.Status != core.OrderReady || b.UpstreamReplaces != "" || b.UpstreamOrderURL == "" {
		t.Fatalf("order B after alreadyReplaced retry: %+v", b)
	}
	up := e.primary.Orders()
	if len(up) != 3 || up[2].Replaces != "" || up[2].Exempt {
		t.Fatalf("upstream orders: %+v", up)
	}
	// B was re-admitted with ordinary budget.
	refs := e.openRefs()
	if len(refs) != 1 || refs[0] != b.ID {
		t.Fatalf("open reservations: %v, want only B", refs)
	}
	kinds := map[core.BudgetKind]core.BudgetState{}
	evs, _ := e.st.Budgets().ListByRef(e.ctx, b.ID)
	for _, ev := range evs {
		kinds[ev.Kind] = ev.State
	}
	if kinds[core.BudgetNewOrder] != core.BudgetCommitted || kinds[core.BudgetCertSet] != core.BudgetReserved || kinds[core.BudgetCertDomain] != core.BudgetReserved {
		t.Fatalf("budget events of B after re-admission: %+v", evs)
	}
	got, err := e.finalize(b, e.csr(b))
	if err != nil || got.Status != core.OrderValid {
		t.Fatalf("finalize B: %v %+v", err, got)
	}
	e.assertOneUpstreamPerOrder()
}

func TestAbandonedOrderIsAdopted(t *testing.T) {
	e := newEnv(t, nil)
	a := e.admit("acct", "www.example.com")
	a = e.waitPrepared(a.ID)
	// The client vanishes; the order expires.
	e.clock.Advance(15*time.Minute + time.Second)
	if err := e.eng.Sweep(e.ctx); err != nil {
		t.Fatal(err)
	}
	a = e.order(a.ID)
	if a.Status != core.OrderInvalid || a.Prep != core.PrepPrepared || a.Error == nil {
		t.Fatalf("expired order: %+v", a)
	}
	if refs := e.openRefs(); len(refs) != 0 {
		t.Fatalf("expired order still holds budget: %v", refs)
	}
	if e.budgetUsed("primary", core.BudgetCertSet) != 0 || e.budgetUsed("primary", core.BudgetNewOrder) != 1 {
		t.Fatalf("budgets after expiry: set %d new %d", e.budgetUsed("primary", core.BudgetCertSet), e.budgetUsed("primary", core.BudgetNewOrder))
	}
	if up := e.primary.Orders(); len(up) != 1 || up[0].Status != core.UpstreamReady {
		t.Fatalf("upstream order after expiry: %+v", up)
	}
	ev := e.events(core.AuditOrder)
	if last := ev[len(ev)-1]; last.Result != core.AuditResultFailed || !strings.Contains(last.Detail, "adoption") {
		t.Fatalf("expiry audit: %+v", last)
	}

	// The next order for the same set adopts the upstream order.
	b := e.admit("other", "www.example.com")
	if b.Prep != core.PrepPrepared || b.UpstreamOrderURL != a.UpstreamOrderURL {
		t.Fatalf("adopting order: %+v", b)
	}
	if e.order(a.ID).AdoptedByOrderID != b.ID {
		t.Fatal("donor not marked adopted")
	}
	if e.budgetUsed("primary", core.BudgetNewOrder) != 1 {
		t.Fatal("adoption spent new-order budget")
	}
	got, err := e.finalize(b, e.csr(b))
	if err != nil || got.Status != core.OrderValid {
		t.Fatalf("finalize adopted: %v %+v", err, got)
	}
	if e.primary.Stats().OrdersCreated != 1 {
		t.Fatalf("upstream orders created: %d, want 1", e.primary.Stats().OrdersCreated)
	}
	// A third order cannot adopt it again.
	c := e.admit("third", "www.example.com")
	if c.Prep != core.PrepIntent {
		t.Fatalf("third order adopted a used upstream order: %+v", c)
	}
	e.waitPrepared(c.ID)
	e.assertOneUpstreamPerOrder()
}

func TestUpstreamRateLimitClosesAdmission(t *testing.T) {
	e := newEnv(t, nil)
	e.providers.SetDisabled("fallback", true)
	e.primary.Inject(coretest.Fault{Op: coretest.OpNewOrder, Err: e.primary.RateLimited(time.Hour)})

	o := e.admit("acct", "www.example.com")
	o = e.waitTerminal(o.ID)
	if o.Status != core.OrderInvalid || o.Error == nil || o.Error.Type != core.ProblemRateLimited {
		t.Fatalf("order after upstream 429: %+v err %v", o, o.Error)
	}
	if refs := e.openRefs(); len(refs) != 0 {
		t.Fatalf("budget not refunded: %v", refs)
	}
	// The circuit is closed: the next request is refused locally.
	_, err := e.eng.Admit(e.ctx, core.AdmitRequest{AccountID: "acct", Names: e.set("www.example.com"), SourceIP: srcIP, Decision: allowed})
	ae := asAdmission(t, err)
	if ae.Kind != core.AdmissionRateLimited || ae.RetryAfter < 59*time.Minute || ae.RetryAfter > time.Hour {
		t.Fatalf("refusal: %+v", ae)
	}
	if e.primary.Stats().Calls[coretest.OpNewOrder] != 1 {
		t.Fatalf("upstream newOrder called %d times after the circuit closed", e.primary.Stats().Calls[coretest.OpNewOrder])
	}
	if p := core.ProblemFromError(err); p.Status != 429 || p.RetryAfter != ae.RetryAfter {
		t.Fatalf("client problem: %+v", p)
	}
	rl := e.events(core.AuditRateLimit)
	if len(rl) != 1 || rl[0].Reason != core.ReasonRateLimited || rl[0].Visibility != core.AuditVisibilityAdmin {
		t.Fatalf("rate-limit audit: %+v", rl)
	}
	// After the Retry-After the provider is tried again.
	e.primary.ClearFaults()
	e.clock.Advance(time.Hour)
	o = e.admit("acct", "www.example.com")
	e.waitPrepared(o.ID)
}

func TestUpstreamBusyRetryAfter(t *testing.T) {
	e := newEnv(t, nil)
	e.providers.SetDisabled("fallback", true)
	e.primary.Inject(coretest.Fault{Op: coretest.OpNewOrder, Err: e.primary.Busy(45 * time.Second), Times: 1})
	o := e.admit("acct", "www.example.com")
	o = e.waitTerminal(o.ID)
	if o.Status != core.OrderInvalid || o.Error.Status != 503 {
		t.Fatalf("order after 503: %+v %v", o, o.Error)
	}
	_, err := e.eng.Admit(e.ctx, core.AdmitRequest{AccountID: "acct", Names: e.set("www.example.com"), SourceIP: srcIP, Decision: allowed})
	ae := asAdmission(t, err)
	if ae.Kind != core.AdmissionRateLimited || ae.RetryAfter != 45*time.Second {
		t.Fatalf("refusal after busy: %+v", ae)
	}
	e.clock.Advance(45 * time.Second)
	o = e.admit("acct", "www.example.com")
	e.waitPrepared(o.ID)
}

func TestNewIssuanceFallsBackWhenPrimaryDown(t *testing.T) {
	e := newEnv(t, nil)
	e.down("primary")
	o := e.admit("acct", "www.example.com")
	if o.Provider != "fallback" {
		t.Fatalf("new issuance went to %s", o.Provider)
	}
	e.waitPrepared(o.ID)
	fo := e.events(core.AuditFailover)
	if len(fo) != 1 || fo[0].Provider != "fallback" || !strings.Contains(fo[0].Detail, "primary") {
		t.Fatalf("failover audit: %+v", fo)
	}
	// Both down: 503 with the smallest Retry-After.
	e.down("fallback")
	_, err := e.eng.Admit(e.ctx, core.AdmitRequest{AccountID: "x", Names: e.set("a.example.com"), SourceIP: srcIP, Decision: allowed})
	ae := asAdmission(t, err)
	if ae.Kind != core.AdmissionProviderDown || ae.Provider != "" || ae.RetryAfter <= 0 {
		t.Fatalf("both down: %+v", ae)
	}
	if p := core.ProblemFromError(err); p.Status != 503 {
		t.Fatalf("client problem: %+v", p)
	}
}

func TestRenewalWithPlentyOfLifetimeDoesNotSwitch(t *testing.T) {
	e := newEnv(t, nil)
	_, c1 := e.issue("acct", "www.example.com")
	e.clock.Advance(30 * day)
	e.down("primary")
	_, err := e.eng.Admit(e.ctx, core.AdmitRequest{AccountID: "acct", Names: e.set("www.example.com"), SourceIP: srcIP, Decision: allowed})
	ae := asAdmission(t, err)
	if ae.Kind != core.AdmissionProviderDown || ae.Provider != "primary" {
		t.Fatalf("expected a clean provider_down error, got %+v", ae)
	}
	if e.fallback.Stats().OrdersCreated != 0 {
		t.Fatal("renewal was moved to the fallback with plenty of lifetime left")
	}
	if e.cert(c1.ID).ReplacedByID != "" {
		t.Fatal("certificate marked replaced without a renewal")
	}
	if len(e.events(core.AuditFailover)) != 0 {
		t.Fatal("unexpected failover event")
	}
}

func TestEmergencySwitch(t *testing.T) {
	e := newEnv(t, nil)
	_, c1 := e.issue("acct", "www.example.com")
	// Default window for a 90-day certificate checked daily: 7.5 days.
	e.clock.Set(c1.NotAfter.Add(-7 * day))
	e.down("primary")
	o := e.admit("acct", "www.example.com")
	if o.Provider != "fallback" || o.Class != core.ClassACMEEmergency || o.ARIQualified {
		t.Fatalf("emergency order: provider %s class %s", o.Provider, o.Class)
	}
	o = e.waitPrepared(o.ID)
	if o.UpstreamReplaces != "" {
		t.Fatalf("replaces carried across providers: %q", o.UpstreamReplaces)
	}
	got, err := e.finalize(o, e.csr(o))
	if err != nil || got.Status != core.OrderValid {
		t.Fatalf("finalize: %v", err)
	}
	c2 := e.cert(got.CertificateID)
	if c2.Provider != "fallback" || c2.ReplacesID != "" {
		t.Fatalf("fallback certificate: %+v", c2)
	}
	if _, err := e.fallback.VerifyChain(c2.ChainPEM, "www.example.com"); err != nil {
		t.Fatal(err)
	}
	fo := e.events(core.AuditFailover)
	if len(fo) != 1 || !strings.Contains(fo[0].Detail, "emergency switch") {
		t.Fatalf("failover audit: %+v", fo)
	}
	// Later renewals follow the lineage to the fallback.
	e.clock.Advance(30 * day)
	o3 := e.admit("acct", "www.example.com")
	if o3.Provider != "fallback" {
		t.Fatalf("lineage did not move: %s", o3.Provider)
	}
	e.waitPrepared(o3.ID)
}

// TestEmergencyWindowFormula checks the §8 values through the engine's
// provider choice: inside the window a down primary is switched away from,
// outside it the renewal gets a clean temporary error. The lineage is driven
// by renewal-information polls at a fixed cadence, and the renewal requests
// themselves keep that cadence (the gap to the current request counts).
func TestEmergencyWindowFormula(t *testing.T) {
	cases := []struct {
		name            string
		gap             time.Duration // cadence of the client's checks
		window          time.Duration // expected emergency window (90-day certificate)
		outside, inside time.Duration // offsets from issuance, multiples of gap
	}{
		{"daily checks: 4.5d + 3*1d", day, 7*day + 12*time.Hour, 82 * day, 83 * day},
		{"weekly checks: 4.5d + 3*7d", 7 * day, 25*day + 12*time.Hour, 63 * day, 70 * day},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := newEnv(t, nil)
			_, c1 := e.issue("acct", "www.example.com")
			t0 := e.clock.Now()
			if got := c1.NotAfter.Sub(t0); got != 90*day {
				t.Fatalf("certificate lifetime %s", got)
			}
			if c1.NotAfter.Sub(t0.Add(tc.outside)) <= tc.window || c1.NotAfter.Sub(t0.Add(tc.inside)) >= tc.window {
				t.Fatal("test offsets do not bracket the window")
			}
			for at := t0.Add(tc.gap); at.Before(t0.Add(tc.outside)); at = at.Add(tc.gap) {
				e.clock.Set(at)
				if _, err := e.eng.RenewalInfo(e.ctx, c1.ARICertID); err != nil {
					t.Fatal(err)
				}
			}
			// Outside the window: refused cleanly, nothing moves.
			e.clock.Set(t0.Add(tc.outside))
			e.down("primary")
			_, err := e.eng.Admit(e.ctx, core.AdmitRequest{AccountID: "acct", Names: e.set("www.example.com"), SourceIP: srcIP, Decision: allowed})
			if ae := asAdmission(t, err); ae.Kind != core.AdmissionProviderDown {
				t.Fatalf("outside window: %+v", ae)
			}
			lin, _ := e.st.Lineages().Get(e.ctx, "www.example.com")
			if lin.ObservedInterval != tc.gap {
				t.Fatalf("observed interval %s, want %s", lin.ObservedInterval, tc.gap)
			}
			// Inside the window: emergency switch.
			for at := t0.Add(tc.outside + tc.gap); at.Before(t0.Add(tc.inside)); at = at.Add(tc.gap) {
				e.clock.Set(at)
				if _, err := e.eng.RenewalInfo(e.ctx, c1.ARICertID); err != nil {
					t.Fatal(err)
				}
			}
			e.clock.Set(t0.Add(tc.inside))
			e.down("primary")
			o := e.admit("acct", "www.example.com")
			if o.Provider != "fallback" || o.Class != core.ClassACMEEmergency {
				t.Fatalf("inside window: provider %s class %s", o.Provider, o.Class)
			}
			e.waitPrepared(o.ID)
			if ev := e.events(core.AuditOrder); !strings.Contains(ev[len(ev)-1].Detail, "emergency window "+tc.window.Round(time.Minute).String()) {
				t.Fatalf("audit detail: %q", ev[len(ev)-1].Detail)
			}
		})
	}
}

func TestDNSPropagationFailure(t *testing.T) {
	e := newEnv(t, nil)
	e.dns.OnPresent(func(ctx context.Context, owner, record, value string) error { return core.ErrDNSPropagation })
	o := e.admit("acct", "www.example.com", "*.example.com")
	o = e.waitTerminal(o.ID)
	if o.Status != core.OrderInvalid || o.Prep != core.PrepFailed || o.Error == nil || o.Error.Type != core.ProblemDNS {
		t.Fatalf("order after propagation failure: %+v %v", o, o.Error)
	}
	// failOrder marks the order invalid before it cleans up, refunds and
	// audits (last), so wait for the audit event before checking the rest.
	e.waitUntil("issue audit", func() bool { return len(e.events(core.AuditIssue)) > 0 })
	if e.dns.ActiveCount() != 0 {
		t.Fatal("TXT values left behind")
	}
	if refs := e.openRefs(); len(refs) != 0 {
		t.Fatalf("budget not refunded: %v", refs)
	}
	if up := e.primary.Orders(); len(up) != 1 || up[0].Status != core.UpstreamPending {
		t.Fatalf("upstream order: %+v", up)
	}
	issues := e.events(core.AuditIssue)
	if len(issues) != 1 || issues[0].Result != core.AuditResultFailed || issues[0].Reason != core.ReasonDNSFailure {
		t.Fatalf("issue audit: %+v", issues)
	}
	// The primary is still healthy: DNS failures are not provider failures.
	if !e.snapshot("primary").Open {
		t.Fatal("DNS failure closed the provider circuit")
	}
}

func TestUpstreamValidationFailure(t *testing.T) {
	e := newEnv(t, nil)
	// The CA looks elsewhere: the value is never where it checks.
	e.primary.SetTXTLookup(func(context.Context, string) ([]string, error) { return []string{"nope"}, nil })
	o := e.admit("acct", "www.example.com")
	o = e.waitTerminal(o.ID)
	if o.Status != core.OrderInvalid || o.Error == nil || o.Error.Type != core.ProblemUnauthorized {
		t.Fatalf("order: %+v %v", o, o.Error)
	}
	if e.dns.ActiveCount() != 0 || len(e.openRefs()) != 0 {
		t.Fatal("cleanup or refund missing")
	}
}

func TestConcurrentOrdersShareChallengeRecords(t *testing.T) {
	e := newEnv(t, nil)
	// Values are presented while both orders are in flight.
	gate := newBlocker()
	e.dns.OnPresent(gate.hook)
	a := e.admit("a", "shared.example.com", "a.example.com")
	b := e.admit("b", "shared.example.com", "b.example.com")
	w := e.admit("w", "wild.example.com", "*.wild.example.com")
	gate.wait(t)
	close(gate.release)
	for _, o := range []*core.Order{a, b, w} {
		got := e.waitPrepared(o.ID)
		if got.Status != core.OrderReady {
			t.Fatalf("order %s: %v", o.ID, got.Error)
		}
	}
	byRecord := map[string]int{}
	for _, c := range e.dns.Challenges() {
		if !c.State.Terminal() {
			t.Fatalf("challenge left active: %+v", c)
		}
		byRecord[c.RecordName]++
	}
	if byRecord["_acme-challenge.shared.example.com"] != 2 || byRecord["_acme-challenge.wild.example.com"] != 2 {
		t.Fatalf("challenges per record: %v", byRecord)
	}
	if e.primary.Stats().OrdersCreated != 3 {
		t.Fatalf("upstream orders: %d", e.primary.Stats().OrdersCreated)
	}
	for _, o := range []*core.Order{a, b, w} {
		got, err := e.finalize(e.order(o.ID), e.csr(o))
		if err != nil || got.Status != core.OrderValid {
			t.Fatalf("finalize %s: %v", o.ID, err)
		}
	}
	e.assertOneUpstreamPerOrder()
}

func TestNoProviderEnabled(t *testing.T) {
	e := newEnv(t, nil)
	e.providers.SetDisabled("primary", true)
	e.providers.SetDisabled("fallback", true)
	_, err := e.eng.Admit(e.ctx, core.AdmitRequest{AccountID: "a", Names: e.set("www.example.com"), SourceIP: srcIP, Decision: allowed})
	if ae := asAdmission(t, err); ae.Kind != core.AdmissionProviderDown {
		t.Fatalf("no providers: %+v", ae)
	}
}

func TestLineageProviderDisabledBecomesFreshIssuance(t *testing.T) {
	e := newEnv(t, nil)
	e.providers.SetDisabled("primary", true)
	_, c1 := e.issue("acct", "www.example.com")
	e.providers.SetDisabled("primary", false)
	e.providers.SetDisabled("fallback", true)
	e.clock.Advance(day)
	o := e.admit("acct", "www.example.com")
	if o.Provider != "primary" {
		t.Fatalf("provider %s", o.Provider)
	}
	o = e.waitPrepared(o.ID)
	if o.UpstreamReplaces != "" {
		t.Fatalf("replaces %q sent to a provider that did not issue %s", o.UpstreamReplaces, c1.ID)
	}
	if fo := e.events(core.AuditFailover); len(fo) != 1 || !strings.Contains(fo[0].Detail, "no longer enabled") {
		t.Fatalf("failover audit: %+v", fo)
	}
}
