package issuance_test

import (
	"context"
	"testing"
	"time"

	"tls-broker/internal/core"
	"tls-broker/internal/core/coretest"
)

func (e *env) issueDirect(ctx context.Context, id string, background bool) (*core.Certificate, error) {
	e.t.Helper()
	return e.eng.Issue(ctx, core.IssueRequest{Identifier: id, CSRDER: coretest.MakeCSR(e.key, id), SourceIP: srcIP,
		Decision: allowed, Background: background})
}

func (e *env) directOrders() []core.Order {
	e.t.Helper()
	list, err := e.st.Orders().List(e.ctx, core.OrderFilter{Mode: core.ModeDirect})
	if err != nil {
		e.t.Fatal(err)
	}
	return list
}

func TestIssueCacheMiss(t *testing.T) {
	e := newEnv(t, nil)
	cert, err := e.issueDirect(e.ctx, "edge.example.com", false)
	if err != nil {
		t.Fatal(err)
	}
	if cert.Mode != core.ModeDirect || len(cert.ChainPEM) == 0 || cert.Provider != "primary" {
		t.Fatalf("certificate: %+v", cert)
	}
	if _, err := e.primary.VerifyChain(cert.ChainPEM, "edge.example.com"); err != nil {
		t.Fatal(err)
	}
	// The store keeps the mapping, not the chain.
	stored := e.cert(cert.ID)
	if stored.ChainPEM != nil || stored.ARICertID != cert.ARICertID {
		t.Fatalf("stored direct certificate: %+v", stored)
	}
	orders := e.directOrders()
	if len(orders) != 1 || orders[0].Status != core.OrderValid || orders[0].Class != core.ClassDirectMiss || orders[0].AccountID != "" {
		t.Fatalf("direct orders: %+v", orders)
	}
	if len(e.openRefs()) != 0 || e.dns.ActiveCount() != 0 {
		t.Fatal("budget or DNS not settled")
	}
	if ev := e.events(core.AuditIssue); len(ev) != 1 || ev[0].Mode != core.ModeDirect || ev[0].Result != core.AuditResultOK {
		t.Fatalf("issue audit: %+v", ev)
	}
}

func TestIssueWildcardAndBaseShareRecord(t *testing.T) {
	e := newEnv(t, nil)
	cert, err := e.issueDirect(e.ctx, "*.example.com", false)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.primary.VerifyChain(cert.ChainPEM, "x.example.com"); err != nil {
		t.Fatal(err)
	}
}

func TestIssueBackgroundRenewal(t *testing.T) {
	e := newEnv(t, nil)
	c1, err := e.issueDirect(e.ctx, "edge.example.com", false)
	if err != nil {
		t.Fatal(err)
	}
	e.clock.Advance(30 * day)
	c2, err := e.issueDirect(e.ctx, "edge.example.com", true)
	if err != nil {
		t.Fatal(err)
	}
	orders := e.directOrders()
	if orders[0].Class != core.ClassDirectBackground || orders[0].UpstreamReplaces != c1.ARICertID {
		t.Fatalf("background renewal order: %+v", orders[0])
	}
	if c2.ReplacesID != c1.ID || e.cert(c1.ID).ReplacedByID != c2.ID {
		t.Fatal("replacement relationship missing")
	}
	// Inside c2's ARI window (two thirds of its lifetime) the renewal is
	// class 1 and exempt.
	e.clock.Advance(61 * day)
	c3, err := e.issueDirect(e.ctx, "edge.example.com", true)
	if err != nil {
		t.Fatal(err)
	}
	orders = e.directOrders()
	if orders[0].Class != core.ClassARIRenewal || !orders[0].ARIQualified || c3.ReplacesID != c2.ID {
		t.Fatalf("ARI renewal order: %+v", orders[0])
	}
	if up := e.primary.Orders(); !up[2].Exempt {
		t.Fatalf("upstream orders: %+v", up)
	}
}

func TestIssueEmergencyFailsOver(t *testing.T) {
	e := newEnv(t, nil)
	c1, err := e.issueDirect(e.ctx, "edge.example.com", false)
	if err != nil {
		t.Fatal(err)
	}
	// Plenty of lifetime: a down primary is a clean error, even for a
	// foreground request.
	e.clock.Advance(30 * day)
	e.down("primary")
	_, err = e.issueDirect(e.ctx, "edge.example.com", false)
	if ae := asAdmission(t, err); ae.Kind != core.AdmissionProviderDown {
		t.Fatalf("plenty of lifetime: %+v", ae)
	}
	// Inside the emergency window the fallback takes over.
	e.clock.Set(c1.NotAfter.Add(-6 * day))
	e.down("primary")
	c2, err := e.issueDirect(e.ctx, "edge.example.com", true)
	if err != nil {
		t.Fatal(err)
	}
	orders := e.directOrders()
	if orders[0].Class != core.ClassDirectEmergency || c2.Provider != "fallback" || c2.ReplacesID != "" {
		t.Fatalf("emergency order %+v cert %+v", orders[0], c2)
	}
	// Expired certificate: still an emergency, synchronous.
	e.clock.Set(c2.NotAfter.Add(time.Hour))
	e.down("fallback")
	c3, err := e.issueDirect(e.ctx, "edge.example.com", false)
	if err != nil {
		t.Fatal(err)
	}
	if c3.Provider != "primary" || e.directOrders()[0].Class != core.ClassDirectEmergency {
		t.Fatalf("expired renewal: %+v", c3)
	}
}

func TestIssueRejectsBadInput(t *testing.T) {
	e := newEnv(t, nil)
	_, err := e.eng.Issue(e.ctx, core.IssueRequest{Identifier: "edge.example.com", CSRDER: coretest.MakeCSR(e.key, "other.example.com"), SourceIP: srcIP, Decision: allowed})
	if p := asProblem(t, err); p.Type != core.ProblemBadCSR {
		t.Fatalf("csr mismatch: %v", p)
	}
	_, err = e.eng.Issue(e.ctx, core.IssueRequest{Identifier: "edge.example.com", CSRDER: coretest.MakeCSR(e.key, "edge.example.com"), SourceIP: srcIP,
		Decision: core.Decision{Allowed: false, Reason: core.ReasonWildcardGrantRequired}})
	if p := asProblem(t, err); p.Type != core.ProblemUnauthorized {
		t.Fatalf("denied: %v", p)
	}
	_, err = e.eng.Issue(e.ctx, core.IssueRequest{Identifier: "edge.other.net", CSRDER: coretest.MakeCSR(e.key, "edge.other.net"), SourceIP: srcIP, Decision: allowed})
	if p := asProblem(t, err); p.Type != core.ProblemRejectedIdentifier {
		t.Fatalf("outside zones: %v", p)
	}
	if len(e.directOrders()) != 0 || e.primary.Stats().OrdersCreated != 0 {
		t.Fatal("a rejected request reached admission")
	}
}

func TestIssueCancelledBeforeCSR(t *testing.T) {
	e := newEnv(t, nil)
	block := newBlocker()
	e.dns.OnPresent(block.hook)
	ctx, cancel := context.WithCancel(e.ctx)
	ch := make(chan error, 1)
	go func() {
		_, err := e.issueDirect(ctx, "edge.example.com", false)
		ch <- err
	}()
	block.wait(t)
	cancel()
	isErr(t, <-ch, context.Canceled)
	orders := e.directOrders()
	if len(orders) != 1 || orders[0].Status != core.OrderInvalid || orders[0].Prep != core.PrepFailed {
		t.Fatalf("abandoned direct order: %+v", orders)
	}
	if len(e.openRefs()) != 0 || e.dns.ActiveCount() != 0 {
		t.Fatal("budget or DNS not released")
	}
	if e.primary.Stats().Finalizations != 0 {
		t.Fatal("CSR sent for an abandoned attempt")
	}
}

func TestIssueCancelledAfterCSRCompletesInBackground(t *testing.T) {
	e := newEnv(t, nil)
	e.primary.Inject(coretest.Fault{Op: coretest.OpWaitCertificate, Delay: time.Minute, Times: 1})
	ctx, cancel := context.WithCancel(e.ctx)
	ch := make(chan error, 1)
	go func() {
		_, err := e.issueDirect(ctx, "edge.example.com", false)
		ch <- err
	}()
	if !e.clock.BlockUntil(1, 5*time.Second) {
		t.Fatal("CA delay timer not armed")
	}
	cancel()
	isErr(t, <-ch, context.Canceled)
	e.clock.Advance(time.Minute)
	e.waitUntil("direct order valid", func() bool {
		o := e.directOrders()
		return len(o) == 1 && o[0].Status == core.OrderValid
	})
	if len(e.openRefs()) != 0 {
		t.Fatal("budget not committed")
	}
	// The next request renews normally against the stored certificate.
	e.clock.Advance(day)
	c2, err := e.issueDirect(e.ctx, "edge.example.com", true)
	if err != nil {
		t.Fatal(err)
	}
	if c2.ReplacesID == "" {
		t.Fatal("background-completed certificate was not found as predecessor")
	}
}

func TestIssueAdoptsAbandonedACMEOrder(t *testing.T) {
	e := newEnv(t, nil)
	a := e.admit("acct", "edge.example.com")
	e.waitPrepared(a.ID)
	e.clock.Advance(16 * time.Minute)
	if err := e.eng.Sweep(e.ctx); err != nil {
		t.Fatal(err)
	}
	cert, err := e.issueDirect(e.ctx, "edge.example.com", false)
	if err != nil {
		t.Fatal(err)
	}
	if cert.OrderID == a.ID || e.primary.Stats().OrdersCreated != 1 {
		t.Fatalf("direct issuance did not adopt: %d upstream orders", e.primary.Stats().OrdersCreated)
	}
	if e.order(a.ID).AdoptedByOrderID != cert.OrderID {
		t.Fatal("donor not marked")
	}
}
