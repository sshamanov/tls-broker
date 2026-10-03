package e2e

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/go-acme/lego/v5/acme"

	"tls-broker/internal/core"
	"tls-broker/internal/core/coretest"
)

// A client that never finalizes: the order expires at the next sweep, the
// certificate budgets are refunded (the new-order budget stays spent: the
// upstream order exists), and the next order for the same names adopts the
// prepared upstream order instead of creating another.
func testClientVanishes(t *testing.T) {
	b := newFakeBroker(t)
	ctx := context.Background()
	c := b.machine("10.0.0.15", "gone.example.com").acme()
	o := c.mustOrder("", "gone.example.com")
	id := pathBase(o.Location)
	eventually(t, "upstream preparation", func() bool { return b.order(id).Prep == core.PrepPrepared })
	donor := b.order(id)

	b.advance(16 * time.Minute) // scheduler.order_ttl is 15m
	b.housekeep()
	if got := b.order(id); got.Status != core.OrderInvalid || got.Prep != core.PrepPrepared {
		t.Fatalf("after sweep: %+v", got)
	}
	events, err := b.app().Store().Budgets().ListByRef(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range events {
		if e.State == core.BudgetReserved || e.Kind != core.BudgetNewOrder {
			t.Fatalf("budget not refunded: %+v", events)
		}
	}
	if got := c.poll(o.Location); got.Status != acme.StatusInvalid {
		t.Fatalf("expired order polls as %s", got.Status)
	}
	_, err = c.finalize(o, coretest.MakeCSR(coretest.GenKey(), "gone.example.com"))
	if pd := problem(t, err); pd.Type != acme.OrderNotReadyErrorType {
		t.Fatalf("finalize of expired order: %+v", pd)
	}

	// Another client asks for the same names: it adopts the upstream order.
	c2 := b.machine("10.0.0.16", "gone.example.com").acme()
	got := c2.issue("", "gone.example.com")
	adopter := b.order(got.orderID)
	if adopter.UpstreamOrderURL != donor.UpstreamOrderURL {
		t.Fatalf("not adopted: %q vs %q", adopter.UpstreamOrderURL, donor.UpstreamOrderURL)
	}
	if d := b.order(id); d.AdoptedByOrderID != got.orderID {
		t.Fatalf("donor not marked adopted: %+v", d)
	}
	if s := b.le.Stats(); s.OrdersCreated != 1 || s.CertificatesIssued != 1 {
		t.Fatalf("CA stats %+v", s)
	}
	b.checkInvariants(0)
}

// The broker restarts while an order is processing (the CA is slow to
// issue): shutdown leaves the order as it is, Recover resumes it, and the
// client's polling finds it valid. Finalize reached the CA once.
func testRestartDuringProcessing(t *testing.T) {
	b := newFakeBroker(t)
	c := b.machine("10.0.0.17", "restart.example.com").acme()
	b.le.Inject(coretest.Fault{Op: coretest.OpWaitCertificate, Delay: time.Hour, Times: 1})
	o := c.mustOrder("", "restart.example.com")
	csr := coretest.MakeCSR(coretest.GenKey(), "restart.example.com")
	var fin acme.ExtendedOrder
	var err error
	b.pump(time.Second, func() { fin, err = c.finalize(o, csr) })
	if err != nil || fin.Status != acme.StatusProcessing {
		t.Fatalf("finalize: %+v %v", fin, err)
	}
	id := pathBase(o.Location)

	b.restart()
	if got := b.order(id); got.Status != core.OrderProcessing && got.Status != core.OrderValid {
		t.Fatalf("order after restart: %+v", got)
	}
	// The client keeps polling with its old nonce state (badNonce after a
	// restart is retried by the client) and the same account.
	eventually(t, "order valid after restart", func() bool { return c.poll(o.Location).Status == acme.StatusValid })
	got := c.poll(o.Location)
	got.Location = o.Location
	is := c.download(got, csr)
	if _, err := b.le.VerifyChain(is.chain, "restart.example.com"); err != nil {
		t.Fatal(err)
	}
	if s := b.le.Stats(); s.OrdersCreated != 1 || s.Finalizations != 1 || s.CertificatesIssued != 1 {
		t.Fatalf("CA stats %+v", s)
	}
	b.checkInvariants(0)
}

// A renewal stays with the lineage's provider: a certificate first issued
// by the fallback (the primary was down at the time) is renewed at the
// fallback even after the primary has recovered.
func testRenewalSticky(t *testing.T) {
	b := newFakeBroker(t)
	m := b.machine("10.0.0.20", "sticky.example.com")
	c := m.acme()

	// The primary fails the first order upstream (after admission): the
	// order becomes invalid and the primary's circuit closes.
	b.le.Inject(coretest.Fault{Op: coretest.OpNewOrder, Err: b.le.Down(), Times: 1})
	failed := c.mustOrder("", "sticky.example.com")
	eventually(t, "failed order", func() bool { return b.order(pathBase(failed.Location)).Status == core.OrderInvalid })
	if got := c.poll(failed.Location); got.Status != acme.StatusInvalid || got.Error == nil {
		t.Fatalf("failed order polls as %+v", got)
	}

	// The client tries again: new issuance falls back to google.
	first := c.issue("", "sticky.example.com")
	if p := b.certByARI(first.certID).Provider; p != "google" {
		t.Fatalf("first certificate from %s", p)
	}
	if _, err := b.goog.VerifyChain(first.chain, "sticky.example.com"); err != nil {
		t.Fatal(err)
	}
	if fo := b.auditEvents(core.AuditFailover); len(fo) != 1 || fo[0].Provider != "google" {
		t.Fatalf("failover events %+v", fo)
	}

	// A month later the primary is healthy again; the renewal stays at
	// google, naming its predecessor there (google does not exempt it).
	b.advance(30 * day)
	renewal := c.issue("", "sticky.example.com")
	rc := b.certByARI(renewal.certID)
	if rc.Provider != "google" || rc.ReplacesID != b.certByARI(first.certID).ID {
		t.Fatalf("renewal %+v", rc)
	}
	ro := b.order(renewal.orderID)
	up, _ := caOrder(b.goog, ro.UpstreamOrderURL)
	if up.Replaces != first.certID || up.Exempt || ro.ARIQualified {
		t.Fatalf("renewal upstream %+v, order %+v", up, ro)
	}
	if s := b.le.Stats(); s.OrdersCreated != 0 || s.Calls[coretest.OpNewOrder] != 1 {
		t.Fatalf("primary used for the renewal: %+v", s)
	}
	b.checkInvariants(0)
}

// ARI: renewalInfo is answered from the CA; a renewal inside the suggested
// window is an exempt ARI renewal whether the client sends `replaces` or the
// broker infers it; outside the window `replaces` is still sent but the
// order is ordinary.
func testARIRenewal(t *testing.T) {
	b := newFakeBroker(t)
	ctx := context.Background()
	m := b.machine("10.0.0.21", "ari.example.com", "ari2.example.com", "ari3.example.com")
	c := m.acme()
	window := func(is *issued, from time.Duration) (time.Time, time.Time) {
		start := b.clock.Now().Add(from).Truncate(time.Second)
		end := start.Add(2 * day)
		if !b.le.SetRenewalWindow(is.certID, start, end) {
			t.Fatalf("no certificate %s at the CA", is.certID)
		}
		return start, end
	}

	// 1. renewalInfo proxied, then a renewal with replaces inside the window.
	first := c.issue("", "ari.example.com")
	start, end := window(first, 20*day)
	ri, err := c.core.Certificates.GetRenewalInfo(ctx, first.certID)
	if err != nil {
		t.Fatal(err)
	}
	if !ri.SuggestedWindow.Start.Equal(start) || !ri.SuggestedWindow.End.Equal(end) || ri.RetryAfter != 6*time.Hour {
		t.Fatalf("renewalInfo %+v (want %s..%s)", ri, start, end)
	}
	if code, _, _ := m.get("/acme/renewal-info/AAAA.BBBB"); code != http.StatusNotFound {
		t.Fatalf("renewalInfo of an unknown certificate: %d", code)
	}
	b.advance(21 * day)
	r1 := c.issue(first.certID, "ari.example.com")
	if r1.created.Replaces != first.certID {
		t.Fatalf("replaces not echoed: %+v", r1.created)
	}
	b.checkARIRenewal(r1, first, true)

	// 2. The client sends no replaces: the broker infers the predecessor.
	second := c.issue("", "ari2.example.com")
	window(second, 20*day)
	b.advance(21 * day)
	r2 := c.issue("", "ari2.example.com")
	b.checkARIRenewal(r2, second, true)

	// 3. Before the window: replaces is sent upstream, but no exemption.
	third := c.issue("", "ari3.example.com")
	window(third, 20*day)
	b.advance(10 * day)
	r3 := c.issue(third.certID, "ari3.example.com")
	b.checkARIRenewal(r3, third, false)

	if s := b.le.Stats(); s.ExemptOrders != 2 {
		t.Fatalf("exempt orders at the CA: %d", s.ExemptOrders)
	}
	if s := b.goog.Stats(); s.OrdersCreated != 0 {
		t.Fatalf("fallback used: %+v", s)
	}
	b.checkInvariants(0)
}

// checkARIRenewal asserts that renewal replaced pred at the same provider,
// with `replaces` upstream, exempt (class 1, no budget) or not.
func (b *broker) checkARIRenewal(renewal, pred *issued, exempt bool) {
	t := b.t
	t.Helper()
	o := b.order(renewal.orderID)
	up, ok := caOrder(b.le, o.UpstreamOrderURL)
	if !ok || o.Provider != "letsencrypt" || o.UpstreamReplaces != pred.certID || up.Replaces != pred.certID {
		t.Fatalf("renewal order %+v, upstream %+v", o, up)
	}
	if o.ARIQualified != exempt || up.Exempt != exempt {
		t.Fatalf("exempt %v: order ARIQualified=%v, upstream Exempt=%v", exempt, o.ARIQualified, up.Exempt)
	}
	wantClass := core.ClassACMEOrdinary
	if exempt {
		wantClass = core.ClassARIRenewal
	}
	if o.Class != wantClass {
		t.Fatalf("class %v, want %v", o.Class, wantClass)
	}
	events, err := b.app().Store().Budgets().ListByRef(context.Background(), o.ID)
	if err != nil {
		t.Fatal(err)
	}
	if exempt != (len(events) == 0) {
		t.Fatalf("exempt %v but budget events %+v", exempt, events)
	}
	nc, pc := b.certByARI(renewal.certID), b.certByARI(pred.certID)
	if nc.ReplacesID != pc.ID || nc.Provider != pc.Provider || nc.AccountURL != pc.AccountURL {
		t.Fatalf("renewal certificate %+v, predecessor %+v", nc, pc)
	}
	if pc2 := b.certByARI(pred.certID); pc2.ReplacedByID != nc.ID {
		t.Fatalf("predecessor not marked replaced: %+v", pc2)
	}
}
