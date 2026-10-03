package e2e

import (
	"context"
	"net/http"
	"slices"
	"testing"
	"time"

	"github.com/go-acme/lego/v5/acme"

	"tls-broker/internal/core"
	"tls-broker/internal/core/coretest"
)

// TestScenarios runs every critical scenario of architecture §25 (plus the
// edge cases around them) on its own broker, in parallel.
func TestScenarios(t *testing.T) {
	for _, sc := range scenarios {
		t.Run(sc.name, func(t *testing.T) {
			t.Parallel()
			sc.run(t)
		})
	}
}

var scenarios = []struct {
	name string
	run  func(t *testing.T)
}{
	{"healthz before ready", testHealthzBeforeReady},
	{"new issuance", testNewIssuance},
	{"already-valid authz", testAlreadyValidAuthz},
	{"same-CSR finalize retry", testSameCSRRetry},
	{"different-CSR retry rejection", testDifferentCSRRetry},
	{"finalize before preparation is done", testFinalizeBeforePrepared},
	{"client vanishes after newOrder", testClientVanishes},
	{"restart during processing", testRestartDuringProcessing},
	{"renewal", testRenewalSticky},
	{"ARI renewal", testARIRenewal},
	{"Route53 timeout", testRoute53Timeout},
	{"DNS propagation delay", testPropagationDelay},
	{"upstream 429", testUpstream429},
	{"upstream 503 Retry-After", testUpstream503},
	{"provider outage", testProviderOutage},
	{"emergency provider switch", testEmergencySwitch},
	{"concurrent TXT challenges", testConcurrentTXT},
	{"direct cache miss hit renewal", testDirectCache},
	{"duplicate direct requests collapse to one issuance", testDirectCollapse},
	{"blocked and grant failures", testBlockedAndGrants},
	{"wildcard permission", testWildcardPermission},
	{"multi-SAN DNS gate", testMultiSANGate},
	{"DNS proxy", testDNSProxy},
	{"UI login grant audit", testUI},
}

// /healthz answers 503 until Run marked the broker ready; so does every
// application route.
func testHealthzBeforeReady(t *testing.T) {
	b := newFakeBroker(t)
	b.stop()
	a := b.newApp()
	if c := status(a.Handler(), "/healthz"); c != http.StatusServiceUnavailable {
		t.Fatalf("healthz before Run: %d", c)
	}
	if c := status(a.Handler(), "/acme/directory"); c != http.StatusServiceUnavailable {
		t.Fatalf("acme before Run: %d", c)
	}
	b.run(a)
	if c := status(a.Handler(), "/healthz"); c != http.StatusOK {
		t.Fatalf("healthz after Run: %d", c)
	}
	m := b.machine("10.0.0.1")
	if c, _, body := m.get("/acme/directory"); c != http.StatusOK {
		t.Fatalf("directory: %d %s", c, body)
	}
}

// New issuance, single name and multi-SAN: one upstream order per
// downstream order, the chain is the CA's, no root.
func testNewIssuance(t *testing.T) {
	b := newFakeBroker(t)
	c := b.machine("10.0.0.10", "www.example.com", "api.example.com", "app.example.org").acme()

	single := c.issue("", "www.example.com")
	if _, err := b.le.VerifyChain(single.chain, "www.example.com"); err != nil {
		t.Fatalf("single chain: %v", err)
	}
	if s := b.le.Stats(); s.OrdersCreated != 1 || s.CertificatesIssued != 1 || s.Calls[coretest.OpNewOrder] != 1 {
		t.Fatalf("single: CA stats %+v", s)
	}

	multi := c.issue("", "api.example.com", "app.example.org", "www.example.com")
	if _, err := b.le.VerifyChain(multi.chain, "app.example.org"); err != nil {
		t.Fatalf("multi chain: %v", err)
	}
	if got := multi.leaf.DNSNames; !slices.Equal(got, []string{"api.example.com", "app.example.org", "www.example.com"}) {
		t.Fatalf("multi SANs %v", got)
	}
	s := b.le.Stats()
	if s.OrdersCreated != 2 || s.CertificatesIssued != 2 || s.Calls[coretest.OpNewOrder] != 2 || s.Finalizations != 2 {
		t.Fatalf("multi: CA stats %+v", s)
	}
	if g := b.goog.Stats(); g.OrdersCreated != 0 {
		t.Fatalf("fallback used: %+v", g)
	}
	o := b.order(multi.orderID)
	if o.Status != core.OrderValid || o.Provider != "letsencrypt" || o.UpstreamOrderURL == "" || o.Class != core.ClassACMEOrdinary {
		t.Fatalf("broker order %+v", o)
	}
	// Both zones were used: the TXT values went to the right hosted zones
	// and were cleaned up afterwards.
	if b.r53.Changes(zoneCOM) == 0 || b.r53.Changes(zoneORG) == 0 {
		t.Fatalf("route53 changes com=%d org=%d", b.r53.Changes(zoneCOM), b.r53.Changes(zoneORG))
	}
	for _, rec := range []string{"_acme-challenge.www.example.com", "_acme-challenge.api.example.com", "_acme-challenge.app.example.org"} {
		if v := b.r53.TXT(rec); len(v) != 0 {
			t.Fatalf("%s left behind: %v", rec, v)
		}
	}
	// The order is issued once: asking again for the same names creates a
	// new downstream order (and a new upstream one), never reuses a valid one.
	if evs := b.auditEvents(core.AuditIssue); len(evs) != 2 {
		t.Fatalf("issue events: %d", len(evs))
	}
	b.checkInvariants(0)
}

// Authorizations are already valid with exactly one valid dns-01 challenge;
// a wildcard's authorization names the base with "wildcard": true.
func testAlreadyValidAuthz(t *testing.T) {
	b := newFakeBroker(t)
	m := b.machine("10.0.0.11", "example.com")
	b.grant("10.0.0.11", true)
	c := m.acme()
	o := c.mustOrder("", "*.example.com", "example.com")
	c.checkAuthzs(o)
	wild := 0
	for _, u := range o.Authorizations {
		az, err := c.core.Authorizations.Get(context.Background(), u)
		if err != nil {
			t.Fatal(err)
		}
		if az.Identifier.Value != "example.com" || az.Identifier.Type != "dns" {
			t.Fatalf("identifier %+v", az.Identifier)
		}
		if az.Wildcard {
			wild++
		}
		// Responding to the synthetic challenge is harmless.
		ch, err := c.core.Challenges.New(context.Background(), az.Challenges[0].URL)
		if err != nil || ch.Status != acme.StatusValid {
			t.Fatalf("challenge response %+v %v", ch, err)
		}
	}
	if wild != 1 {
		t.Fatalf("wildcard authorizations: %d", wild)
	}
	csr := coretest.MakeCSR(coretest.GenKey(), "*.example.com", "example.com")
	fin, err := c.finalize(o, csr)
	if err != nil || fin.Status != acme.StatusValid {
		t.Fatalf("finalize: %+v %v", fin, err)
	}
	b.checkInvariants(0)
}

// The same CSR again returns the current state; the CA sees one finalize.
func testSameCSRRetry(t *testing.T) {
	b := newFakeBroker(t)
	c := b.machine("10.0.0.12", "www.example.com").acme()
	o := c.mustOrder("", "www.example.com")
	csr := coretest.MakeCSR(coretest.GenKey(), "www.example.com")
	first, err := c.finalize(o, csr)
	if err != nil || first.Status != acme.StatusValid {
		t.Fatalf("finalize: %+v %v", first, err)
	}
	again, err := c.finalize(o, csr)
	if err != nil || again.Status != acme.StatusValid || again.Certificate != first.Certificate {
		t.Fatalf("finalize retry: %+v %v", again, err)
	}
	if s := b.le.Stats(); s.Finalizations != 1 || s.Calls[coretest.OpFinalize] != 1 || s.CertificatesIssued != 1 {
		t.Fatalf("CA stats %+v", s)
	}
	b.checkInvariants(0)
}

// A different CSR for an order that already accepted one is badCSR and
// never reaches the CA.
func testDifferentCSRRetry(t *testing.T) {
	b := newFakeBroker(t)
	c := b.machine("10.0.0.13", "www.example.com").acme()
	o := c.mustOrder("", "www.example.com")
	if fin, err := c.finalize(o, coretest.MakeCSR(coretest.GenKey(), "www.example.com")); err != nil || fin.Status != acme.StatusValid {
		t.Fatalf("finalize: %+v %v", fin, err)
	}
	before := b.le.Stats()
	_, err := c.finalize(o, coretest.MakeCSR(coretest.GenKey(), "www.example.com"))
	pd := problem(t, err)
	if pd.Type != acme.BadCSRErrorType || pd.HTTPStatus != http.StatusBadRequest {
		t.Fatalf("different CSR: %+v", pd)
	}
	// A CSR whose names differ from the order is badCSR as well.
	_, err = c.finalize(o, coretest.MakeCSR(coretest.GenKey(), "other.example.com"))
	if pd := problem(t, err); pd.Type != acme.BadCSRErrorType {
		t.Fatalf("CSR with other names: %+v", pd)
	}
	after := b.le.Stats()
	if after.Calls[coretest.OpFinalize] != before.Calls[coretest.OpFinalize] || after.Calls[coretest.OpNewOrder] != before.Calls[coretest.OpNewOrder] {
		t.Fatalf("upstream called: before %+v after %+v", before.Calls, after.Calls)
	}
	if got := c.poll(o.Location); got.Status != acme.StatusValid {
		t.Fatalf("order after rejected retry: %s", got.Status)
	}
	b.checkInvariants(0)
}

// Finalize arrives while the upstream preparation is still running (a slow
// CA): the order is processing (with Retry-After) and becomes valid once
// the CA is done; the CSR was recorded at once and finalize happened once.
func testFinalizeBeforePrepared(t *testing.T) {
	b := newFakeBroker(t)
	m := b.machine("10.0.0.14", "slow.example.com")
	c := m.acme()
	b.le.Inject(coretest.Fault{Op: coretest.OpWaitReady, Delay: 2 * time.Minute, Times: 1})
	o := c.mustOrder("", "slow.example.com")
	csr := coretest.MakeCSR(coretest.GenKey(), "slow.example.com")
	var fin acme.ExtendedOrder
	var err error
	b.pump(time.Second, func() { fin, err = c.finalize(o, csr) })
	if err != nil || fin.Status != acme.StatusProcessing {
		t.Fatalf("finalize during preparation: %+v %v", fin, err)
	}
	if _, hdr := m.tr.last(); hdr.Get("Retry-After") != "3" {
		t.Fatalf("Retry-After %q", hdr.Get("Retry-After"))
	}
	if bo := b.order(pathBase(o.Location)); bo.Status != core.OrderProcessing || bo.CSRHash == "" {
		t.Fatalf("broker order %+v", bo)
	}
	// Polling while the CA is slow; then the CA finishes.
	b.pump(5*time.Second, func() {
		eventually(t, "order valid", func() bool { return c.poll(o.Location).Status == acme.StatusValid })
	})
	got := c.poll(o.Location)
	if got.Certificate == "" {
		t.Fatalf("valid without certificate: %+v", got)
	}
	got.Location = o.Location
	c.download(got, csr)
	if s := b.le.Stats(); s.Finalizations != 1 || s.OrdersCreated != 1 {
		t.Fatalf("CA stats %+v", s)
	}
	b.checkInvariants(0)
}
