package e2e

import (
	"context"
	"errors"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-acme/lego/v5/acme"

	"tls-broker/internal/core"
	"tls-broker/internal/core/coretest"
	"tls-broker/internal/dns01"
)

// waitInvalid waits until the broker failed the order (in the background).
func (b *broker) waitInvalid(o acme.ExtendedOrder) *core.Order {
	b.t.Helper()
	id := pathBase(o.Location)
	eventually(b.t, "order "+id+" invalid", func() bool { return b.order(id).Status == core.OrderInvalid })
	return b.order(id)
}

// noReservations asserts that a failed order ends up holding no reserved
// budget and that only the new-order budget (the upstream order existed)
// stays spent. The refund follows the order's failure closely, not
// atomically, so it is awaited.
func (b *broker) noReservations(id string) {
	b.t.Helper()
	var events []core.BudgetEvent
	refunded := func() bool {
		var err error
		events, err = b.app().Store().Budgets().ListByRef(context.Background(), id)
		if err != nil {
			b.t.Fatal(err)
		}
		for _, e := range events {
			if e.State == core.BudgetReserved || e.Kind != core.BudgetNewOrder {
				return false
			}
		}
		return true
	}
	deadline := time.Now().Add(10 * time.Second)
	for !refunded() {
		if time.Now().After(deadline) {
			b.t.Fatalf("order %s: budget not refunded: %+v", id, events)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// retryAfter returns the Retry-After of the machine's last response.
func (m *machine) retryAfter() time.Duration {
	_, hdr := m.tr.last()
	n, err := strconv.Atoi(hdr.Get("Retry-After"))
	if err != nil {
		m.b.t.Fatalf("Retry-After %q", hdr.Get("Retry-After"))
	}
	return time.Duration(n) * time.Second
}

// Route53 calls that hang time out and are retried; a Route53 that never
// answers fails the order cleanly (refunded, nothing validated upstream).
func testRoute53Timeout(t *testing.T) {
	b := newFakeBroker(t)
	c := b.machine("10.0.0.22", "r53.example.com", "dead.example.com").acme()

	b.r53.Hang(dns01.OpChange, 1)
	var is acme.ExtendedOrder
	var err error
	b.pump(time.Second, func() { is, err = c.tryIssue("r53.example.com") })
	if err != nil {
		t.Fatalf("issuance after one Route53 timeout: %v", err)
	}
	if n := b.r53.Calls(dns01.OpChange); n < 3 { // hung present, its retry, cleanup
		t.Fatalf("route53 change calls: %d", n)
	}
	if v := b.r53.TXT("_acme-challenge.r53.example.com"); len(v) != 0 {
		t.Fatalf("value left behind: %v", v)
	}
	_ = is

	b.r53.Hang(dns01.OpChange, 1000)
	o := c.mustOrder("", "dead.example.com")
	var bo *core.Order
	b.pump(5*time.Second, func() { bo = b.waitInvalid(o) })
	b.r53.ClearFaults()
	if bo.Error == nil || bo.Prep != core.PrepFailed {
		t.Fatalf("order after Route53 outage: %+v", bo)
	}
	t.Logf("route53 outage problem: %s: %s", bo.Error.Type, bo.Error.Detail)
	if got := c.poll(o.Location); got.Status != acme.StatusInvalid || got.Error == nil {
		t.Fatalf("client sees %+v", got)
	}
	b.noReservations(bo.ID)
	if s := b.le.Stats(); s.Calls[coretest.OpAccept] != 1 { // only the first order's
		t.Fatalf("challenges accepted upstream without a published value: %+v", s.Calls)
	}
	b.checkInvariants(0)
}

// Public DNS lags Route53: the broker waits until the value is visible
// before asking the CA to validate; if it never becomes visible within
// route53.propagation_timeout the order fails without a validation attempt.
func testPropagationDelay(t *testing.T) {
	b := newFakeBroker(t)
	c := b.machine("10.0.0.23", "lag.example.com", "never.example.com").acme()

	b.r53.SetPublicDelay(45 * time.Second)
	start := b.clock.Now()
	var err error
	b.pump(time.Second, func() { _, err = c.tryIssue("lag.example.com") })
	if err != nil {
		t.Fatalf("issuance with propagation delay: %v", err)
	}
	if waited := b.clock.Now().Sub(start); waited < 45*time.Second {
		t.Fatalf("finished after %s of propagation delay", waited)
	}
	if s := b.le.Stats(); s.Calls[coretest.OpAccept] != 1 || s.CertificatesIssued != 1 {
		t.Fatalf("CA stats %+v", s)
	}

	b.r53.SetPublicDelay(time.Hour)
	o := c.mustOrder("", "never.example.com")
	var bo *core.Order
	b.pump(5*time.Second, func() { bo = b.waitInvalid(o) })
	if bo.Error == nil || !strings.Contains(bo.Error.Detail, "did not become visible") {
		t.Fatalf("order after propagation timeout: %+v", bo.Error)
	}
	b.noReservations(bo.ID)
	if s := b.le.Stats(); s.Calls[coretest.OpAccept] != 1 {
		t.Fatalf("validation attempted for an invisible value: %+v", s.Calls)
	}
	if v := b.r53.TXT("_acme-challenge.never.example.com"); len(v) != 0 {
		t.Fatalf("value left behind: %v", v)
	}
	b.checkInvariants(0)
}

// An upstream 429 fails the order it hit and closes the provider's circuit:
// the next renewal is refused locally with 429 rateLimited and the CA's
// Retry-After, nothing is sent upstream or to another CA until then.
func testUpstream429(t *testing.T) {
	b := newFakeBroker(t)
	m := b.machine("10.0.0.30", "rl.example.com")
	c := m.acme()
	c.issue("", "rl.example.com")
	b.advance(30 * day)

	b.le.Inject(coretest.Fault{Op: coretest.OpNewOrder, Err: b.le.RateLimited(2 * time.Hour), Times: 1})
	hit := b.waitInvalid(c.mustOrder("", "rl.example.com"))
	if hit.Error == nil || hit.Error.Type != core.ProblemRateLimited {
		t.Fatalf("order that hit the limit: %+v", hit.Error)
	}
	b.noReservations(hit.ID)

	_, err := c.newOrder("", "rl.example.com")
	var rl *acme.RateLimitedError
	if !errors.As(err, &rl) || rl.HTTPStatus != http.StatusTooManyRequests {
		t.Fatalf("newOrder while limited: %v", err)
	}
	if rl.RetryAfter < 2*time.Hour-time.Minute || rl.RetryAfter > 2*time.Hour {
		t.Fatalf("Retry-After %s", rl.RetryAfter)
	}
	if n := b.le.Stats().Calls[coretest.OpNewOrder]; n != 2 {
		t.Fatalf("upstream newOrder calls: %d", n)
	}
	if n := b.goog.Stats().OrdersCreated; n != 0 {
		t.Fatalf("renewal moved to the fallback: %d", n)
	}
	if evs := b.auditEvents(core.AuditRateLimit); len(evs) == 0 {
		t.Fatal("no rate_limit audit event")
	}

	b.advance(2*time.Hour + time.Minute)
	c.issue("", "rl.example.com")
	if n := b.le.Stats().CertificatesIssued; n != 2 {
		t.Fatalf("certificates after the limit passed: %d", n)
	}
	b.checkInvariants(0)
}

// An upstream 503 with Retry-After ("busy"): the order fails, the circuit
// closes for the CA's Retry-After, and the next renewal is refused locally
// as rateLimited (docs/rate-limits.md: a CA asking to back off is treated
// like a rate limit) with the remaining time; after it the provider is used
// again and nothing went to the fallback.
func testUpstream503(t *testing.T) {
	b := newFakeBroker(t)
	m := b.machine("10.0.0.31", "busy.example.com")
	c := m.acme()
	c.issue("", "busy.example.com")
	b.advance(30 * day)

	b.le.Inject(coretest.Fault{Op: coretest.OpNewOrder, Err: b.le.Busy(10 * time.Minute), Times: 1})
	hit := b.waitInvalid(c.mustOrder("", "busy.example.com"))
	b.noReservations(hit.ID)

	_, err := c.newOrder("", "busy.example.com")
	var rl *acme.RateLimitedError
	if !errors.As(err, &rl) || rl.HTTPStatus != http.StatusTooManyRequests {
		t.Fatalf("newOrder while the CA asks to back off: %v", err)
	}
	if rl.RetryAfter < 9*time.Minute || rl.RetryAfter > 10*time.Minute {
		t.Fatalf("Retry-After %s", rl.RetryAfter)
	}
	if n := b.le.Stats().Calls[coretest.OpNewOrder]; n != 2 {
		t.Fatalf("upstream newOrder calls: %d", n)
	}
	b.advance(11 * time.Minute)
	c.issue("", "busy.example.com")
	if n := b.goog.Stats().OrdersCreated; n != 0 {
		t.Fatalf("fallback used: %d", n)
	}
	b.checkInvariants(0)
}

// The primary goes down: new issuance falls back to google; a renewal with
// plenty of lifetime left gets a clean temporary error and is not moved.
func testProviderOutage(t *testing.T) {
	b := newFakeBroker(t)
	m := b.machine("10.0.0.40", "old.example.com", "new.example.com")
	c := m.acme()
	c.issue("", "old.example.com")
	b.advance(30 * day)

	b.le.Inject(coretest.Fault{Op: coretest.OpAny, Err: b.le.Down()})
	b.waitInvalid(c.mustOrder("", "new.example.com")) // trips the circuit

	nw := c.issue("", "new.example.com")
	if p := b.certByARI(nw.certID).Provider; p != "google" {
		t.Fatalf("new issuance during the outage went to %s", p)
	}
	fo := b.auditEvents(core.AuditFailover)
	if len(fo) != 1 || !slices.Contains(fo[0].Names, "new.example.com") {
		t.Fatalf("failover audit %+v", fo)
	}

	before := b.goog.Stats().OrdersCreated
	_, err := c.newOrder("", "old.example.com")
	pd := problem(t, err)
	if pd.HTTPStatus != http.StatusServiceUnavailable || pd.Type != acme.ServerInternalErrorType {
		t.Fatalf("renewal during the outage: %+v", pd)
	}
	if ra := m.retryAfter(); ra <= 0 {
		t.Fatalf("Retry-After %s", ra)
	}
	if after := b.goog.Stats().OrdersCreated; after != before {
		t.Fatalf("renewal with plenty of lifetime moved to the fallback")
	}
	b.checkInvariants(0)
}

// Close to expiry the renewal may switch provider: the primary is down, the
// certificate expires in four days, the renewal is admitted at google
// (emergency class, no `replaces` across CAs), and the lineage then stays
// there.
func testEmergencySwitch(t *testing.T) {
	b := newFakeBroker(t)
	m := b.machine("10.0.0.41", "em.example.com")
	c := m.acme()
	old := c.issue("", "em.example.com")
	b.advance(86 * day)

	// The renewal's ARI check already finds the primary down (and closes
	// its circuit), so the very first renewal order goes to the fallback.
	b.le.Inject(coretest.Fault{Op: coretest.OpAny, Err: b.le.Down()})
	r := c.issue("", "em.example.com")
	rc := b.certByARI(r.certID)
	ro := b.order(r.orderID)
	if rc.Provider != "google" || ro.Class != core.ClassACMEEmergency || ro.UpstreamReplaces != "" || rc.ReplacesID != "" {
		t.Fatalf("emergency renewal: cert %+v order %+v", rc, ro)
	}
	if fo := b.auditEvents(core.AuditFailover); len(fo) != 1 || fo[0].Provider != "google" {
		t.Fatalf("failover audit %+v", fo)
	}
	_ = old

	b.le.ClearFaults()
	b.advance(60 * day)
	r2 := c.issue("", "em.example.com")
	if rc2 := b.certByARI(r2.certID); rc2.Provider != "google" || rc2.ReplacesID != rc.ID {
		t.Fatalf("renewal after the switch: %+v", rc2)
	}
	b.checkInvariants(0)
}

// Several values at one TXT record coexist: a wildcard and its base in one
// order, two clients' orders running at the same time, and a DNS-proxy
// client's value that outlives an ACME order on the same record.
func testConcurrentTXT(t *testing.T) {
	b := newFakeBroker(t)
	var mu sync.Mutex
	seen := map[string]int{} // most values seen at a record during validation
	lookup := func(ctx context.Context, name string) ([]string, error) {
		v, err := b.r53.LookupTXT(ctx, name)
		mu.Lock()
		seen[name] = max(seen[name], len(v))
		mu.Unlock()
		return v, err
	}
	b.le.SetTXTLookup(lookup)
	most := func(rec string) int {
		mu.Lock()
		defer mu.Unlock()
		return seen[rec]
	}
	b.grant("10.0.0.50", true)
	m := b.machine("10.0.0.50", "cc.example.com", "duo.example.com")

	// Wildcard + base in one order: both values at once.
	m.acme().issue("", "*.cc.example.com", "cc.example.com")
	if n := most("_acme-challenge.cc.example.com"); n != 2 {
		t.Fatalf("values at validation: %d", n)
	}

	// Two clients, two orders on one record, at the same time: the CA's
	// validation of whichever order comes first is held until the other
	// order's value is in Route53 too, so both are published together.
	duo := "_acme-challenge.duo.example.com"
	b.le.SetTXTLookup(func(ctx context.Context, name string) ([]string, error) {
		if name == duo {
			for deadline := time.Now().Add(10 * time.Second); len(b.r53.TXT(duo)) < 2 && time.Now().Before(deadline); {
				time.Sleep(time.Millisecond)
			}
		}
		return lookup(ctx, name)
	})
	c1, c2 := m.acme(), b.machine("10.0.0.51", "duo.example.com").acme()
	b.grant("10.0.0.51", true)
	var err1, err2 error
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); _, err1 = c1.tryIssue("*.duo.example.com") }()
	go func() { defer wg.Done(); _, err2 = c2.tryIssue("duo.example.com") }()
	wg.Wait()
	if err1 != nil || err2 != nil {
		t.Fatalf("concurrent orders: %v / %v", err1, err2)
	}
	if n := most(duo); n != 2 {
		t.Fatalf("values seen during concurrent validation: %d", n)
	}
	b.le.SetTXTLookup(lookup)

	// A DNS-proxy value survives an ACME order on the same record.
	code, _, body := m.postJSON("/dns/present", `{"identifier":"cc.example.com","value":"proxy-value-0123456789"}`)
	if code != http.StatusCreated {
		t.Fatalf("present: %d %s", code, body)
	}
	m.acme().issue("", "cc.example.com")
	if n := most("_acme-challenge.cc.example.com"); n < 2 {
		t.Fatalf("values at validation next to the proxy value: %d", n)
	}
	if v := b.r53.TXT("_acme-challenge.cc.example.com"); !slices.Equal(v, []string{"proxy-value-0123456789"}) {
		t.Fatalf("record after the ACME order: %v", v)
	}
	if v := b.r53.TXT("_acme-challenge.duo.example.com"); len(v) != 0 {
		t.Fatalf("values left behind: %v", v)
	}
	b.checkInvariants(0)
}
