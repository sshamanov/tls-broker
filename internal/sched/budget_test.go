package sched_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"tls-broker/internal/core"
)

func TestSetBudgetExhaustionAndSlidingRetryAfter(t *testing.T) {
	e := newEnv(t, limits(core.ProviderLimits{
		CertsPerSet: core.Limit{Count: 2, Window: 7 * day}, Concurrency: 4,
	}))
	set := []string{"www.example.com"}
	e.acquire(req("a", set...)).Commit() // t0
	e.clock.Advance(time.Hour)
	e.acquire(req("b", set...)).Commit() // t0+1h
	e.clock.Advance(time.Hour)

	ae := e.refuse(req("c", set...), core.AdmissionRateLimited)
	if ae.RetryAfter != 7*day-2*time.Hour {
		t.Fatalf("RetryAfter = %v, want %v", ae.RetryAfter, 7*day-2*time.Hour)
	}
	if !strings.Contains(ae.Reason, "identifier set www.example.com") || ae.Provider != "primary" {
		t.Fatalf("refusal %+v", ae)
	}
	// Other sets are not affected.
	e.acquire(req("other", "api.example.com")).Refund()

	e.clock.Advance(3 * day)
	ae = e.refuse(req("c", set...), core.AdmissionRateLimited)
	if want := 7*day - 2*time.Hour - 3*day; ae.RetryAfter != want {
		t.Fatalf("RetryAfter after 3 days = %v, want %v", ae.RetryAfter, want)
	}
	e.clock.Advance(ae.RetryAfter - time.Nanosecond)
	e.refuse(req("c", set...), core.AdmissionRateLimited)
	e.clock.Advance(time.Nanosecond) // a leaves the window
	e.acquire(req("c", set...)).Commit()
	// Now b and c count; the next room comes when b leaves.
	ae = e.refuse(req("d", set...), core.AdmissionRateLimited)
	if ae.RetryAfter != time.Hour {
		t.Fatalf("RetryAfter = %v, want 1h (b leaves)", ae.RetryAfter)
	}
}

func TestRetryAfterIsTheLongestOfSeveralBudgets(t *testing.T) {
	e := newEnv(t, limits(core.ProviderLimits{
		NewOrders:   core.Limit{Count: 1, Window: time.Hour},
		CertsPerSet: core.Limit{Count: 1, Window: 7 * day},
		Concurrency: 4,
	}))
	tk := e.acquire(req("a"))
	tk.OrderCreated()
	tk.Commit()
	ae := e.refuse(req("b", "a.example.com"), core.AdmissionRateLimited)
	if ae.RetryAfter != 7*day {
		t.Fatalf("RetryAfter = %v, want 7d", ae.RetryAfter)
	}
	ae = e.refuse(req("c"), core.AdmissionRateLimited)
	if ae.RetryAfter != time.Hour || !strings.Contains(ae.Reason, "new orders") {
		t.Fatalf("refusal %+v", ae)
	}
}

func TestDomainBudgetCountsRegisteredDomainsOncePerCertificate(t *testing.T) {
	e := newEnv(t, limits(core.ProviderLimits{
		CertsPerDomain: core.Limit{Count: 2, Window: 7 * day}, Concurrency: 4,
	}))
	// Two names of one registered domain plus one of another.
	e.acquire(req("a", "a.example.com", "b.example.com", "x.example.org")).Commit()
	if got := e.usage(core.BudgetCertDomain, "example.com"); got != 1 {
		t.Fatalf("example.com used %d, want 1", got)
	}
	if got := e.usage(core.BudgetCertDomain, "example.org"); got != 1 {
		t.Fatalf("example.org used %d, want 1", got)
	}
	e.acquire(req("b", "c.example.com")).Commit()
	ae := e.refuse(req("c", "d.example.com"), core.AdmissionRateLimited)
	if !strings.Contains(ae.Reason, "registered domain example.com") {
		t.Fatalf("reason %q", ae.Reason)
	}
	e.acquire(req("d", "y.example.org")).Commit()
}

func TestRenewalReservedHeadroom(t *testing.T) {
	e := newEnv(t, limits(core.ProviderLimits{
		CertsPerDomain:        core.Limit{Count: 4, Window: 7 * day},
		Concurrency:           8,
		RenewalReservePercent: 50,
	}))
	e.acquire(req("n1", "n1.example.com")).Commit()
	e.acquire(req("n2", "n2.example.com")).Commit()
	ae := e.refuse(req("n3", "n3.example.com"), core.AdmissionRateLimited)
	if !strings.Contains(ae.Reason, "reserved for renewals") || ae.RetryAfter != 7*day {
		t.Fatalf("refusal %+v", ae)
	}
	renew := func(ref string) core.AdmissionRequest {
		r := req(ref, ref+".example.com")
		r.Renewal = true
		return r
	}
	e.acquire(renew("r1")).Commit()
	e.acquire(renew("r2")).Commit()
	e.refuse(renew("r3"), core.AdmissionRateLimited)

	var u core.BudgetUsage
	for _, b := range e.primary().Budgets {
		if b.Kind == core.BudgetCertDomain {
			u = b
		}
	}
	if u.Used != 4 || u.Limit != 4 || u.RenewalOnly != 2 || u.Window != 7*day {
		t.Fatalf("usage %+v", u)
	}
}

func TestRenewalReserveNeverBlocksEverything(t *testing.T) {
	e := newEnv(t, limits(core.ProviderLimits{
		CertsPerSet: core.Limit{Count: 1, Window: day}, Concurrency: 1, RenewalReservePercent: 90,
	}))
	e.acquire(req("a")).Commit()
	e.refuse(req("b", "a.example.com"), core.AdmissionRateLimited)
}

func TestRefundReturnsCapacity(t *testing.T) {
	e := newEnv(t, limits(core.ProviderLimits{
		NewOrders:   core.Limit{Count: 1, Window: 3 * time.Hour},
		CertsPerSet: core.Limit{Count: 1, Window: 7 * day},
		Concurrency: 4,
	}))
	// Refund before OrderCreated: everything comes back.
	e.acquire(req("a")).Refund()
	if n := len(e.budgets.all()); n != 0 {
		t.Fatalf("store events after refund: %d", n)
	}
	// Refund after OrderCreated: the new order stays spent, the set does not.
	tk := e.acquire(req("b", "a.example.com"))
	tk.OrderCreated()
	tk.Refund()
	if got := e.usage(core.BudgetNewOrder, ""); got != 1 {
		t.Fatalf("new orders used %d, want 1", got)
	}
	if got := e.usage(core.BudgetCertSet, "a.example.com"); got != 0 {
		t.Fatalf("set used %d, want 0", got)
	}
	e.refuse(req("c", "a.example.com"), core.AdmissionRateLimited)
	// Adopting an existing upstream order spends no new-order budget.
	r := req("d", "a.example.com")
	r.ReuseUpstreamOrder = true
	tk = e.acquire(r)
	tk.OrderCreated() // nothing to commit
	tk.Commit()
	evs, _ := e.budgets.ListByRef(context.Background(), "d")
	if len(evs) != 2 { // cert_domain (counted though not enforced) + cert_set
		t.Fatalf("events of d: %+v", evs)
	}
	for _, ev := range evs {
		if ev.Kind == core.BudgetNewOrder || ev.State != core.BudgetCommitted {
			t.Fatalf("events of d: %+v", evs)
		}
	}
}

func TestCommitWithoutOrderCreatedReturnsNewOrder(t *testing.T) {
	e := newEnv(t, nil)
	tk := e.acquire(req("a"))
	tk.Commit()
	evs, _ := e.budgets.ListByRef(context.Background(), "a")
	for _, ev := range evs {
		if ev.Kind == core.BudgetNewOrder || ev.State != core.BudgetCommitted {
			t.Fatalf("event %+v after Commit without OrderCreated", ev)
		}
	}
	if len(evs) != 2 { // cert_domain + cert_set
		t.Fatalf("events %+v", evs)
	}
	if got := e.usage(core.BudgetNewOrder, ""); got != 0 {
		t.Fatalf("new orders used %d", got)
	}
}

func TestTicketSettlementIsIdempotentInAnyOrder(t *testing.T) {
	e := newEnv(t, nil)
	tk := e.acquire(req("a"))
	tk.OrderCreated()
	tk.OrderCreated()
	tk.Commit()
	tk.Refund()
	tk.Commit()
	tk.PrepDone()
	tk.OrderCreated()
	evs, _ := e.budgets.ListByRef(context.Background(), "a")
	if len(evs) != 3 {
		t.Fatalf("events %+v", evs)
	}
	for _, ev := range evs {
		if ev.State != core.BudgetCommitted {
			t.Fatalf("event %+v not committed", ev)
		}
	}

	tk = e.acquire(req("b"))
	tk.Refund()
	tk.OrderCreated() // after settlement: nothing
	tk.Commit()
	if evs, _ := e.budgets.ListByRef(context.Background(), "b"); len(evs) != 0 {
		t.Fatalf("events after refund: %+v", evs)
	}
	if p := e.primary(); p.SlotsInUse != 0 || p.Reserved != 0 {
		t.Fatalf("in use %d reserved %d", p.SlotsInUse, p.Reserved)
	}
	if tk.Ref() != "b" {
		t.Fatalf("Ref %q", tk.Ref())
	}
}

func TestARIQualifiedIsExemptFromBudgets(t *testing.T) {
	e := newEnv(t, limits(core.ProviderLimits{
		NewOrders:      core.Limit{Count: 1, Window: 3 * time.Hour},
		CertsPerDomain: core.Limit{Count: 1, Window: 7 * day},
		CertsPerSet:    core.Limit{Count: 1, Window: 7 * day},
		Concurrency:    1,
	}))
	tk := e.acquire(req("first", "www.example.com"))
	tk.OrderCreated()
	tk.Commit()
	e.refuse(req("plain", "www.example.com"), core.AdmissionRateLimited)

	r := req("ari", "www.example.com")
	r.ARIQualified, r.Renewal, r.Class = true, true, core.ClassARIRenewal
	ari := e.acquire(r)
	if evs, _ := e.budgets.ListByRef(context.Background(), "ari"); len(evs) != 0 {
		t.Fatalf("ARI request reserved %+v", evs)
	}
	if _, err := e.s.Reattach(context.Background(), "ari"); !isNotFound(err) {
		t.Fatalf("Reattach(ari) = %v, want ErrNotFound", err)
	}
	if refs, _ := e.s.OpenRefs(context.Background()); len(refs) != 0 {
		t.Fatalf("OpenRefs %v", refs)
	}
	// It still takes the only slot, and still holds its Ref.
	if p := e.primary(); p.SlotsInUse != 1 {
		t.Fatalf("in use %d", p.SlotsInUse)
	}
	if _, err := e.s.Acquire(context.Background(), r); !errors.Is(err, core.ErrConflict) {
		t.Fatalf("second ARI acquire: %v", err)
	}
	ari.OrderCreated()
	ari.Commit()
	if got := e.usage(core.BudgetCertSet, "www.example.com"); got != 1 {
		t.Fatalf("set used %d after ARI commit, want 1", got)
	}
	if got := e.usage(core.BudgetNewOrder, ""); got != 1 {
		t.Fatalf("new orders used %d after ARI commit, want 1", got)
	}
}

func TestReserveFailureHoldsNothing(t *testing.T) {
	e := newEnv(t, limits(core.ProviderLimits{CertsPerSet: core.Limit{Count: 1, Window: day}, Concurrency: 1}))
	e.budgets.failReserve = errors.New("disk full")
	if _, err := e.s.Acquire(context.Background(), req("a")); err == nil || core.AsAdmissionError(err) != nil {
		t.Fatalf("Acquire with failing store = %v", err)
	}
	if p := e.primary(); p.SlotsInUse != 0 || p.Reserved != 0 {
		t.Fatalf("in use %d reserved %d", p.SlotsInUse, p.Reserved)
	}
	e.acquire(req("a")).Commit() // the budget was not consumed
}

func TestSnapshotListsBudgets(t *testing.T) {
	e := newEnv(t, nil)
	tk := e.acquire(req("a", "a.example.com", "b.example.org"))
	snap := e.s.Snapshot()
	if !snap.At.Equal(e.clock.Now()) || len(snap.Providers) != 2 || snap.Providers[0].Name != "primary" || snap.Providers[1].Name != "fallback" {
		t.Fatalf("snapshot %+v", snap)
	}
	var got []string
	for _, b := range snap.Providers[0].Budgets {
		got = append(got, string(b.Kind)+":"+b.Key)
	}
	want := "new_order:,cert_domain:example.com,cert_domain:example.org,cert_set:a.example.com,b.example.org"
	if strings.Join(got, ",") != want {
		t.Fatalf("budgets %v", got)
	}
	if fb := snap.Providers[1]; len(fb.Budgets) != 1 || fb.Budgets[0].Used != 0 || !fb.Open || fb.SlotsTotal != 4 {
		t.Fatalf("fallback %+v", fb)
	}
	tk.Refund()
	if n := len(e.primary().Budgets); n != 1 {
		t.Fatalf("budgets after refund: %d", n)
	}
}
