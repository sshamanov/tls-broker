package store

import (
	"errors"
	"fmt"
	"reflect"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"tls-broker/internal/core"
	"tls-broker/internal/names"
)

// prepare runs Create, SetUpstream and SetPrepared.
func prepare(t *testing.T, s *Store, o *core.Order, url string) {
	t.Helper()
	must(t, s.Orders().Create(ctx, o))
	must(t, s.Orders().SetUpstream(ctx, o.ID, url, "", t0.Add(7*24*time.Hour), t0.Add(time.Second)))
	must(t, s.Orders().SetPrepared(ctx, o.ID, t0.Add(2*time.Second)))
}

// issue takes a fresh order all the way to valid with cert c.
func issue(t *testing.T, s *Store, o *core.Order, c *core.Certificate) {
	t.Helper()
	prepare(t, s, o, "https://ca.example/order/"+o.ID)
	_, first, err := s.Orders().BeginFinalize(ctx, o.ID, "hash-"+o.ID, []byte("csr-"+o.ID), t0.Add(3*time.Second))
	must(t, err)
	if !first {
		t.Fatal("first BeginFinalize not first")
	}
	must(t, s.Orders().Complete(ctx, o.ID, c, t0.Add(4*time.Second)))
}

func TestOrderLifecycle(t *testing.T) {
	s := open(t)
	os := s.Orders()
	o := newOrder("o1", "b.example.com", "a.example.com")
	o.Replaces = "client.replaces"
	o.ARIQualified = true
	must(t, os.Create(ctx, o))
	if !o.UpdatedAt.Equal(t0) {
		t.Fatalf("Create UpdatedAt %v", o.UpdatedAt)
	}
	got, err := os.Get(ctx, "o1")
	must(t, err)
	if !reflect.DeepEqual(got, o) {
		t.Fatalf("Get:\n%+v\nwant\n%+v", got, o)
	}

	exp := t0.Add(7 * 24 * time.Hour)
	must(t, os.SetUpstream(ctx, "o1", "https://ca.example/order/1", "pred.ari", exp, t0.Add(time.Second)))
	got, _ = os.Get(ctx, "o1")
	if got.Prep != core.PrepPreparing || got.UpstreamOrderURL != "https://ca.example/order/1" ||
		got.UpstreamReplaces != "pred.ari" || !got.UpstreamExpiresAt.Equal(exp) || !got.UpdatedAt.Equal(t0.Add(time.Second)) {
		t.Fatalf("after SetUpstream %+v", got)
	}
	wantErr(t, os.SetUpstream(ctx, "o1", "https://ca.example/order/2", "", exp, t0), core.ErrConflict)

	must(t, os.SetPrepared(ctx, "o1", t0.Add(2*time.Second)))
	must(t, os.SetPrepared(ctx, "o1", t0.Add(time.Hour))) // no-op
	got, _ = os.Get(ctx, "o1")
	if got.Prep != core.PrepPrepared || !got.UpdatedAt.Equal(t0.Add(2*time.Second)) {
		t.Fatalf("after SetPrepared %+v", got)
	}

	fo, first, err := os.BeginFinalize(ctx, "o1", "h1", []byte("csr1"), t0.Add(3*time.Second))
	must(t, err)
	if !first || fo.Status != core.OrderProcessing || fo.CSRHash != "h1" || string(fo.CSRDER) != "csr1" {
		t.Fatalf("BeginFinalize %+v first=%v", fo, first)
	}
	got, _ = os.Get(ctx, "o1")
	if !reflect.DeepEqual(got, fo) {
		t.Fatalf("BeginFinalize returned %+v, stored %+v", fo, got)
	}
	again, first, err := os.BeginFinalize(ctx, "o1", "h1", []byte("csr1"), t0.Add(time.Hour))
	must(t, err)
	if first || !reflect.DeepEqual(again, fo) {
		t.Fatalf("same-CSR retry changed state: first=%v %+v", first, again)
	}
	_, _, err = os.BeginFinalize(ctx, "o1", "h2", []byte("csr2"), t0.Add(4*time.Second))
	wantErr(t, err, core.ErrCSRMismatch)

	c := newCert("c1", "o1", o.Names, t0)
	must(t, os.Complete(ctx, "o1", c, t0.Add(5*time.Second)))
	got, _ = os.Get(ctx, "o1")
	if got.Status != core.OrderValid || got.CertificateID != "c1" || got.CSRDER != nil || got.CSRHash != "h1" ||
		!got.UpdatedAt.Equal(t0.Add(5*time.Second)) {
		t.Fatalf("after Complete %+v", got)
	}
	gc, err := s.Certificates().Get(ctx, "c1")
	must(t, err)
	if !reflect.DeepEqual(gc, c) {
		t.Fatalf("certificate\n%+v\nwant\n%+v", gc, c)
	}
	wantErr(t, os.Complete(ctx, "o1", newCert("c2", "o1", o.Names, t0), t0), core.ErrConflict)
	wantErr(t, os.Fail(ctx, "o1", core.NewProblem(core.ProblemServerInternal, "x"), t0), core.ErrConflict)

	// Retries after completion return the final state.
	v, first, err := os.BeginFinalize(ctx, "o1", "h1", []byte("csr1"), t0.Add(time.Hour))
	must(t, err)
	if first || v.Status != core.OrderValid || v.CertificateID != "c1" {
		t.Fatalf("retry after valid: %+v", v)
	}
	_, _, err = os.BeginFinalize(ctx, "o1", "h2", []byte("csr2"), t0.Add(time.Hour))
	wantErr(t, err, core.ErrCSRMismatch)
}

func TestOrderCreateConflicts(t *testing.T) {
	s := open(t)
	os := s.Orders()
	must(t, os.Create(ctx, newOrder("o1", "a.example.com")))
	wantErr(t, os.Create(ctx, newOrder("o1", "b.example.com")), core.ErrConflict)

	o := newOrder("o2", "a.example.com")
	o.Status = core.OrderProcessing
	wantErr(t, os.Create(ctx, o), core.ErrConflict)
	o = newOrder("o3", "a.example.com")
	o.Prep = core.PrepPrepared
	wantErr(t, os.Create(ctx, o), core.ErrConflict)
	o = newOrder("o4", "a.example.com")
	o.CSRHash = "x"
	wantErr(t, os.Create(ctx, o), core.ErrConflict)
	for _, bad := range []*core.Order{
		{ID: "", Mode: core.ModeACME, Names: names.MustSet("a.example.com"), Provider: "le", Status: core.OrderReady, Prep: core.PrepIntent},
		{ID: "x", Mode: "bogus", Names: names.MustSet("a.example.com"), Provider: "le", Status: core.OrderReady, Prep: core.PrepIntent},
		{ID: "x", Mode: core.ModeACME, Provider: "le", Status: core.OrderReady, Prep: core.PrepIntent},
		{ID: "x", Mode: core.ModeACME, Names: names.MustSet("a.example.com"), Status: core.OrderReady, Prep: core.PrepIntent},
	} {
		if err := os.Create(ctx, bad); err == nil {
			t.Errorf("Create accepted %+v", bad)
		}
	}
	_, err := os.Get(ctx, "o2")
	wantErr(t, err, core.ErrNotFound)
	if _, err := os.Get(ctx, "x"); !errors.Is(err, core.ErrNotFound) {
		t.Fatal("invalid order stored")
	}
}

func TestOrderStatePreconditions(t *testing.T) {
	s := open(t)
	os := s.Orders()
	wantErr(t, os.SetUpstream(ctx, "nope", "u", "", t0, t0), core.ErrNotFound)
	wantErr(t, os.SetPrepared(ctx, "nope", t0), core.ErrNotFound)
	wantErr(t, os.Fail(ctx, "nope", nil, t0), core.ErrNotFound)
	wantErr(t, os.Complete(ctx, "nope", newCert("c", "nope", names.MustSet("a.example.com"), t0), t0), core.ErrNotFound)
	_, _, err := os.BeginFinalize(ctx, "nope", "h", []byte("c"), t0)
	wantErr(t, err, core.ErrNotFound)

	must(t, os.Create(ctx, newOrder("o1", "a.example.com")))
	wantErr(t, os.SetPrepared(ctx, "o1", t0), core.ErrConflict) // still intent
	wantErr(t, os.Complete(ctx, "o1", newCert("c1", "o1", names.MustSet("a.example.com"), t0), t0), core.ErrConflict)
	if err := os.SetUpstream(ctx, "o1", "", "", t0, t0); err == nil {
		t.Fatal("empty upstream URL accepted")
	}

	// Finalize before preparation finished is allowed, and preparation can
	// still be recorded afterwards.
	_, first, err := os.BeginFinalize(ctx, "o1", "h", []byte("csr"), t0.Add(time.Second))
	must(t, err)
	if !first {
		t.Fatal("not first")
	}
	must(t, os.SetUpstream(ctx, "o1", "https://ca.example/order/o1", "", t0, t0.Add(2*time.Second)))
	must(t, os.SetPrepared(ctx, "o1", t0.Add(3*time.Second)))
	// Complete checks the certificate belongs to the order.
	wantErr(t, os.Complete(ctx, "o1", newCert("c1", "other", names.MustSet("a.example.com"), t0), t0), core.ErrConflict)
	must(t, os.Complete(ctx, "o1", newCert("c1", "o1", names.MustSet("a.example.com"), t0), t0))

	// Two orders cannot own the same upstream order.
	must(t, os.Create(ctx, newOrder("o2", "a.example.com")))
	wantErr(t, os.SetUpstream(ctx, "o2", "https://ca.example/order/o1", "", t0, t0), core.ErrConflict)
	got, _ := os.Get(ctx, "o2")
	if got.Prep != core.PrepIntent || got.UpstreamOrderURL != "" {
		t.Fatalf("conflicting SetUpstream changed the order: %+v", got)
	}

	// A failed order accepts nothing but a repeated Fail.
	must(t, os.Fail(ctx, "o2", core.NewProblem(core.ProblemServerInternal, "boom"), t0.Add(time.Minute)))
	wantErr(t, os.SetUpstream(ctx, "o2", "https://ca.example/order/o2", "", t0, t0), core.ErrConflict)
	wantErr(t, os.SetPrepared(ctx, "o2", t0), core.ErrConflict)
}

func TestOrderSetPreparedOnFailedPrep(t *testing.T) {
	s := open(t)
	os := s.Orders()
	o := newOrder("o1", "a.example.com")
	must(t, os.Create(ctx, o))
	must(t, os.SetUpstream(ctx, "o1", "https://ca.example/order/1", "", time.Time{}, t0))
	// Expired while preparing: Prep becomes failed, so the late SetPrepared
	// of the background preparation is refused.
	_, err := os.ExpireDue(ctx, o.ExpiresAt)
	must(t, err)
	wantErr(t, os.SetPrepared(ctx, "o1", o.ExpiresAt.Add(time.Second)), core.ErrConflict)
	got, _ := os.Get(ctx, "o1")
	if got.Status != core.OrderInvalid || got.Prep != core.PrepFailed {
		t.Fatalf("%+v", got)
	}
}

func TestOrderBeginFinalizeExpiredAndInvalid(t *testing.T) {
	s := open(t)
	os := s.Orders()
	o := newOrder("o1", "a.example.com")
	must(t, os.Create(ctx, o))
	_, _, err := os.BeginFinalize(ctx, "o1", "h", []byte("c"), o.ExpiresAt)
	wantErr(t, err, core.ErrExpired)
	got, _ := os.Get(ctx, "o1")
	if got.Status != core.OrderReady || got.Finalized() || got.CSRDER != nil {
		t.Fatalf("ErrExpired changed the order: %+v", got)
	}
	// One nanosecond before expiry is fine.
	_, first, err := os.BeginFinalize(ctx, "o1", "h", []byte("c"), o.ExpiresAt.Add(-time.Nanosecond))
	must(t, err)
	if !first {
		t.Fatal("not first")
	}

	o2 := newOrder("o2", "a.example.com")
	must(t, os.Create(ctx, o2))
	p := core.NewProblem(core.ProblemRateLimited, "nope")
	must(t, os.Fail(ctx, "o2", p, t0.Add(time.Second)))
	inv, first, err := os.BeginFinalize(ctx, "o2", "h", []byte("c"), t0.Add(2*time.Second))
	must(t, err)
	if first || inv.Status != core.OrderInvalid || !reflect.DeepEqual(inv.Error, p) || inv.Finalized() {
		t.Fatalf("finalize of invalid order: first=%v %+v", first, inv)
	}
	if err := func() error { _, _, err := os.BeginFinalize(ctx, "o2", "", nil, t0); return err }(); err == nil {
		t.Fatal("empty CSR accepted")
	}
}

func TestOrderBeginFinalizeConcurrent(t *testing.T) {
	s := open(t)
	os := s.Orders()
	must(t, os.Create(ctx, newOrder("same", "a.example.com")))
	must(t, os.Create(ctx, newOrder("diff", "a.example.com")))

	const n = 16
	var wg sync.WaitGroup
	var firstSame, firstDiff, mismatch atomic.Int32
	for i := 0; i < n; i++ {
		wg.Add(2)
		go func() {
			defer wg.Done()
			o, first, err := os.BeginFinalize(ctx, "same", "h", []byte("csr"), t0)
			if err != nil {
				t.Error(err)
				return
			}
			if o.CSRHash != "h" || o.Status != core.OrderProcessing {
				t.Errorf("unexpected %+v", o)
			}
			if first {
				firstSame.Add(1)
			}
		}()
		go func(i int) {
			defer wg.Done()
			h := fmt.Sprintf("h%d", i)
			_, first, err := os.BeginFinalize(ctx, "diff", h, []byte(h), t0)
			switch {
			case errors.Is(err, core.ErrCSRMismatch):
				mismatch.Add(1)
			case err != nil:
				t.Error(err)
			case first:
				firstDiff.Add(1)
			}
		}(i)
	}
	wg.Wait()
	if firstSame.Load() != 1 {
		t.Fatalf("same CSR: %d firsts, want 1", firstSame.Load())
	}
	if firstDiff.Load() != 1 || mismatch.Load() != n-1 {
		t.Fatalf("different CSRs: %d firsts, %d mismatches", firstDiff.Load(), mismatch.Load())
	}
}

func TestOrderFail(t *testing.T) {
	s := open(t)
	os := s.Orders()
	p := core.NewProblem(core.ProblemServerInternal, "upstream broke")

	// Fail before preparation: Prep failed.
	must(t, os.Create(ctx, newOrder("a", "a.example.com")))
	must(t, os.Fail(ctx, "a", p, t0.Add(time.Second)))
	got, _ := os.Get(ctx, "a")
	if got.Status != core.OrderInvalid || got.Prep != core.PrepFailed || !reflect.DeepEqual(got.Error, p) ||
		!got.UpdatedAt.Equal(t0.Add(time.Second)) {
		t.Fatalf("%+v", got)
	}
	// Failing again is a no-op that keeps the first problem.
	must(t, os.Fail(ctx, "a", core.NewProblem(core.ProblemMalformed, "other"), t0.Add(time.Hour)))
	again, _ := os.Get(ctx, "a")
	if !reflect.DeepEqual(again, got) {
		t.Fatalf("second Fail changed the order: %+v", again)
	}

	// Fail of a prepared order keeps Prep prepared (adoptable).
	prepare(t, s, newOrder("b", "b.example.com"), "https://ca.example/order/b")
	must(t, os.Fail(ctx, "b", nil, t0.Add(time.Minute)))
	got, _ = os.Get(ctx, "b")
	if got.Status != core.OrderInvalid || got.Prep != core.PrepPrepared || got.Error != nil {
		t.Fatalf("%+v", got)
	}

	// Fail of a processing order clears the CSR but keeps its hash.
	prepare(t, s, newOrder("c", "c.example.com"), "https://ca.example/order/c")
	_, _, err := os.BeginFinalize(ctx, "c", "hc", []byte("csr"), t0)
	must(t, err)
	must(t, os.Fail(ctx, "c", p, t0.Add(time.Minute)))
	got, _ = os.Get(ctx, "c")
	if got.Status != core.OrderInvalid || got.CSRDER != nil || got.CSRHash != "hc" {
		t.Fatalf("%+v", got)
	}
	var csrNull bool
	must(t, s.r.QueryRow(`SELECT csr_der IS NULL FROM orders WHERE id = 'c'`).Scan(&csrNull))
	if !csrNull {
		t.Fatal("CSR still stored after Fail")
	}
	// A processing order that failed is not adoptable even if prepared.
	_, err = os.FindAdoptable(ctx, "le", "c.example.com", t0)
	wantErr(t, err, core.ErrNotFound)
}

func TestOrderExpireDue(t *testing.T) {
	s := open(t)
	os := s.Orders()
	early := newOrder("early", "a.example.com")
	early.ExpiresAt = t0.Add(time.Minute)
	must(t, os.Create(ctx, early))
	exact := newOrder("exact", "b.example.com")
	exact.ExpiresAt = t0.Add(2 * time.Minute)
	prepare(t, s, exact, "https://ca.example/order/exact")
	later := newOrder("later", "c.example.com")
	later.ExpiresAt = t0.Add(time.Hour)
	must(t, os.Create(ctx, later))
	proc := newOrder("proc", "d.example.com")
	proc.ExpiresAt = t0.Add(time.Minute)
	must(t, os.Create(ctx, proc))
	_, _, err := os.BeginFinalize(ctx, "proc", "h", []byte("csr"), t0)
	must(t, err)

	now := t0.Add(2 * time.Minute)
	out, err := os.ExpireDue(ctx, now)
	must(t, err)
	if len(out) != 2 || out[0].ID != "early" || out[1].ID != "exact" {
		t.Fatalf("ExpireDue returned %v", out)
	}
	for _, o := range out {
		if o.Status != core.OrderInvalid || o.Error == nil || o.Error.Type != core.ProblemMalformed || !o.UpdatedAt.Equal(now) {
			t.Fatalf("expired order %+v", o)
		}
		stored, _ := os.Get(ctx, o.ID)
		if !reflect.DeepEqual(stored, &o) {
			t.Fatalf("returned %+v, stored %+v", o, stored)
		}
	}
	if out[0].Prep != core.PrepFailed || out[1].Prep != core.PrepPrepared {
		t.Fatalf("prep after expiry: %s %s", out[0].Prep, out[1].Prep)
	}
	for _, id := range []string{"later", "proc"} {
		o, _ := os.Get(ctx, id)
		if o.Status.Terminal() {
			t.Fatalf("%s expired: %+v", id, o)
		}
	}
	out, err = os.ExpireDue(ctx, now)
	must(t, err)
	if out == nil || len(out) != 0 {
		t.Fatalf("second ExpireDue: %#v", out)
	}
}

func TestOrderFindOpen(t *testing.T) {
	s := open(t)
	os := s.Orders()
	key := names.MustSet("a.example.com").Key()
	_, err := os.FindOpen(ctx, "acct1", key, t0)
	wantErr(t, err, core.ErrNotFound)

	old := newOrder("old", "a.example.com")
	must(t, os.Create(ctx, old))
	newer := newOrder("newer", "a.example.com")
	newer.CreatedAt = t0.Add(time.Minute)
	newer.ExpiresAt = t0.Add(10 * time.Minute)
	must(t, os.Create(ctx, newer))
	otherAcct := newOrder("otheracct", "a.example.com")
	otherAcct.AccountID = "acct2"
	otherAcct.CreatedAt = t0.Add(2 * time.Minute)
	must(t, os.Create(ctx, otherAcct))
	direct := newOrder("direct", "a.example.com")
	direct.Mode, direct.CreatedAt = core.ModeDirect, t0.Add(3*time.Minute)
	must(t, os.Create(ctx, direct))

	o, err := os.FindOpen(ctx, "acct1", key, t0.Add(5*time.Minute))
	must(t, err)
	if o.ID != "newer" {
		t.Fatalf("FindOpen = %s, want newer", o.ID)
	}
	// "newer" expires first; then "old" is the open one.
	o, err = os.FindOpen(ctx, "acct1", key, t0.Add(10*time.Minute))
	must(t, err)
	if o.ID != "old" {
		t.Fatalf("FindOpen after newer expired = %s", o.ID)
	}
	_, _, err = os.BeginFinalize(ctx, "old", "h", []byte("c"), t0)
	must(t, err)
	_, err = os.FindOpen(ctx, "acct1", key, t0.Add(10*time.Minute))
	wantErr(t, err, core.ErrNotFound)
	_, err = os.FindOpen(ctx, "acct1", names.MustSet("a.example.com", "b.example.com").Key(), t0)
	wantErr(t, err, core.ErrNotFound)
}

// expiredPrepared creates an order whose upstream order is prepared and then
// lets it expire without a CSR: an adoptable donor.
func expiredPrepared(t *testing.T, s *Store, id string, created time.Time, upstreamExpires time.Time, ns ...string) *core.Order {
	t.Helper()
	o := newOrder(id, ns...)
	o.CreatedAt, o.ExpiresAt = created, created.Add(15*time.Minute)
	must(t, s.Orders().Create(ctx, o))
	must(t, s.Orders().SetUpstream(ctx, id, "https://ca.example/order/"+id, "rep-"+id, upstreamExpires, created))
	must(t, s.Orders().SetPrepared(ctx, id, created))
	_, err := s.Orders().ExpireDue(ctx, o.ExpiresAt)
	must(t, err)
	got, err := s.Orders().Get(ctx, id)
	must(t, err)
	return got
}

func TestOrderAdoption(t *testing.T) {
	s := open(t)
	os := s.Orders()
	key := names.MustSet("a.example.com").Key()
	upExp := t0.Add(7 * 24 * time.Hour)
	donor := expiredPrepared(t, s, "donor", t0, upExp, "a.example.com")
	if donor.Status != core.OrderInvalid || donor.Prep != core.PrepPrepared {
		t.Fatalf("donor %+v", donor)
	}
	now := t0.Add(time.Hour)

	found, err := os.FindAdoptable(ctx, "le", key, now)
	must(t, err)
	if found.ID != "donor" {
		t.Fatalf("FindAdoptable = %s", found.ID)
	}
	_, err = os.FindAdoptable(ctx, "gts", key, now)
	wantErr(t, err, core.ErrNotFound)
	_, err = os.FindAdoptable(ctx, "le", names.MustSet("b.example.com").Key(), now)
	wantErr(t, err, core.ErrNotFound)
	// Upstream order expiring within the hour is not usable.
	_, err = os.FindAdoptable(ctx, "le", key, upExp.Add(-time.Hour))
	wantErr(t, err, core.ErrNotFound)
	_, err = os.FindAdoptable(ctx, "le", key, upExp.Add(-time.Hour-time.Nanosecond))
	must(t, err)

	// Preconditions of CreateAdopting.
	wrongProv := newOrder("n0", "a.example.com")
	wrongProv.Provider = "gts"
	wantErr(t, os.CreateAdopting(ctx, wrongProv, "donor"), core.ErrConflict)
	wrongNames := newOrder("n0", "b.example.com")
	wantErr(t, os.CreateAdopting(ctx, wrongNames, "donor"), core.ErrConflict)
	wantErr(t, os.CreateAdopting(ctx, newOrder("n0", "a.example.com"), "missing"), core.ErrNotFound)
	if _, err := os.Get(ctx, "n0"); !errors.Is(err, core.ErrNotFound) {
		t.Fatal("failed CreateAdopting inserted the order")
	}
	// The new ID must be fresh; the donor is left untouched on conflict.
	must(t, os.Create(ctx, newOrder("taken", "z.example.com")))
	wantErr(t, os.CreateAdopting(ctx, newOrder("taken", "a.example.com"), "donor"), core.ErrConflict)
	d, _ := os.Get(ctx, "donor")
	if d.AdoptedByOrderID != "" {
		t.Fatal("donor marked although the insert failed")
	}

	n := newOrder("n1", "a.example.com")
	n.Mode, n.AccountID = core.ModeDirect, "" // either mode may adopt
	n.CreatedAt, n.ExpiresAt = now, now.Add(15*time.Minute)
	must(t, os.CreateAdopting(ctx, n, "donor"))
	if n.Prep != core.PrepPrepared || n.UpstreamOrderURL != donor.UpstreamOrderURL ||
		n.UpstreamReplaces != "rep-donor" || !n.UpstreamExpiresAt.Equal(upExp) {
		t.Fatalf("adopter fields %+v", n)
	}
	got, _ := os.Get(ctx, "n1")
	if !reflect.DeepEqual(got, n) {
		t.Fatalf("stored adopter\n%+v\nwant\n%+v", got, n)
	}
	d, _ = os.Get(ctx, "donor")
	if d.AdoptedByOrderID != "n1" || d.Status != core.OrderInvalid {
		t.Fatalf("donor after adoption %+v", d)
	}
	_, err = os.FindAdoptable(ctx, "le", key, now)
	wantErr(t, err, core.ErrNotFound)
	wantErr(t, os.CreateAdopting(ctx, newOrder("n2", "a.example.com"), "donor"), core.ErrConflict)

	// The adopter runs normally from prepared.
	wantErr(t, os.SetUpstream(ctx, "n1", "https://ca.example/order/x", "", t0, now), core.ErrConflict)
	must(t, os.SetPrepared(ctx, "n1", now)) // no-op
	_, _, err = os.BeginFinalize(ctx, "n1", "h", []byte("csr"), now)
	must(t, err)

	// Non-adoptable donors.
	must(t, os.Create(ctx, newOrder("fresh", "a.example.com")))
	wantErr(t, os.CreateAdopting(ctx, newOrder("n3", "a.example.com"), "fresh"), core.ErrConflict) // not invalid
	must(t, os.Fail(ctx, "fresh", nil, now))
	wantErr(t, os.CreateAdopting(ctx, newOrder("n3", "a.example.com"), "fresh"), core.ErrConflict) // prep failed
	wantErr(t, os.CreateAdopting(ctx, newOrder("n3", "a.example.com"), "n1"), core.ErrConflict)    // has CSR
}

func TestOrderAdoptionChain(t *testing.T) {
	// An adopter that itself expires unfinalized becomes the donor of the
	// next order; the upstream order still has exactly one live owner.
	s := open(t)
	os := s.Orders()
	key := names.MustSet("a.example.com").Key()
	expiredPrepared(t, s, "d0", t0, time.Time{}, "a.example.com")

	a1 := newOrder("a1", "a.example.com")
	a1.CreatedAt, a1.ExpiresAt = t0.Add(time.Hour), t0.Add(time.Hour+15*time.Minute)
	must(t, os.CreateAdopting(ctx, a1, "d0"))
	_, err := os.ExpireDue(ctx, a1.ExpiresAt)
	must(t, err)
	found, err := os.FindAdoptable(ctx, "le", key, a1.ExpiresAt)
	must(t, err)
	if found.ID != "a1" {
		t.Fatalf("FindAdoptable = %s, want a1", found.ID)
	}
	a2 := newOrder("a2", "a.example.com")
	a2.CreatedAt, a2.ExpiresAt = t0.Add(2*time.Hour), t0.Add(2*time.Hour+15*time.Minute)
	must(t, os.CreateAdopting(ctx, a2, "a1"))

	var owners int
	must(t, s.r.QueryRow(`SELECT count(*) FROM orders WHERE upstream_order_url = ? AND adopted_by_order_id = ''`,
		"https://ca.example/order/d0").Scan(&owners))
	if owners != 1 {
		t.Fatalf("%d live owners of the upstream order", owners)
	}
}

func TestOrderAdoptionConcurrent(t *testing.T) {
	s := open(t)
	os := s.Orders()
	key := names.MustSet("a.example.com").Key()
	expiredPrepared(t, s, "donor", t0, time.Time{}, "a.example.com")
	now := t0.Add(time.Hour)

	const n = 24
	var wg sync.WaitGroup
	var adopted atomic.Int32
	start := make(chan struct{})
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			d, err := os.FindAdoptable(ctx, "le", key, now)
			if errors.Is(err, core.ErrNotFound) {
				return
			}
			if err != nil {
				t.Error(err)
				return
			}
			o := newOrder(fmt.Sprintf("n%02d", i), "a.example.com")
			o.CreatedAt = now
			err = os.CreateAdopting(ctx, o, d.ID)
			switch {
			case err == nil:
				adopted.Add(1)
			case !errors.Is(err, core.ErrConflict):
				t.Error(err)
			}
		}(i)
	}
	close(start)
	wg.Wait()
	if adopted.Load() != 1 {
		t.Fatalf("%d adoptions, want exactly 1", adopted.Load())
	}
	var live int
	must(t, s.r.QueryRow(`SELECT count(*) FROM orders WHERE upstream_order_url <> '' AND adopted_by_order_id = ''`).Scan(&live))
	if live != 1 {
		t.Fatalf("%d live owners", live)
	}
}

func TestOrderListActiveAndList(t *testing.T) {
	s := open(t)
	os := s.Orders()
	for i, id := range []string{"o1", "o2", "o3", "o4"} {
		o := newOrder(id, fmt.Sprintf("h%d.example.com", i))
		o.CreatedAt = t0.Add(time.Duration(i) * time.Minute)
		if i == 3 {
			o.Mode, o.Provider = core.ModeDirect, "gts"
		}
		must(t, os.Create(ctx, o))
	}
	_, _, err := os.BeginFinalize(ctx, "o2", "h", []byte("c"), t0)
	must(t, err)
	must(t, os.Fail(ctx, "o3", nil, t0))

	ids := func(list []core.Order) []string {
		out := []string{}
		for _, o := range list {
			out = append(out, o.ID)
		}
		return out
	}
	act, err := os.ListActive(ctx)
	must(t, err)
	if want := []string{"o1", "o2", "o4"}; !reflect.DeepEqual(ids(act), want) {
		t.Fatalf("ListActive %v", ids(act))
	}

	for _, tc := range []struct {
		f    core.OrderFilter
		want []string
	}{
		{core.OrderFilter{}, []string{"o4", "o3", "o2", "o1"}},
		{core.OrderFilter{Mode: core.ModeDirect}, []string{"o4"}},
		{core.OrderFilter{Status: core.OrderInvalid}, []string{"o3"}},
		{core.OrderFilter{Provider: "le"}, []string{"o3", "o2", "o1"}},
		{core.OrderFilter{NameContains: "h1."}, []string{"o2"}},
		{core.OrderFilter{NameContains: "%"}, []string{}},
		{core.OrderFilter{Limit: 2}, []string{"o4", "o3"}},
		{core.OrderFilter{Limit: 2, Offset: 3}, []string{"o1"}},
	} {
		got, err := os.List(ctx, tc.f)
		must(t, err)
		if !reflect.DeepEqual(ids(got), tc.want) {
			t.Errorf("List(%+v) = %v, want %v", tc.f, ids(got), tc.want)
		}
	}
}

func TestOrderPrune(t *testing.T) {
	s := open(t)
	os := s.Orders()
	set := names.MustSet("a.example.com")
	issue(t, s, newOrder("valid", "a.example.com"), newCert("c1", "valid", set, t0))
	must(t, os.Create(ctx, newOrder("failed", "b.example.com")))
	must(t, os.Fail(ctx, "failed", nil, t0.Add(time.Minute)))
	expiredPrepared(t, s, "donor", t0, time.Time{}, "d.example.com")
	expiredPrepared(t, s, "donor2", t0, time.Time{}, "e.example.com")
	// Created after the ExpireDue calls above so that they stay active.
	must(t, os.Create(ctx, newOrder("active", "c.example.com")))
	ad := newOrder("adopter", "d.example.com")
	must(t, os.CreateAdopting(ctx, ad, "donor"))
	ad2 := newOrder("adopter2", "e.example.com")
	must(t, os.CreateAdopting(ctx, ad2, "donor2"))
	must(t, os.Fail(ctx, "adopter2", nil, t0))

	n, err := os.Prune(ctx, t0) // nothing is older than t0
	must(t, err)
	if n != 0 {
		t.Fatalf("pruned %d", n)
	}
	n, err = os.Prune(ctx, t0.Add(24*time.Hour))
	must(t, err)
	// valid, failed, donor2, adopter2 go; active, adopter and donor stay.
	if n != 4 {
		t.Fatalf("pruned %d, want 4", n)
	}
	for _, id := range []string{"active", "donor", "adopter"} {
		if _, err := os.Get(ctx, id); err != nil {
			t.Errorf("%s pruned: %v", id, err)
		}
	}
	if _, err := s.Certificates().Get(ctx, "c1"); err != nil {
		t.Fatalf("certificate pruned with its order: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Certificates
// ---------------------------------------------------------------------------

func TestCompleteReplacementLinks(t *testing.T) {
	s := open(t)
	set := names.MustSet("a.example.com")
	issue(t, s, newOrder("o1", "a.example.com"), newCert("c1", "o1", set, t0))

	c2 := newCert("c2", "o2", set, t0.Add(60*24*time.Hour))
	c2.ReplacesID = "c1"
	issue(t, s, newOrder("o2", "a.example.com"), c2)
	c1, err := s.Certificates().Get(ctx, "c1")
	must(t, err)
	if c1.ReplacedByID != "c2" {
		t.Fatalf("c1.ReplacedByID = %q", c1.ReplacedByID)
	}
	// A second certificate naming the same predecessor does not steal it.
	c3 := newCert("c3", "o3", set, t0.Add(61*24*time.Hour))
	c3.ReplacesID = "c1"
	issue(t, s, newOrder("o3", "a.example.com"), c3)
	c1, _ = s.Certificates().Get(ctx, "c1")
	if c1.ReplacedByID != "c2" {
		t.Fatalf("c1.ReplacedByID overwritten: %q", c1.ReplacedByID)
	}
	// An unknown predecessor is ignored.
	c4 := newCert("c4", "o4", set, t0.Add(62*24*time.Hour))
	c4.ReplacesID = "unknown"
	issue(t, s, newOrder("o4", "a.example.com"), c4)
}

func TestCompleteConflictsLeaveOrderProcessing(t *testing.T) {
	s := open(t)
	set := names.MustSet("a.example.com")
	issue(t, s, newOrder("o1", "a.example.com"), newCert("c1", "o1", set, t0))

	prepare(t, s, newOrder("o2", "a.example.com"), "https://ca.example/order/o2")
	_, _, err := s.Orders().BeginFinalize(ctx, "o2", "h", []byte("csr"), t0)
	must(t, err)
	dupARI := newCert("c2", "o2", set, t0)
	dupARI.ARICertID = "aki.c1"
	wantErr(t, s.Orders().Complete(ctx, "o2", dupARI, t0), core.ErrConflict)
	dupID := newCert("c1", "o2", set, t0)
	dupID.ARICertID = "aki.other"
	wantErr(t, s.Orders().Complete(ctx, "o2", dupID, t0), core.ErrConflict)
	o, _ := s.Orders().Get(ctx, "o2")
	if o.Status != core.OrderProcessing || string(o.CSRDER) != "csr" || o.CertificateID != "" {
		t.Fatalf("failed Complete changed the order: %+v", o)
	}
	_, err = s.Certificates().Get(ctx, "c2")
	wantErr(t, err, core.ErrNotFound)

	// Certificates without ARI identifier may coexist.
	a := newCert("c2", "o2", set, t0)
	a.ARICertID = ""
	must(t, s.Orders().Complete(ctx, "o2", a, t0))
	prepare(t, s, newOrder("o3", "a.example.com"), "https://ca.example/order/o3")
	_, _, err = s.Orders().BeginFinalize(ctx, "o3", "h", []byte("csr"), t0)
	must(t, err)
	b := newCert("c3", "o3", set, t0)
	b.ARICertID = ""
	must(t, s.Orders().Complete(ctx, "o3", b, t0))
	_, err = s.Certificates().GetByARICertID(ctx, "")
	wantErr(t, err, core.ErrNotFound)
}

func TestCertificateQueries(t *testing.T) {
	s := open(t)
	cs := s.Certificates()
	a := names.MustSet("a.example.com")
	day := 24 * time.Hour

	c1 := newCert("c1", "o1", a, t0)
	issue(t, s, newOrder("o1", "a.example.com"), c1)
	c2 := newCert("c2", "o2", a, t0.Add(30*day))
	issue(t, s, newOrder("o2", "a.example.com"), c2)
	c3 := newCert("c3", "o3", a, t0.Add(40*day))
	c3.Provider = "gts"
	issue(t, s, newOrder("o3", "a.example.com"), c3)
	d := newOrder("o4", "b.example.com")
	d.Mode = core.ModeDirect
	c4 := newCert("c4", "o4", names.MustSet("b.example.com"), t0.Add(-time.Hour))
	c4.Mode = core.ModeDirect
	issue(t, s, d, c4)

	got, err := cs.GetByARICertID(ctx, "aki.c2")
	must(t, err)
	if !reflect.DeepEqual(got, c2) {
		t.Fatalf("GetByARICertID %+v", got)
	}
	_, err = cs.GetByARICertID(ctx, "nope")
	wantErr(t, err, core.ErrNotFound)
	_, err = cs.Get(ctx, "nope")
	wantErr(t, err, core.ErrNotFound)

	got, err = cs.Newest(ctx, a.Key(), "")
	must(t, err)
	if got.ID != "c3" {
		t.Fatalf("Newest any = %s", got.ID)
	}
	got, err = cs.Newest(ctx, a.Key(), "le")
	must(t, err)
	if got.ID != "c2" {
		t.Fatalf("Newest le = %s", got.ID)
	}
	_, err = cs.Newest(ctx, "z.example.com", "")
	wantErr(t, err, core.ErrNotFound)

	got, err = cs.NewestUnreplaced(ctx, a.Key(), "le", t0)
	must(t, err)
	if got.ID != "c2" {
		t.Fatalf("NewestUnreplaced = %s", got.ID)
	}
	must(t, cs.MarkReplaced(ctx, "c2", "cX"))
	must(t, cs.MarkReplaced(ctx, "c2", "cY")) // already set: no change
	got, _ = cs.Get(ctx, "c2")
	if got.ReplacedByID != "cX" {
		t.Fatalf("ReplacedByID = %q", got.ReplacedByID)
	}
	wantErr(t, cs.MarkReplaced(ctx, "nope", "cX"), core.ErrNotFound)
	got, err = cs.NewestUnreplaced(ctx, a.Key(), "le", t0)
	must(t, err)
	if got.ID != "c1" {
		t.Fatalf("NewestUnreplaced after replacement = %s", got.ID)
	}
	// c1 expires at t0+90d: not a usable predecessor at or after that.
	_, err = cs.NewestUnreplaced(ctx, a.Key(), "le", c1.NotAfter)
	wantErr(t, err, core.ErrNotFound)
	if _, err := cs.NewestUnreplaced(ctx, a.Key(), "", t0); err == nil {
		t.Fatal("NewestUnreplaced without provider succeeded")
	}

	ids := func(list []core.Certificate) []string {
		out := []string{}
		for _, c := range list {
			if c.ChainPEM != nil {
				t.Errorf("List returned the chain of %s", c.ID)
			}
			out = append(out, c.ID)
		}
		return out
	}
	for _, tc := range []struct {
		f    core.CertificateFilter
		want []string
	}{
		{core.CertificateFilter{}, []string{"c3", "c2", "c1", "c4"}},
		{core.CertificateFilter{Mode: core.ModeDirect}, []string{"c4"}},
		{core.CertificateFilter{Provider: "gts"}, []string{"c3"}},
		{core.CertificateFilter{NameContains: "b.example"}, []string{"c4"}},
		{core.CertificateFilter{ValidAt: t0.Add(100 * day)}, []string{"c3", "c2"}},
		{core.CertificateFilter{Limit: 1, Offset: 1}, []string{"c2"}},
	} {
		list, err := cs.List(ctx, tc.f)
		must(t, err)
		if got := ids(list); !reflect.DeepEqual(got, tc.want) {
			t.Errorf("List(%+v) = %v, want %v", tc.f, got, tc.want)
		}
	}

	// DropChains: c1 expired before t0+91d; c4 is direct (no chain stored).
	n, err := cs.DropChains(ctx, t0.Add(91*day))
	must(t, err)
	if n != 1 {
		t.Fatalf("DropChains = %d, want 1", n)
	}
	got, _ = cs.Get(ctx, "c1")
	if got.ChainPEM != nil || got.Serial != "0ac1" || !got.NotAfter.Equal(c1.NotAfter) {
		t.Fatalf("after DropChains %+v", got)
	}
	got, _ = cs.Get(ctx, "c2")
	if string(got.ChainPEM) != "chain of c2" {
		t.Fatal("DropChains dropped a live chain")
	}
	n, _ = cs.DropChains(ctx, t0.Add(91*day))
	if n != 0 {
		t.Fatal("DropChains not idempotent")
	}
}

// ---------------------------------------------------------------------------
// Crash-shaped sequences (architecture §20)
// ---------------------------------------------------------------------------

func TestCrashRecoveryStates(t *testing.T) {
	path := dbPath(t)
	s, err := Open(path)
	must(t, err)
	os := s.Orders()

	// 1. Intent recorded, crash before the URL was stored.
	must(t, os.Create(ctx, newOrder("intent", "a.example.com")))
	// 2. Upstream order known, preparation in flight.
	must(t, os.Create(ctx, newOrder("preparing", "b.example.com")))
	must(t, os.SetUpstream(ctx, "preparing", "https://ca.example/order/b", "", t0.Add(24*time.Hour), t0))
	// 3. CSR recorded and sent, certificate not yet stored.
	prepare(t, s, newOrder("processing", "c.example.com"), "https://ca.example/order/c")
	_, _, err = os.BeginFinalize(ctx, "processing", "hc", []byte("csr-c"), t0)
	must(t, err)
	// 4. Finished.
	issue(t, s, newOrder("valid", "d.example.com"), newCert("cd", "valid", names.MustSet("d.example.com"), t0))
	// Budget reservation that must survive.
	must(t, s.Budgets().Reserve(ctx, []core.BudgetEvent{{Ref: "processing", Provider: "le", Kind: core.BudgetCertSet, Key: "c.example.com", At: t0}}))
	// "Crash": close without any cleanup and reopen.
	must(t, s.Close())
	s = openAt(t, path)
	os = s.Orders()

	act, err := os.ListActive(ctx)
	must(t, err)
	byID := map[string]core.Order{}
	for _, o := range act {
		byID[o.ID] = o
	}
	if len(act) != 3 {
		t.Fatalf("ListActive after restart: %v", act)
	}
	if o := byID["intent"]; o.Prep != core.PrepIntent || o.UpstreamOrderURL != "" {
		t.Fatalf("intent order %+v", o)
	}
	if o := byID["preparing"]; o.Prep != core.PrepPreparing || o.UpstreamOrderURL == "" {
		t.Fatalf("preparing order %+v", o)
	}
	if o := byID["processing"]; o.Status != core.OrderProcessing || string(o.CSRDER) != "csr-c" {
		t.Fatalf("processing order %+v", o)
	}
	res, err := s.Budgets().ListReserved(ctx)
	must(t, err)
	if len(res) != 1 || res[0].Ref != "processing" {
		t.Fatalf("reservations after restart: %+v", res)
	}

	// Recovery: intent without URL -> invalid, never another upstream order.
	must(t, os.Fail(ctx, "intent", core.NewProblem(core.ProblemServerInternal, "interrupted"), t0.Add(time.Hour)))
	o, _ := os.Get(ctx, "intent")
	if o.Status != core.OrderInvalid || o.Prep != core.PrepFailed {
		t.Fatalf("recovered intent %+v", o)
	}
	wantErr(t, os.SetUpstream(ctx, "intent", "https://ca.example/order/late", "", t0, t0), core.ErrConflict)
	// Preparing: resumes.
	must(t, os.SetPrepared(ctx, "preparing", t0.Add(time.Hour)))
	// Processing: the client retries finalize with the same CSR and gets
	// the existing state; the engine completes it.
	p, first, err := os.BeginFinalize(ctx, "processing", "hc", []byte("csr-c"), t0.Add(time.Hour))
	must(t, err)
	if first || p.Status != core.OrderProcessing {
		t.Fatalf("finalize retry after restart: first=%v %+v", first, p)
	}
	must(t, os.Complete(ctx, "processing", newCert("cc", "processing", names.MustSet("c.example.com"), t0), t0.Add(time.Hour)))
	must(t, s.Budgets().Commit(ctx, "processing"))
	// Valid: served from storage.
	v, _ := os.Get(ctx, "valid")
	c, err := s.Certificates().Get(ctx, v.CertificateID)
	must(t, err)
	if string(c.ChainPEM) != "chain of cd" {
		t.Fatalf("persisted certificate %+v", c)
	}
	act, _ = os.ListActive(ctx)
	if len(act) != 1 || act[0].ID != "preparing" {
		t.Fatalf("active after recovery %v", act)
	}
}
