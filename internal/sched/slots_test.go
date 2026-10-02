package sched_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"tls-broker/internal/core"
	"tls-broker/internal/sched"
)

func TestWaitersServedByClassThenArrival(t *testing.T) {
	e := newEnv(t, limits(unlimited(1)))
	holder := e.acquire(req("holder"))
	out := make(chan result, 8)

	queue := []struct {
		ref   string
		class core.PriorityClass
	}{
		{"bg", core.ClassDirectBackground},
		{"ord1", core.ClassACMEOrdinary},
		{"ari", core.ClassARIRenewal},
		{"ord2", core.ClassACMEOrdinary},
		{"miss", core.ClassDirectMiss},
		{"ord3", core.ClassACMEOrdinary},
		{"emerg", core.ClassDirectEmergency},
	}
	for _, q := range queue {
		r := req(q.ref)
		r.Class, r.MaxWait = q.class, time.Hour
		e.startWaiter(context.Background(), r, out)
	}

	want := []string{"ari", "emerg", "ord1", "ord2", "ord3", "miss", "bg"}
	holder.PrepDone()
	for i, ref := range want {
		got := recv(t, out)
		if got.err != nil || got.ref != ref {
			t.Fatalf("grant %d = %s (%v), want %s", i, got.ref, got.err, ref)
		}
		noResult(t, out) // one slot: nobody else may be admitted yet
		if p := e.primary(); p.SlotsInUse != 1 || p.Waiting != len(want)-i-1 {
			t.Fatalf("after grant %d: in use %d waiting %d", i, p.SlotsInUse, p.Waiting)
		}
		got.tk.PrepDone()
	}
	if p := e.primary(); p.SlotsInUse != 0 || p.Waiting != 0 {
		t.Fatalf("end: in use %d waiting %d", p.SlotsInUse, p.Waiting)
	}
}

func TestMaxWaitExpiryReturnsReservation(t *testing.T) {
	e := newEnv(t, func(c *core.Config) {
		c.Providers[0].Limits.Concurrency = 1
		c.Scheduler.BusyRetryAfter = 45 * time.Second
	})
	holder := e.acquire(req("holder"))
	out := make(chan result, 1)
	r := req("waiter")
	r.MaxWait = 10 * time.Second
	e.startWaiter(context.Background(), r, out)
	if !e.clock.BlockUntil(1, 5*time.Second) {
		t.Fatal("wait timer never armed")
	}
	if got := e.primary().Reserved; got != 2 {
		t.Fatalf("Reserved while waiting = %d, want 2", got)
	}
	e.clock.Advance(9 * time.Second)
	noResult(t, out)
	e.clock.Advance(time.Second)
	got := recv(t, out)
	ae := core.AsAdmissionError(got.err)
	if ae == nil || ae.Kind != core.AdmissionBusy || ae.RetryAfter != 45*time.Second {
		t.Fatalf("waiter result %v, want busy with 45s", got.err)
	}
	p := e.primary()
	if p.Waiting != 0 || p.SlotsInUse != 1 || p.Reserved != 1 {
		t.Fatalf("after expiry: waiting %d in use %d reserved %d", p.Waiting, p.SlotsInUse, p.Reserved)
	}
	if evs, _ := e.budgets.ListByRef(context.Background(), "waiter"); len(evs) != 0 {
		t.Fatalf("expired waiter left budget events: %+v", evs)
	}
	holder.Refund()
	if p := e.primary(); p.SlotsInUse != 0 {
		t.Fatalf("slot leaked: in use %d", p.SlotsInUse)
	}
	e.acquire(req("waiter")).Refund() // the Ref is free again
}

func TestDefaultMaxWaitIsAdmitWait(t *testing.T) {
	e := newEnv(t, func(c *core.Config) {
		c.Providers[0].Limits.Concurrency = 1
		c.Scheduler.AdmitWait = 5 * time.Second
	})
	e.acquire(req("holder"))
	out := make(chan result, 1)
	r := req("waiter")
	r.MaxWait = 0
	e.startWaiter(context.Background(), r, out)
	if !e.clock.BlockUntil(1, 5*time.Second) {
		t.Fatal("wait timer never armed")
	}
	e.clock.Advance(4 * time.Second)
	noResult(t, out)
	e.clock.Advance(time.Second)
	if got := recv(t, out); core.AsAdmissionError(got.err) == nil {
		t.Fatalf("got %v, want busy refusal", got.err)
	}
}

func TestNegativeMaxWaitDoesNotWait(t *testing.T) {
	e := newEnv(t, limits(unlimited(1)))
	e.acquire(req("holder"))
	e.refuse(req("now"), core.AdmissionBusy)
	if p := e.primary(); p.Waiting != 0 || p.Reserved != 1 {
		t.Fatalf("waiting %d reserved %d", p.Waiting, p.Reserved)
	}
}

func TestContextCancelWhileWaiting(t *testing.T) {
	e := newEnv(t, limits(unlimited(1)))
	holder := e.acquire(req("holder"))
	ctx, cancel := context.WithCancel(context.Background())
	out := make(chan result, 1)
	r := req("waiter")
	r.MaxWait = time.Hour
	e.startWaiter(ctx, r, out)
	cancel()
	got := recv(t, out)
	if !errors.Is(got.err, context.Canceled) || got.tk != nil {
		t.Fatalf("got %v, want context.Canceled", got.err)
	}
	if p := e.primary(); p.Waiting != 0 || p.Reserved != 1 {
		t.Fatalf("after cancel: waiting %d reserved %d", p.Waiting, p.Reserved)
	}
	holder.PrepDone()
	if p := e.primary(); p.SlotsInUse != 0 {
		t.Fatalf("slot handed to a cancelled waiter: in use %d", p.SlotsInUse)
	}
	if _, err := e.s.Acquire(ctx, req("late")); !errors.Is(err, context.Canceled) {
		t.Fatalf("Acquire with done ctx = %v", err)
	}
}

func TestPrepDoneReleasesSlotOnce(t *testing.T) {
	e := newEnv(t, limits(unlimited(2)))
	a := e.acquire(req("a"))
	e.acquire(req("b"))
	a.PrepDone()
	a.PrepDone()
	a.Commit()
	a.Refund()
	if p := e.primary(); p.SlotsInUse != 1 {
		t.Fatalf("in use %d, want 1", p.SlotsInUse)
	}
}

func TestConfigReloadAddsSlots(t *testing.T) {
	e := newEnv(t, limits(unlimited(1)))
	e.acquire(req("holder"))
	out := make(chan result, 1)
	r := req("waiter")
	r.MaxWait = time.Hour
	e.startWaiter(context.Background(), r, out)
	e.cfg.Update(func(c *core.Config) {
		ps := append([]core.ProviderConfig(nil), c.Providers...)
		ps[0].Limits.Concurrency = 2
		c.Providers = ps
	})
	got := recv(t, out)
	if got.err != nil {
		t.Fatalf("waiter after reload: %v", got.err)
	}
	if p := e.primary(); p.SlotsTotal != 2 || p.SlotsInUse != 2 {
		t.Fatalf("slots %d/%d", p.SlotsInUse, p.SlotsTotal)
	}
}

func TestCloseFailsWaitersAndRefusesNewRequests(t *testing.T) {
	e := newEnv(t, limits(unlimited(1)))
	holder := e.acquire(req("holder"))
	out := make(chan result, 1)
	r := req("waiter")
	r.MaxWait = time.Hour
	e.startWaiter(context.Background(), r, out)
	if err := e.s.Close(); err != nil {
		t.Fatal(err)
	}
	if got := recv(t, out); !errors.Is(got.err, sched.ErrClosed) {
		t.Fatalf("waiter after Close: %v", got.err)
	}
	if _, err := e.s.Acquire(context.Background(), req("x")); !errors.Is(err, sched.ErrClosed) {
		t.Fatalf("Acquire after Close: %v", err)
	}
	holder.Commit() // tickets keep working
	if err := e.s.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestRequestValidation(t *testing.T) {
	e := newEnv(t, nil)
	r := req("a")
	r.Provider = "nope"
	if _, err := e.s.Acquire(context.Background(), r); err == nil || core.AsAdmissionError(err) != nil {
		t.Fatalf("unknown provider: %v", err)
	}
	r = req("a")
	r.Class = 0
	if _, err := e.s.Acquire(context.Background(), r); err == nil {
		t.Fatal("invalid class admitted")
	}
	r = req("x")
	r.Ref = ""
	if _, err := e.s.Acquire(context.Background(), r); err == nil {
		t.Fatal("empty ref admitted")
	}
	tk := e.acquire(req("dup"))
	if _, err := e.s.Acquire(context.Background(), req("dup")); !errors.Is(err, core.ErrConflict) {
		t.Fatalf("second Acquire for one Ref: %v", err)
	}
	tk.Refund()
	e.acquire(req("dup"))
}
