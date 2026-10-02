package sched_test

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"tls-broker/internal/core"
)

func provErr(kind core.ProviderErrorKind, retry time.Duration) error {
	return &core.ProviderError{Provider: "primary", Kind: kind, RetryAfter: retry}
}

func (e *env) stored(name string) core.ProviderState {
	e.t.Helper()
	st, err := e.states.Get(context.Background(), name)
	if err != nil {
		e.t.Fatalf("stored state of %s: %v", name, err)
	}
	return *st
}

func TestRateLimitClosesUntilRetryAfter(t *testing.T) {
	e := newEnv(t, nil)
	ctx := context.Background()
	t0 := e.clock.Now()
	e.s.ReportProvider(ctx, "primary", provErr(core.ProviderRateLimited, 10*time.Minute))

	ae := e.refuse(req("a"), core.AdmissionRateLimited)
	if ae.RetryAfter != 10*time.Minute {
		t.Fatalf("RetryAfter %v", ae.RetryAfter)
	}
	st := e.stored("primary")
	if st.Health != core.ProviderLimited || !st.RetryAfter.Equal(t0.Add(10*time.Minute)) || st.Failures != 1 || st.LastError == "" {
		t.Fatalf("stored %+v", st)
	}
	if p := e.primary(); p.Open || p.State.Health != core.ProviderLimited {
		t.Fatalf("snapshot %+v", p)
	}
	// The fallback provider is unaffected.
	r := req("fb")
	r.Provider = "fallback"
	e.acquire(r).Refund()

	e.clock.Advance(4 * time.Minute)
	if ae := e.refuse(req("a"), core.AdmissionRateLimited); ae.RetryAfter != 6*time.Minute {
		t.Fatalf("RetryAfter %v", ae.RetryAfter)
	}
	e.clock.Advance(6 * time.Minute)
	e.acquire(req("a")).Refund()
	if !e.primary().Open {
		t.Fatal("snapshot still closed")
	}

	ev := e.auditor.OfType(core.AuditProviderState)
	if len(ev) != 1 || ev[0].Reason != core.ReasonRateLimited || ev[0].Provider != "primary" {
		t.Fatalf("audit %+v", ev)
	}
}

func TestDefaultRetryAfterPerKind(t *testing.T) {
	e := newEnv(t, func(c *core.Config) {
		c.Scheduler.RateLimitRetryAfter = 2 * time.Hour
		c.Scheduler.BusyRetryAfter = 30 * time.Second
	})
	ctx := context.Background()
	e.s.ReportProvider(ctx, "primary", provErr(core.ProviderBusy, 0))
	if ae := e.refuse(req("a"), core.AdmissionRateLimited); ae.RetryAfter != 30*time.Second {
		t.Fatalf("busy RetryAfter %v", ae.RetryAfter)
	}
	e.s.ReportProvider(ctx, "primary", provErr(core.ProviderRateLimited, 0))
	if ae := e.refuse(req("a"), core.AdmissionRateLimited); ae.RetryAfter != 2*time.Hour {
		t.Fatalf("rate-limit RetryAfter %v", ae.RetryAfter)
	}
	// A shorter signal does not shorten the closure in force.
	e.s.ReportProvider(ctx, "primary", provErr(core.ProviderBusy, time.Second))
	if ae := e.refuse(req("a"), core.AdmissionRateLimited); ae.RetryAfter != 2*time.Hour {
		t.Fatalf("RetryAfter after shorter signal %v", ae.RetryAfter)
	}
}

func TestDownBacksOffAndProbes(t *testing.T) {
	e := newEnv(t, func(c *core.Config) {
		c.Scheduler.DownRetryAfter = time.Minute
		c.Scheduler.DownRetryAfterMax = 4 * time.Minute
	})
	ctx := context.Background()
	for i, want := range []time.Duration{time.Minute, 2 * time.Minute, 4 * time.Minute, 4 * time.Minute} {
		e.s.ReportProvider(ctx, "primary", provErr(core.ProviderDown, 0))
		ae := e.refuse(req("a"), core.AdmissionProviderDown)
		if ae.RetryAfter != want {
			t.Fatalf("failure %d: RetryAfter %v, want %v", i+1, ae.RetryAfter, want)
		}
		if st := e.stored("primary"); st.Failures != i+1 || st.Health != core.ProviderUnavailable {
			t.Fatalf("failure %d: stored %+v", i+1, st)
		}
		e.clock.Advance(want)
	}
	// RetryAfter passed: one probe goes through, the rest wait for it.
	probe := e.acquire(req("probe"))
	e.refuse(req("other"), core.AdmissionProviderDown)
	probe.PrepDone() // the probe finished without reporting
	probe2 := e.acquire(req("probe2"))
	e.s.ReportProvider(ctx, "primary", nil)
	probe2.Commit()
	st := e.stored("primary")
	if st.Health != core.ProviderHealthy || st.Failures != 0 || !st.RetryAfter.IsZero() || st.LastError != "" {
		t.Fatalf("after success %+v", st)
	}
	e.acquire(req("x")).Refund()
	e.acquire(req("y")).Refund()
}

func TestSuccessDoesNotReopenEarly(t *testing.T) {
	e := newEnv(t, nil)
	ctx := context.Background()
	e.s.ReportProvider(ctx, "primary", provErr(core.ProviderRateLimited, time.Hour))
	e.s.ReportProvider(ctx, "primary", nil) // an in-flight call succeeded
	e.refuse(req("a"), core.AdmissionRateLimited)
	if st := e.stored("primary"); st.Failures != 0 || st.Health != core.ProviderLimited {
		t.Fatalf("stored %+v", st)
	}
}

func TestIgnoredReports(t *testing.T) {
	e := newEnv(t, nil)
	ctx := context.Background()
	for _, err := range []error{
		provErr(core.ProviderRejected, time.Hour),
		provErr(core.ProviderAlreadyReplaced, 0),
		context.Canceled,
		errors.New("something else"),
		nil, // healthy and nothing to reset: no write
	} {
		e.s.ReportProvider(ctx, "primary", err)
	}
	if _, err := e.states.Get(ctx, "primary"); !isNotFound(err) {
		t.Fatalf("state written for ignored reports: %v", err)
	}
	e.acquire(req("a")).Refund()
}

func TestClosingAdmissionFailsWaiters(t *testing.T) {
	e := newEnv(t, limits(unlimited(1)))
	holder := e.acquire(req("holder"))
	out := make(chan result, 2)
	for _, ref := range []string{"w1", "w2"} {
		r := req(ref)
		r.MaxWait = time.Hour
		e.startWaiter(context.Background(), r, out)
	}
	e.s.ReportProvider(context.Background(), "primary", provErr(core.ProviderDown, 5*time.Minute))
	for range 2 {
		got := recv(t, out)
		ae := core.AsAdmissionError(got.err)
		if ae == nil || ae.Kind != core.AdmissionProviderDown || ae.RetryAfter != 5*time.Minute {
			t.Fatalf("waiter %s: %v", got.ref, got.err)
		}
	}
	holder.PrepDone()
	if p := e.primary(); p.SlotsInUse != 0 || p.Waiting != 0 || p.Reserved != 1 {
		t.Fatalf("in use %d waiting %d reserved %d", p.SlotsInUse, p.Waiting, p.Reserved)
	}
	refs, _ := e.s.OpenRefs(context.Background())
	if len(refs) != 1 || refs[0] != "holder" {
		t.Fatalf("OpenRefs %v", refs)
	}
}

// TestNothingAdmittedWhileClosed hammers a closed provider from many
// goroutines, with requests already queued and slots being released, and
// checks that nothing gets through until the closure ends.
func TestNothingAdmittedWhileClosed(t *testing.T) {
	e := newEnv(t, limits(unlimited(2)))
	ctx := context.Background()
	holders := []core.Ticket{e.acquire(req("h1")), e.acquire(req("h2"))}
	out := make(chan result, 64)
	for i := range 8 {
		r := req(fmt.Sprintf("q%d", i))
		r.MaxWait = time.Hour
		r.Class = core.PriorityClass(1 + i%6)
		e.startWaiter(ctx, r, out)
	}
	e.s.ReportProvider(ctx, "primary", provErr(core.ProviderRateLimited, time.Hour))

	var wg sync.WaitGroup
	for i := range 48 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			r := req(fmt.Sprintf("c%d", i))
			r.MaxWait = time.Hour
			tk, err := e.s.Acquire(ctx, r)
			out <- result{r.Ref, tk, err}
		}()
	}
	for _, h := range holders {
		h.Refund()
	}
	wg.Wait()
	for range 56 {
		got := recv(t, out)
		if got.err == nil {
			t.Fatalf("%s admitted while admission was closed", got.ref)
		}
		if ae := core.AsAdmissionError(got.err); ae == nil || ae.Kind != core.AdmissionRateLimited {
			t.Fatalf("%s: %v", got.ref, got.err)
		}
	}
	if p := e.primary(); p.SlotsInUse != 0 || p.Waiting != 0 || p.Reserved != 0 {
		t.Fatalf("in use %d waiting %d reserved %d", p.SlotsInUse, p.Waiting, p.Reserved)
	}
	if n := len(e.budgets.all()); n != 0 {
		t.Fatalf("store holds %d events", n)
	}
	e.clock.Advance(time.Hour)
	e.acquire(req("after")).Refund()
}
