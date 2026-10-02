package sched_test

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"testing"
	"time"

	"tls-broker/internal/core"
	"tls-broker/internal/core/coretest"
	"tls-broker/internal/names"
	"tls-broker/internal/sched"
)

const day = 24 * time.Hour

type env struct {
	t       *testing.T
	clock   *coretest.FakeClock
	cfg     *coretest.FakeConfig
	budgets *memBudgets
	states  *memStates
	auditor *coretest.FakeAuditor
	s       *sched.Scheduler
}

// newEnv builds a scheduler on the coretest fixture configuration, changed
// by mutate when non-nil.
func newEnv(t *testing.T, mutate func(c *core.Config)) *env {
	t.Helper()
	cfg := coretest.NewConfig()
	if mutate != nil {
		mutate(cfg)
	}
	clock := coretest.NewFakeClock()
	e := &env{
		t:       t,
		clock:   clock,
		cfg:     coretest.NewFakeConfig(cfg),
		budgets: &memBudgets{},
		states:  newMemStates(),
		auditor: coretest.NewFakeAuditor(clock),
	}
	e.s = e.start()
	return e
}

func (e *env) start() *sched.Scheduler {
	e.t.Helper()
	s, err := sched.New(context.Background(), sched.Options{
		Config: e.cfg, Budgets: e.budgets, States: e.states, Clock: e.clock,
		Auditor: e.auditor, Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if err != nil {
		e.t.Fatalf("sched.New: %v", err)
	}
	e.t.Cleanup(func() { _ = s.Close() })
	return s
}

// restart closes the scheduler and builds a new one on the same stores.
func (e *env) restart() {
	e.t.Helper()
	_ = e.s.Close()
	e.s = e.start()
}

// primary returns the snapshot of the "primary" provider.
func (e *env) primary() core.ProviderSnapshot {
	e.t.Helper()
	for _, p := range e.s.Snapshot().Providers {
		if p.Name == "primary" {
			return p
		}
	}
	e.t.Fatal("no primary provider in snapshot")
	return core.ProviderSnapshot{}
}

func (e *env) usage(kind core.BudgetKind, key string) int {
	for _, b := range e.primary().Budgets {
		if b.Kind == kind && b.Key == key {
			return b.Used
		}
	}
	return 0
}

// limits replaces the primary provider's limits.
func limits(l core.ProviderLimits) func(c *core.Config) {
	return func(c *core.Config) { c.Providers[0].Limits = l }
}

// unlimited are limits with no budget enforced and the given concurrency.
func unlimited(concurrency int) core.ProviderLimits {
	return core.ProviderLimits{Concurrency: concurrency}
}

func req(ref string, ns ...string) core.AdmissionRequest {
	if len(ns) == 0 {
		ns = []string{ref + ".example.com"}
	}
	return core.AdmissionRequest{
		Ref: ref, Provider: "primary", Names: names.MustSet(ns...),
		Class: core.ClassACMEOrdinary, MaxWait: -1,
	}
}

func (e *env) acquire(r core.AdmissionRequest) core.Ticket {
	e.t.Helper()
	tk, err := e.s.Acquire(context.Background(), r)
	if err != nil {
		e.t.Fatalf("Acquire(%s): %v", r.Ref, err)
	}
	return tk
}

func (e *env) refuse(r core.AdmissionRequest, kind core.AdmissionKind) *core.AdmissionError {
	e.t.Helper()
	tk, err := e.s.Acquire(context.Background(), r)
	if err == nil {
		tk.Refund()
		e.t.Fatalf("Acquire(%s) admitted, want %s refusal", r.Ref, kind)
	}
	ae := core.AsAdmissionError(err)
	if ae == nil || ae.Kind != kind {
		e.t.Fatalf("Acquire(%s) = %v, want %s refusal", r.Ref, err, kind)
	}
	if ae.RetryAfter <= 0 {
		e.t.Fatalf("Acquire(%s) RetryAfter %v, want > 0", r.Ref, ae.RetryAfter)
	}
	return ae
}

// eventually polls cond in real time.
func eventually(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(time.Millisecond)
	}
}

type result struct {
	ref string
	tk  core.Ticket
	err error
}

// startWaiter runs Acquire in a goroutine and waits until the request is
// queued for a slot.
func (e *env) startWaiter(ctx context.Context, r core.AdmissionRequest, out chan<- result) {
	e.t.Helper()
	before := e.primary().Waiting
	go func() {
		tk, err := e.s.Acquire(ctx, r)
		out <- result{r.Ref, tk, err}
	}()
	eventually(e.t, "waiter "+r.Ref+" queued", func() bool { return e.primary().Waiting == before+1 })
}

func recv(t *testing.T, ch <-chan result) result {
	t.Helper()
	select {
	case r := <-ch:
		return r
	case <-time.After(5 * time.Second):
		t.Fatal("no result")
		return result{}
	}
}

func noResult(t *testing.T, ch <-chan result) {
	t.Helper()
	select {
	case r := <-ch:
		t.Fatalf("unexpected result for %s: %v", r.ref, r.err)
	case <-time.After(20 * time.Millisecond):
	}
}

func isNotFound(err error) bool { return errors.Is(err, core.ErrNotFound) }
