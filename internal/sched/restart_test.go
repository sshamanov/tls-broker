package sched_test

import (
	"context"
	"fmt"
	"math/rand/v2"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"tls-broker/internal/core"
)

func TestStateSurvivesRestart(t *testing.T) {
	e := newEnv(t, limits(core.ProviderLimits{
		NewOrders:   core.Limit{Count: 10, Window: 3 * time.Hour},
		CertsPerSet: core.Limit{Count: 1, Window: 7 * day},
		Concurrency: 2,
	}))
	ctx := context.Background()
	open := e.acquire(req("open", "open.example.com"))
	open.OrderCreated()
	done := e.acquire(req("done", "done.example.com"))
	done.OrderCreated()
	done.Commit()
	reserved := e.acquire(req("reserved", "res.example.com")) // never OrderCreated
	_ = reserved
	e.s.ReportProvider(ctx, "primary", provErr(core.ProviderRateLimited, 30*time.Minute))
	before := e.primary()

	e.clock.Advance(time.Minute)
	e.restart()

	refs, err := e.s.OpenRefs(ctx)
	if err != nil || fmt.Sprint(refs) != "[open reserved]" {
		t.Fatalf("OpenRefs = %v, %v", refs, err)
	}
	after := e.primary()
	if after.Open || !after.State.RetryAfter.Equal(before.State.RetryAfter) || after.Reserved != 2 || after.SlotsInUse != 0 {
		t.Fatalf("after restart %+v", after)
	}
	if got := e.usage(core.BudgetNewOrder, ""); got != 3 {
		t.Fatalf("new orders used %d, want 3", got)
	}
	ae := e.refuse(req("again", "done.example.com"), core.AdmissionRateLimited)
	if ae.RetryAfter != 29*time.Minute { // circuit first
		t.Fatalf("RetryAfter %v", ae.RetryAfter)
	}
	e.clock.Advance(29 * time.Minute)
	ae = e.refuse(req("again", "done.example.com"), core.AdmissionRateLimited)
	if ae.RetryAfter != 7*day-30*time.Minute {
		t.Fatalf("set RetryAfter %v", ae.RetryAfter)
	}

	// Settle the surviving reservations through Reattach.
	tk, err := e.s.Reattach(ctx, "open")
	if err != nil {
		t.Fatal(err)
	}
	tk.PrepDone() // holds no slot: nothing happens
	tk.Commit()
	tk, err = e.s.Reattach(ctx, "reserved")
	if err != nil {
		t.Fatal(err)
	}
	tk.Refund()
	if _, err := e.s.Reattach(ctx, "reserved"); !isNotFound(err) {
		t.Fatalf("Reattach after settlement: %v", err)
	}
	if _, err := e.s.Reattach(ctx, "unknown"); !isNotFound(err) {
		t.Fatalf("Reattach(unknown): %v", err)
	}
	if refs, _ := e.s.OpenRefs(ctx); len(refs) != 0 {
		t.Fatalf("OpenRefs %v", refs)
	}
	reserved2, _ := e.budgets.ListReserved(ctx)
	if len(reserved2) != 0 {
		t.Fatalf("reserved events left: %+v", reserved2)
	}
	evs, _ := e.budgets.ListByRef(ctx, "open")
	if len(evs) != 3 {
		t.Fatalf("events of open: %+v", evs)
	}
	if got := e.usage(core.BudgetNewOrder, ""); got != 2 {
		t.Fatalf("new orders used %d, want 2 (open, done)", got)
	}
}

func TestReattachSharesTheLiveReservation(t *testing.T) {
	e := newEnv(t, limits(unlimited(1)))
	ctx := context.Background()
	e.cfg.Update(func(c *core.Config) {
		ps := append([]core.ProviderConfig(nil), c.Providers...)
		ps[0].Limits.CertsPerSet = core.Limit{Count: 5, Window: day}
		c.Providers = ps
	})
	orig := e.acquire(req("a"))
	again, err := e.s.Reattach(ctx, "a")
	if err != nil {
		t.Fatal(err)
	}
	again.PrepDone() // not the slot holder
	if p := e.primary(); p.SlotsInUse != 1 {
		t.Fatalf("in use %d", p.SlotsInUse)
	}
	again.Refund() // settles, and frees the slot
	orig.Commit()  // too late: refund won
	if p := e.primary(); p.SlotsInUse != 0 || p.Reserved != 0 {
		t.Fatalf("in use %d reserved %d", p.SlotsInUse, p.Reserved)
	}
	if n := len(e.budgets.all()); n != 0 {
		t.Fatalf("store events: %d", n)
	}
}

func TestLongerWindowAfterReloadLoadsOlderEvents(t *testing.T) {
	long := core.ProviderLimits{CertsPerSet: core.Limit{Count: 1, Window: 7 * day}, Concurrency: 1}
	short := core.ProviderLimits{CertsPerSet: core.Limit{Count: 1, Window: time.Hour}, Concurrency: 1}
	setLimits := func(l core.ProviderLimits) func(c *core.Config) {
		return func(c *core.Config) {
			ps := append([]core.ProviderConfig(nil), c.Providers...)
			for i := range ps {
				ps[i].Limits = l
			}
			c.Providers = ps
		}
	}
	e := newEnv(t, setLimits(long))
	e.acquire(req("a")).Commit()
	e.clock.Advance(2 * time.Hour)

	e.cfg.Update(setLimits(short))
	e.restart() // loads only the last hour
	e.acquire(req("b", "a.example.com")).Refund()

	e.cfg.Update(setLimits(long))
	ae := e.refuse(req("c", "a.example.com"), core.AdmissionRateLimited)
	if ae.RetryAfter != 7*day-2*time.Hour {
		t.Fatalf("RetryAfter %v", ae.RetryAfter)
	}
}

func TestPruneDropsOnlyExpiredCommittedEvents(t *testing.T) {
	e := newEnv(t, func(c *core.Config) {
		for i := range c.Providers {
			c.Providers[i].Limits = core.ProviderLimits{CertsPerSet: core.Limit{Count: 9, Window: day}, Concurrency: 4}
		}
	})
	ctx := context.Background()
	e.acquire(req("old")).Commit()
	open := e.acquire(req("open"))
	e.clock.Advance(day + time.Second)
	e.acquire(req("new")).Commit()
	n, err := e.s.Prune(ctx)
	if err != nil || n != 2 { // cert_domain and cert_set of "old"
		t.Fatalf("Prune = %d, %v", n, err)
	}
	if refs, _ := e.s.OpenRefs(ctx); fmt.Sprint(refs) != "[open]" {
		t.Fatalf("OpenRefs %v", refs)
	}
	open.Commit()
	evs, _ := e.budgets.ListByRef(ctx, "open")
	if len(evs) != 2 || evs[0].State != core.BudgetCommitted || evs[1].State != core.BudgetCommitted {
		t.Fatalf("open events %+v", evs)
	}
}

// TestConcurrentAcquireRelease runs many goroutines through acquire, ticket
// methods in random order, cancellation and timeouts, and checks the slot
// bound and that nothing is left over.
func TestConcurrentAcquireRelease(t *testing.T) {
	const slots = 3
	e := newEnv(t, limits(core.ProviderLimits{
		NewOrders:      core.Limit{Count: 1 << 20, Window: time.Hour},
		CertsPerDomain: core.Limit{Count: 1 << 20, Window: time.Hour},
		CertsPerSet:    core.Limit{Count: 1 << 20, Window: time.Hour},
		Concurrency:    slots,
	}))
	goroutinesBefore := runtime.NumGoroutine()
	var holding, peak atomic.Int32
	var admitted, refused atomic.Int32
	var wg sync.WaitGroup
	for g := range 32 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			rng := rand.New(rand.NewPCG(uint64(g), 1))
			for i := range 40 {
				r := req(fmt.Sprintf("g%d-%d", g, i), fmt.Sprintf("h%d.example.com", rng.IntN(5)))
				r.Class = core.PriorityClass(1 + rng.IntN(6))
				r.MaxWait = time.Hour
				r.ARIQualified = rng.IntN(5) == 0
				r.ReuseUpstreamOrder = rng.IntN(4) == 0
				ctx, cancel := context.WithCancel(context.Background())
				if rng.IntN(4) == 0 {
					delay := time.Duration(rng.IntN(200)) * time.Microsecond
					go func() {
						time.Sleep(delay)
						cancel()
					}()
				}
				tk, err := e.s.Acquire(ctx, r)
				if err != nil {
					refused.Add(1)
					cancel()
					continue
				}
				admitted.Add(1)
				n := holding.Add(1)
				for {
					p := peak.Load()
					if n <= p || peak.CompareAndSwap(p, n) {
						break
					}
				}
				if rng.IntN(2) == 0 {
					tk.OrderCreated()
				}
				runtime.Gosched()
				holding.Add(-1)
				switch rng.IntN(4) {
				case 0:
					tk.PrepDone()
					tk.Commit()
				case 1:
					tk.PrepDone()
					go tk.Refund()
					tk.Commit()
				case 2:
					tk.Refund()
					tk.PrepDone()
				default:
					tk.Commit()
					tk.Refund()
				}
				cancel()
			}
		}()
	}
	wg.Wait()
	if peak.Load() > slots {
		t.Fatalf("%d tickets held at once, limit %d", peak.Load(), slots)
	}
	if admitted.Load() == 0 {
		t.Fatal("nothing admitted")
	}
	t.Logf("admitted %d, refused %d, peak %d", admitted.Load(), refused.Load(), peak.Load())
	eventually(t, "settlement", func() bool {
		p := e.primary()
		return p.SlotsInUse == 0 && p.Waiting == 0 && p.Reserved == 0
	})
	reservedLeft, _ := e.budgets.ListReserved(context.Background())
	eventually(t, "store settlement", func() bool {
		reservedLeft, _ = e.budgets.ListReserved(context.Background())
		return len(reservedLeft) == 0
	})
	_ = e.s.Close()
	eventually(t, "goroutines to exit", func() bool { return runtime.NumGoroutine() <= goroutinesBefore })
}
