package sched

import (
	"context"

	"tls-broker/internal/core"
)

// ticket is a handle to a reservation. Several handles may share one
// reservation (Acquire and later Reattach); settlement happens once.
type ticket struct {
	s   *Scheduler
	res *reservation
	// holdsSlot: this handle came from Acquire and PrepDone may release the
	// slot. Reattached handles hold none.
	holdsSlot bool
}

var _ core.Ticket = (*ticket)(nil)

// Ref implements core.Ticket.
func (t *ticket) Ref() string { return t.res.ref }

// OrderCreated implements core.Ticket: the reserved new-order event becomes
// committed, in memory and in the store.
func (t *ticket) OrderCreated() {
	r, s := t.res, t.s
	r.pmu.Lock()
	defer r.pmu.Unlock()
	s.mu.Lock()
	changed := false
	if !r.settled {
		for _, e := range r.events {
			if e.kind == core.BudgetNewOrder && !e.committed {
				e.committed, changed = true, true
			}
		}
	}
	s.mu.Unlock()
	if changed {
		if err := s.budgets.Commit(context.Background(), r.ref, core.BudgetNewOrder); err != nil {
			s.log.Error("sched: commit new-order budget", "ref", r.ref, "err", err)
		}
	}
}

// PrepDone implements core.Ticket.
func (t *ticket) PrepDone() {
	if !t.holdsSlot {
		return
	}
	t.s.mu.Lock()
	defer t.s.mu.Unlock()
	t.s.releaseSlotLocked(t.res)
}

// Commit implements core.Ticket.
func (t *ticket) Commit() { t.s.settle(t.res, true) }

// Refund implements core.Ticket.
func (t *ticket) Refund() { t.s.settle(t.res, false) }

// settle ends a reservation once: the slot is released, certificate events
// are committed (commit) or returned (refund), and a new-order event that
// is still reserved (OrderCreated never called) is returned either way.
func (s *Scheduler) settle(r *reservation, commit bool) {
	r.pmu.Lock()
	defer r.pmu.Unlock()
	s.mu.Lock()
	if r.settled {
		s.mu.Unlock()
		return
	}
	r.settled = true
	if s.reservations[r.ref] == r {
		delete(s.reservations, r.ref)
	}
	s.releaseSlotLocked(r)
	var commitKinds []core.BudgetKind
	release := false
	kept := r.events[:0]
	for _, e := range r.events {
		if e.committed {
			kept = append(kept, e)
			continue
		}
		if commit && e.kind != core.BudgetNewOrder {
			e.committed = true
			kept = append(kept, e)
			commitKinds = appendUnique(commitKinds, e.kind)
			continue
		}
		s.dropEvent(r.provider, e)
		release = true
	}
	r.events = kept
	s.mu.Unlock()

	ctx := context.Background()
	if len(commitKinds) > 0 {
		if err := s.budgets.Commit(ctx, r.ref, commitKinds...); err != nil {
			s.log.Error("sched: commit certificate budgets", "ref", r.ref, "err", err)
		}
	}
	if release {
		// Release only touches reserved events; whatever was committed
		// above or by OrderCreated stays.
		if err := s.budgets.Release(ctx, r.ref); err != nil {
			s.log.Error("sched: release budget reservation", "ref", r.ref, "err", err)
		}
	}
}

func appendUnique(ks []core.BudgetKind, k core.BudgetKind) []core.BudgetKind {
	for _, x := range ks {
		if x == k {
			return ks
		}
	}
	return append(ks, k)
}
