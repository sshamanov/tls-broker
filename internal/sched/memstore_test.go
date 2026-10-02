package sched_test

import (
	"cmp"
	"context"
	"errors"
	"slices"
	"sync"
	"time"

	"tls-broker/internal/core"
)

// memBudgets is an in-memory core.BudgetStore following the interface
// contract. failReserve makes the next Reserve fail.
type memBudgets struct {
	mu          sync.Mutex
	next        int64
	events      []core.BudgetEvent
	failReserve error
}

var _ core.BudgetStore = (*memBudgets)(nil)

func matchKind(k core.BudgetKind, kinds []core.BudgetKind) bool {
	return len(kinds) == 0 || slices.Contains(kinds, k)
}

func (m *memBudgets) Reserve(ctx context.Context, evs []core.BudgetEvent) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.failReserve; err != nil {
		m.failReserve = nil
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	for i := range evs {
		if evs[i].Ref != evs[0].Ref {
			return errors.New("memBudgets: mixed refs")
		}
	}
	for i := range evs {
		m.next++
		evs[i].ID = m.next
		evs[i].State = core.BudgetReserved
		m.events = append(m.events, evs[i])
	}
	return nil
}

func (m *memBudgets) Commit(_ context.Context, ref string, kinds ...core.BudgetKind) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for i := range m.events {
		e := &m.events[i]
		if e.Ref == ref && e.State == core.BudgetReserved && matchKind(e.Kind, kinds) {
			e.State = core.BudgetCommitted
		}
	}
	return nil
}

func (m *memBudgets) Release(_ context.Context, ref string, kinds ...core.BudgetKind) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.events = slices.DeleteFunc(m.events, func(e core.BudgetEvent) bool {
		return e.Ref == ref && e.State == core.BudgetReserved && matchKind(e.Kind, kinds)
	})
	return nil
}

func (m *memBudgets) ListByRef(_ context.Context, ref string) ([]core.BudgetEvent, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := []core.BudgetEvent{}
	for _, e := range m.events {
		if e.Ref == ref {
			out = append(out, e)
		}
	}
	return out, nil
}

func (m *memBudgets) ListSince(_ context.Context, since time.Time) ([]core.BudgetEvent, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := []core.BudgetEvent{}
	for _, e := range m.events {
		if !e.At.Before(since) {
			out = append(out, e)
		}
	}
	slices.SortFunc(out, func(a, b core.BudgetEvent) int {
		if c := a.At.Compare(b.At); c != 0 {
			return c
		}
		return cmp.Compare(a.ID, b.ID)
	})
	return out, nil
}

func (m *memBudgets) ListReserved(_ context.Context) ([]core.BudgetEvent, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := []core.BudgetEvent{}
	for _, e := range m.events {
		if e.State == core.BudgetReserved {
			out = append(out, e)
		}
	}
	return out, nil
}

func (m *memBudgets) Prune(_ context.Context, before time.Time) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	n := len(m.events)
	m.events = slices.DeleteFunc(m.events, func(e core.BudgetEvent) bool {
		return e.State == core.BudgetCommitted && e.At.Before(before)
	})
	return n - len(m.events), nil
}

// all returns a copy of every stored event.
func (m *memBudgets) all() []core.BudgetEvent {
	m.mu.Lock()
	defer m.mu.Unlock()
	return slices.Clone(m.events)
}

// memStates is an in-memory core.ProviderStateStore.
type memStates struct {
	mu     sync.Mutex
	states map[string]core.ProviderState
}

var _ core.ProviderStateStore = (*memStates)(nil)

func newMemStates() *memStates { return &memStates{states: map[string]core.ProviderState{}} }

func (m *memStates) Get(_ context.Context, name string) (*core.ProviderState, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	s, ok := m.states[name]
	if !ok {
		return nil, core.ErrNotFound
	}
	return &s, nil
}

func (m *memStates) Put(_ context.Context, s *core.ProviderState) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.states[s.Name] = *s
	return nil
}

func (m *memStates) List(_ context.Context) ([]core.ProviderState, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := []core.ProviderState{}
	for _, s := range m.states {
		out = append(out, s)
	}
	slices.SortFunc(out, func(a, b core.ProviderState) int { return cmp.Compare(a.Name, b.Name) })
	return out, nil
}
