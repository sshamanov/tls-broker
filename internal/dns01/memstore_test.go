package dns01

import (
	"context"
	"fmt"
	"slices"
	"sync"
	"time"

	"tls-broker/internal/core"
)

// memStore is an in-memory core.ChallengeStore following the contract in
// core/stores.go (the real one is internal/store). History of state
// transitions is kept per challenge for assertions.
type memStore struct {
	mu      sync.Mutex
	rows    []*core.Challenge // creation order
	history map[string][]core.ChallengeState
}

var _ core.ChallengeStore = (*memStore)(nil)

func newMemStore() *memStore { return &memStore{history: map[string][]core.ChallengeState{}} }

func (s *memStore) find(id string) *core.Challenge {
	for _, c := range s.rows {
		if c.ID == id {
			return c
		}
	}
	return nil
}

func (s *memStore) Create(ctx context.Context, c *core.Challenge) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.find(c.ID) != nil {
		return fmt.Errorf("challenge %s: %w", c.ID, core.ErrConflict)
	}
	cp := *c
	s.rows = append(s.rows, &cp)
	s.history[c.ID] = []core.ChallengeState{c.State}
	return nil
}

func (s *memStore) Get(ctx context.Context, id string) (*core.Challenge, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	c := s.find(id)
	if c == nil {
		return nil, fmt.Errorf("challenge %s: %w", id, core.ErrNotFound)
	}
	cp := *c
	return &cp, nil
}

func (s *memStore) SetState(ctx context.Context, id string, state core.ChallengeState, errText string, now time.Time) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	c := s.find(id)
	if c == nil {
		return fmt.Errorf("challenge %s: %w", id, core.ErrNotFound)
	}
	if c.State.Terminal() {
		return fmt.Errorf("challenge %s is %s: %w", id, c.State, core.ErrConflict)
	}
	c.State, c.Error, c.UpdatedAt = state, errText, now
	s.history[id] = append(s.history[id], state)
	return nil
}

func (s *memStore) list(pred func(*core.Challenge) bool) []core.Challenge {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := []core.Challenge{}
	for _, c := range s.rows {
		if pred(c) {
			out = append(out, *c)
		}
	}
	return out
}

func (s *memStore) FindActive(ctx context.Context, owner, recordName, value string) (*core.Challenge, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	l := s.list(func(c *core.Challenge) bool {
		return !c.State.Terminal() && c.Owner == owner && c.RecordName == recordName && c.Value == value
	})
	if len(l) == 0 {
		return nil, fmt.Errorf("challenge: %w", core.ErrNotFound)
	}
	return &l[0], nil
}

func (s *memStore) ListActive(ctx context.Context) ([]core.Challenge, error) {
	return s.list(func(c *core.Challenge) bool { return !c.State.Terminal() }), ctx.Err()
}

func (s *memStore) ListByRecord(ctx context.Context, zoneID, recordName string) ([]core.Challenge, error) {
	return s.list(func(c *core.Challenge) bool {
		return !c.State.Terminal() && c.ZoneID == zoneID && c.RecordName == recordName
	}), ctx.Err()
}

func (s *memStore) ListByOwner(ctx context.Context, owner string) ([]core.Challenge, error) {
	return s.list(func(c *core.Challenge) bool { return !c.State.Terminal() && c.Owner == owner }), ctx.Err()
}

func (s *memStore) CountCreatedSince(ctx context.Context, owner string, since time.Time) (int, error) {
	return len(s.list(func(c *core.Challenge) bool { return c.Owner == owner && !c.CreatedAt.Before(since) })), ctx.Err()
}

func (s *memStore) ListStale(ctx context.Context, before time.Time) ([]core.Challenge, error) {
	return s.list(func(c *core.Challenge) bool { return !c.State.Terminal() && c.CreatedAt.Before(before) }), ctx.Err()
}

func (s *memStore) Prune(ctx context.Context, before time.Time) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := len(s.rows)
	s.rows = slices.DeleteFunc(s.rows, func(c *core.Challenge) bool { return c.State.Terminal() && c.UpdatedAt.Before(before) })
	return n - len(s.rows), ctx.Err()
}

// all returns every row, oldest first.
func (s *memStore) all() []core.Challenge { return s.list(func(*core.Challenge) bool { return true }) }

// states returns the state history of a challenge.
func (s *memStore) states(id string) []core.ChallengeState {
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Clone(s.history[id])
}
