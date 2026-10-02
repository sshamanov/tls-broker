package coretest

import (
	"context"
	"fmt"
	"slices"
	"sync"

	"tls-broker/internal/core"
	"tls-broker/internal/names"
)

// FakeDNSEngine is a core.DNSEngine that keeps challenges in memory and
// honours the port's contract: idempotent Present per (owner, record, value),
// coexisting values per record, idempotent Cleanup that removes only its own
// value.
//
// When built with a FakeResolver, presented values appear in (and cleaned
// values disappear from) that resolver's TXT table, so a FakeCA whose TXT
// lookup is the same resolver validates exactly what was presented.
type FakeDNSEngine struct {
	mu        sync.Mutex
	resolver  *FakeResolver
	clock     core.Clock
	zones     *names.Zones
	list      []*core.Challenge
	presentFn func(ctx context.Context, owner, record, value string) error
	cleanupFn func(ctx context.Context, ch core.Challenge) error

	presentCalls, cleanupCalls, reconcileCalls int
}

var _ core.DNSEngine = (*FakeDNSEngine)(nil)

// NewFakeDNSEngine returns an engine. resolver may be nil (values are then
// only recorded). Timestamps come from clock; nil uses the system clock.
func NewFakeDNSEngine(resolver *FakeResolver, clock core.Clock) *FakeDNSEngine {
	if clock == nil {
		clock = core.SystemClock{}
	}
	return &FakeDNSEngine{resolver: resolver, clock: clock}
}

// SetZones restricts Present to records inside the given managed zones;
// others get core.ErrOutsideManagedZones. Without it every record is
// accepted.
func (e *FakeDNSEngine) SetZones(z names.Zones) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.zones = &z
}

// OnPresent installs a hook that runs at the start of every Present, before
// anything is recorded. A non-nil error is returned by Present and nothing is
// created; the hook may also block (for example on a FakeClock or a channel)
// to simulate slow propagation. nil removes the hook.
func (e *FakeDNSEngine) OnPresent(f func(ctx context.Context, owner, record, value string) error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.presentFn = f
}

// OnCleanup installs a hook that runs at the start of every Cleanup of an
// active challenge. A non-nil error is returned and the value stays.
func (e *FakeDNSEngine) OnCleanup(f func(ctx context.Context, ch core.Challenge) error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.cleanupFn = f
}

// Present implements core.DNSEngine.
func (e *FakeDNSEngine) Present(ctx context.Context, owner, record, value string) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	e.mu.Lock()
	e.presentCalls++
	hook, zones := e.presentFn, e.zones
	e.mu.Unlock()

	if zones != nil {
		id, ok := names.IdentifierFromChallengeRecord(record)
		if !ok {
			id = record
		}
		if !zones.Contains(id) {
			return "", fmt.Errorf("%w: %s", core.ErrOutsideManagedZones, record)
		}
	}
	if hook != nil {
		if err := hook(ctx, owner, record, value); err != nil {
			return "", err
		}
	}

	e.mu.Lock()
	defer e.mu.Unlock()
	for _, c := range e.list {
		if !c.State.Terminal() && c.Owner == owner && c.RecordName == record && c.Value == value {
			return c.ID, nil
		}
	}
	now := e.clock.Now()
	c := &core.Challenge{ID: core.NewID(), ZoneID: "FAKEZONE", RecordName: record, Value: value, Owner: owner,
		State: core.ChallengeReady, CreatedAt: now, UpdatedAt: now}
	e.list = append(e.list, c)
	if e.resolver != nil {
		e.resolver.AddTXT(record, value)
	}
	return c.ID, nil
}

// Cleanup implements core.DNSEngine.
func (e *FakeDNSEngine) Cleanup(ctx context.Context, challengeID string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	e.mu.Lock()
	e.cleanupCalls++
	var c *core.Challenge
	for _, cand := range e.list {
		if cand.ID == challengeID {
			c = cand
		}
	}
	if c == nil {
		e.mu.Unlock()
		return fmt.Errorf("challenge %s: %w", challengeID, core.ErrNotFound)
	}
	if c.State.Terminal() {
		e.mu.Unlock()
		return nil
	}
	hook, snapshot := e.cleanupFn, *c
	e.mu.Unlock()

	if hook != nil {
		if err := hook(ctx, snapshot); err != nil {
			return err
		}
	}

	e.mu.Lock()
	defer e.mu.Unlock()
	if c.State.Terminal() {
		return nil
	}
	c.State = core.ChallengeDone
	c.UpdatedAt = e.clock.Now()
	// Remove the value from DNS only if no other active challenge wants it.
	stillWanted := false
	for _, other := range e.list {
		if other != c && other.State.WantsRecord() && other.RecordName == c.RecordName && other.Value == c.Value {
			stillWanted = true
		}
	}
	if e.resolver != nil && !stillWanted {
		e.resolver.RemoveTXT(c.RecordName, c.Value)
	}
	return nil
}

// CleanupOwner implements core.DNSEngine.
func (e *FakeDNSEngine) CleanupOwner(ctx context.Context, owner string) error {
	e.mu.Lock()
	var ids []string
	for _, c := range e.list {
		if c.Owner == owner && !c.State.Terminal() {
			ids = append(ids, c.ID)
		}
	}
	e.mu.Unlock()
	var first error
	for _, id := range ids {
		if err := e.Cleanup(ctx, id); err != nil && first == nil {
			first = err
		}
	}
	return first
}

// Reconcile implements core.DNSEngine; the fake has nothing to repair and
// only counts the call.
func (e *FakeDNSEngine) Reconcile(ctx context.Context) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.reconcileCalls++
	return ctx.Err()
}

// Challenges returns a copy of every challenge ever created, oldest first.
func (e *FakeDNSEngine) Challenges() []core.Challenge {
	e.mu.Lock()
	defer e.mu.Unlock()
	out := make([]core.Challenge, 0, len(e.list))
	for _, c := range e.list {
		out = append(out, *c)
	}
	return out
}

// Active returns the values currently published at a record name, sorted.
func (e *FakeDNSEngine) Active(record string) []string {
	e.mu.Lock()
	defer e.mu.Unlock()
	var out []string
	for _, c := range e.list {
		if c.RecordName == record && c.State.WantsRecord() && !slices.Contains(out, c.Value) {
			out = append(out, c.Value)
		}
	}
	slices.Sort(out)
	return out
}

// ActiveCount returns the number of non-terminal challenges.
func (e *FakeDNSEngine) ActiveCount() int {
	e.mu.Lock()
	defer e.mu.Unlock()
	n := 0
	for _, c := range e.list {
		if !c.State.Terminal() {
			n++
		}
	}
	return n
}

// Calls returns how often Present, Cleanup and Reconcile were called.
func (e *FakeDNSEngine) Calls() (present, cleanup, reconcile int) {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.presentCalls, e.cleanupCalls, e.reconcileCalls
}
