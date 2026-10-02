package sched

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"tls-broker/internal/core"
)

// ErrClosed is returned by Acquire after Close, and to requests that were
// waiting for a slot when Close was called.
var ErrClosed = errors.New("sched: scheduler closed")

// Defaults used when a SchedulerConfig duration is not set.
const (
	defaultBusyRetryAfter      = 30 * time.Second
	defaultDownRetryAfter      = time.Minute
	defaultDownRetryAfterMax   = 30 * time.Minute
	defaultRateLimitRetryAfter = time.Hour
)

// Options are the dependencies of a Scheduler.
type Options struct {
	Config  core.ConfigSource       // required
	Budgets core.BudgetStore        // required
	States  core.ProviderStateStore // required
	Clock   core.Clock              // nil: core.SystemClock
	// Auditor, when set, receives a provider_state event whenever a
	// provider's admission opens or closes.
	Auditor core.Auditor
	Logger  *slog.Logger // nil: slog.Default()
}

// Scheduler implements core.Scheduler. Create it with New and stop it with
// Close.
type Scheduler struct {
	cfgSrc  core.ConfigSource
	budgets core.BudgetStore
	states  core.ProviderStateStore
	clock   core.Clock
	auditor core.Auditor
	log     *slog.Logger

	// stateMu serializes provider-state changes with their persistence so
	// the store sees them in the order they happened. Taken before mu.
	stateMu sync.Mutex

	mu           sync.Mutex
	cfg          *core.Config         // configuration last applied
	order        []string             // configured provider names, in order
	providers    map[string]*provider // every provider ever seen
	reservations map[string]*reservation
	// horizon: the in-memory events are complete for At >= horizon.
	horizon time.Time
	seq     uint64
	closed  bool

	unsubscribe func()
	stop        chan struct{}
	done        chan struct{}
	closeOnce   sync.Once
}

var _ core.Scheduler = (*Scheduler)(nil)

// provider is the working state of one provider.
type provider struct {
	name       string
	configured bool
	limits     core.ProviderLimits
	state      core.ProviderState
	// probe is the reservation let through after an outage's RetryAfter
	// passed; others are refused until it reports or releases its slot.
	probe   *reservation
	inUse   int
	waiters []*waiter // ordered by class, then arrival
	buckets map[bucketID]*bucket
}

func (p *provider) slots() int { return max(p.limits.Concurrency, 1) }

// reservation is the shared state of one admitted Ref. Tickets are handles
// to it; settlement happens once.
type reservation struct {
	// pmu serializes the in-memory change and the store write of one
	// settlement step, so the store sees the steps of a Ref in order.
	// Taken before Scheduler.mu.
	pmu      sync.Mutex
	ref      string
	provider string
	events   []*event
	slot     bool // holds a concurrency slot
	settled  bool
}

// hasReserved reports whether any event is still reserved (an "open
// reservation" in the sense of Reattach and OpenRefs).
func (r *reservation) hasReserved() bool {
	for _, e := range r.events {
		if !e.committed {
			return true
		}
	}
	return false
}

type waiter struct {
	class core.PriorityClass
	seq   uint64
	res   *reservation
	ch    chan struct{} // closed when done
	done  bool
	err   error // nil: slot granted
}

// New restores the scheduler's state from the stores and starts following
// configuration changes.
func New(ctx context.Context, opts Options) (*Scheduler, error) {
	if opts.Config == nil || opts.Budgets == nil || opts.States == nil {
		return nil, errors.New("sched: Config, Budgets and States are required")
	}
	s := &Scheduler{
		cfgSrc:       opts.Config,
		budgets:      opts.Budgets,
		states:       opts.States,
		clock:        opts.Clock,
		auditor:      opts.Auditor,
		log:          opts.Logger,
		providers:    map[string]*provider{},
		reservations: map[string]*reservation{},
		stop:         make(chan struct{}),
		done:         make(chan struct{}),
	}
	if s.clock == nil {
		s.clock = core.SystemClock{}
	}
	if s.log == nil {
		s.log = slog.Default()
	}

	states, err := s.states.List(ctx)
	if err != nil {
		return nil, fmt.Errorf("sched: load provider states: %w", err)
	}
	for _, st := range states {
		s.provider(st.Name).state = st
	}

	cfg := s.cfgSrc.Current()
	since := s.clock.Now().Add(-retention(cfg))
	recent, err := s.budgets.ListSince(ctx, since)
	if err != nil {
		return nil, fmt.Errorf("sched: load budget events: %w", err)
	}
	reserved, err := s.budgets.ListReserved(ctx)
	if err != nil {
		return nil, fmt.Errorf("sched: load reservations: %w", err)
	}
	seen := map[int64]bool{}
	for _, ev := range slices.Concat(recent, reserved) {
		if seen[ev.ID] {
			continue
		}
		seen[ev.ID] = true
		e := s.addEvent(ev.Provider, bucketID{ev.Kind, ev.Key}, ev.At, ev.Ref, ev.Renewal, ev.State == core.BudgetCommitted)
		if e.committed {
			continue
		}
		r := s.reservations[ev.Ref]
		if r == nil {
			r = &reservation{ref: ev.Ref, provider: ev.Provider}
			s.reservations[ev.Ref] = r
		}
		r.events = append(r.events, e)
	}
	s.horizon = since

	changed, unsubscribe := s.cfgSrc.Subscribe()
	s.unsubscribe = unsubscribe
	s.mu.Lock()
	s.refreshLocked()
	s.mu.Unlock()
	go s.follow(changed)
	return s, nil
}

// Close stops following the configuration and fails every waiting request
// with ErrClosed. Tickets already handed out keep working. Idempotent.
func (s *Scheduler) Close() error {
	s.closeOnce.Do(func() {
		s.mu.Lock()
		s.closed = true
		for _, p := range s.providers {
			s.failWaitersLocked(p, ErrClosed)
		}
		s.mu.Unlock()
		close(s.stop)
		<-s.done
		s.unsubscribe()
	})
	return nil
}

func (s *Scheduler) follow(changed <-chan struct{}) {
	defer close(s.done)
	for {
		select {
		case <-s.stop:
			return
		case <-changed:
			s.mu.Lock()
			s.refreshLocked()
			s.mu.Unlock()
		}
	}
}

// provider returns the working state for name, creating it. Caller holds mu
// (or is New before the scheduler is shared).
func (s *Scheduler) provider(name string) *provider {
	p := s.providers[name]
	if p == nil {
		p = &provider{name: name, buckets: map[bucketID]*bucket{}, state: core.ProviderState{Name: name, Health: core.ProviderHealthy}}
		s.providers[name] = p
	}
	return p
}

func (s *Scheduler) addEvent(prov string, id bucketID, at time.Time, ref string, renewal, committed bool) *event {
	p := s.provider(prov)
	b := p.buckets[id]
	if b == nil {
		b = &bucket{id: id}
		p.buckets[id] = b
	}
	e := &event{kind: id.kind, at: at, ref: ref, renewal: renewal, committed: committed}
	b.insert(e)
	return e
}

func (s *Scheduler) dropEvent(prov string, e *event) {
	b := e.bucket
	if b == nil {
		return
	}
	b.remove(e)
	if len(b.events) == 0 {
		delete(s.provider(prov).buckets, b.id)
	}
}

// refreshLocked applies the current configuration if it changed: provider
// limits and slot counts, and a longer retention window (loading older
// events from the store when needed).
func (s *Scheduler) refreshLocked() {
	cur := s.cfgSrc.Current()
	if cur == s.cfg {
		return
	}
	s.cfg = cur
	s.order = s.order[:0]
	configured := map[string]bool{}
	for _, pc := range cur.Providers {
		p := s.provider(pc.Name)
		p.configured, p.limits = true, pc.Limits
		configured[pc.Name] = true
		s.order = append(s.order, pc.Name)
	}
	for name, p := range s.providers {
		if !configured[name] {
			p.configured = false
			s.failWaitersLocked(p, &core.AdmissionError{
				Kind: core.AdmissionProviderDown, Provider: name,
				RetryAfter: s.busyRetryAfter(), Reason: "provider removed from configuration",
			})
		}
	}
	now := s.clock.Now()
	if cutoff := now.Add(-retention(cur)); cutoff.Before(s.horizon) {
		if evs, err := s.budgets.ListSince(context.Background(), cutoff); err != nil {
			s.log.Error("sched: load budget events for a longer window", "err", err)
		} else {
			for _, ev := range evs {
				if ev.State == core.BudgetCommitted && ev.At.Before(s.horizon) {
					s.addEvent(ev.Provider, bucketID{ev.Kind, ev.Key}, ev.At, ev.Ref, ev.Renewal, true)
				}
			}
			s.horizon = cutoff
		}
	}
	for _, name := range s.order {
		s.dispatchLocked(s.providers[name])
	}
}

func (s *Scheduler) busyRetryAfter() time.Duration {
	if d := s.cfg.Scheduler.BusyRetryAfter; d > 0 {
		return d
	}
	return defaultBusyRetryAfter
}

// Acquire implements core.Scheduler.
func (s *Scheduler) Acquire(ctx context.Context, req core.AdmissionRequest) (core.Ticket, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if req.Ref == "" {
		return nil, errors.New("sched: admission request without Ref")
	}
	if !req.Class.Valid() {
		return nil, fmt.Errorf("sched: invalid priority class %d", req.Class)
	}
	if req.Names.IsZero() {
		return nil, errors.New("sched: admission request without names")
	}
	var domains []string
	if !req.ARIQualified {
		var err error
		if domains, err = req.Names.RegisteredDomains(); err != nil {
			return nil, fmt.Errorf("sched: %w", err)
		}
	}

	s.mu.Lock()
	s.refreshLocked()
	if s.closed {
		s.mu.Unlock()
		return nil, ErrClosed
	}
	p := s.providers[req.Provider]
	if p == nil || !p.configured {
		s.mu.Unlock()
		return nil, fmt.Errorf("sched: unknown provider %q", req.Provider)
	}
	if _, ok := s.reservations[req.Ref]; ok {
		s.mu.Unlock()
		return nil, fmt.Errorf("sched: reservation %q already open: %w", req.Ref, core.ErrConflict)
	}
	now := s.clock.Now()
	if aerr := s.circuitLocked(p, now); aerr != nil {
		s.mu.Unlock()
		return nil, aerr
	}

	// Budgets this request touches.
	var ids []bucketID
	if !req.ARIQualified {
		if !req.ReuseUpstreamOrder {
			ids = append(ids, bucketID{core.BudgetNewOrder, ""})
		}
		for _, d := range domains {
			ids = append(ids, bucketID{core.BudgetCertDomain, d})
		}
		ids = append(ids, bucketID{core.BudgetCertSet, req.Names.Key()})
	}
	var worst *refusal
	for _, id := range ids {
		r := check(p.buckets[id], id, limitFor(p.limits, id.kind), p.limits.RenewalReservePercent, req.Renewal, now)
		if r != nil && (worst == nil || r.retryAfter > worst.retryAfter) {
			worst = r
		}
	}
	if worst != nil {
		s.mu.Unlock()
		return nil, &core.AdmissionError{Kind: core.AdmissionRateLimited, Provider: p.name, RetryAfter: worst.retryAfter, Reason: worst.reason}
	}

	res := &reservation{ref: req.Ref, provider: p.name}
	stored := make([]core.BudgetEvent, 0, len(ids))
	for _, id := range ids {
		res.events = append(res.events, s.addEvent(p.name, id, now, req.Ref, req.Renewal, false))
		stored = append(stored, core.BudgetEvent{
			Ref: req.Ref, Provider: p.name, Kind: id.kind, Key: id.key,
			At: now, State: core.BudgetReserved, Renewal: req.Renewal,
		})
	}
	s.reservations[req.Ref] = res
	if p.state.Health == core.ProviderUnavailable {
		p.probe = res // first request after an outage's RetryAfter
	}
	res.pmu.Lock() // fresh: nobody else can hold it
	s.mu.Unlock()

	if len(stored) > 0 {
		if err := s.budgets.Reserve(ctx, stored); err != nil {
			s.mu.Lock()
			s.discardLocked(res)
			s.mu.Unlock()
			res.pmu.Unlock()
			return nil, fmt.Errorf("sched: reserve budget: %w", err)
		}
	}
	res.pmu.Unlock()

	if err := s.waitSlot(ctx, p, req, res); err != nil {
		s.settle(res, false)
		return nil, err
	}
	return &ticket{s: s, res: res, holdsSlot: true}, nil
}

// circuitLocked returns the refusal for a provider whose admission is
// closed at now.
func (s *Scheduler) circuitLocked(p *provider, now time.Time) *core.AdmissionError {
	st := p.state
	if !st.OpenAt(now) {
		kind := core.AdmissionProviderDown
		reason := "provider is down"
		if st.Health == core.ProviderLimited {
			kind, reason = core.AdmissionRateLimited, "provider asked to back off"
		}
		return &core.AdmissionError{Kind: kind, Provider: p.name, RetryAfter: st.RetryAfter.Sub(now), Reason: reason}
	}
	if st.Health == core.ProviderUnavailable && p.probe != nil {
		return &core.AdmissionError{Kind: core.AdmissionProviderDown, Provider: p.name, RetryAfter: s.busyRetryAfter(),
			Reason: "provider is recovering from an outage; a probe request is in flight"}
	}
	return nil
}

// discardLocked forgets a reservation whose persistence failed.
func (s *Scheduler) discardLocked(res *reservation) {
	for _, e := range res.events {
		s.dropEvent(res.provider, e)
	}
	res.events = nil
	res.settled = true
	if s.reservations[res.ref] == res {
		delete(s.reservations, res.ref)
	}
	if p := s.providers[res.provider]; p != nil && p.probe == res {
		p.probe = nil
	}
}

// waitSlot obtains a concurrency slot for res, waiting by class then
// arrival for at most the request's MaxWait.
func (s *Scheduler) waitSlot(ctx context.Context, p *provider, req core.AdmissionRequest, res *reservation) error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return ErrClosed
	}
	if len(p.waiters) == 0 && p.inUse < p.slots() {
		p.inUse++
		res.slot = true
		s.mu.Unlock()
		return nil
	}
	wait := req.MaxWait
	if wait == 0 {
		wait = s.cfg.Scheduler.AdmitWait
	}
	busy := &core.AdmissionError{Kind: core.AdmissionBusy, Provider: p.name, RetryAfter: s.busyRetryAfter(),
		Reason: "no upstream concurrency slot became free"}
	if wait <= 0 {
		s.mu.Unlock()
		return busy
	}
	s.seq++
	w := &waiter{class: req.Class, seq: s.seq, res: res, ch: make(chan struct{})}
	i := sort.Search(len(p.waiters), func(i int) bool {
		o := p.waiters[i]
		return o.class > w.class || (o.class == w.class && o.seq > w.seq)
	})
	p.waiters = slices.Insert(p.waiters, i, w)
	s.mu.Unlock()

	timeout := s.clock.After(wait)
	cancelled := false
	select {
	case <-w.ch:
	case <-timeout:
	case <-ctx.Done():
		cancelled = true
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if !w.done {
		w.done = true
		if i := slices.Index(p.waiters, w); i >= 0 {
			p.waiters = slices.Delete(p.waiters, i, i+1)
		}
		if cancelled {
			return ctx.Err()
		}
		return busy
	}
	if w.err != nil {
		return w.err
	}
	if cancelled {
		// Granted just as ctx ended: give the slot back.
		s.releaseSlotLocked(res)
		return ctx.Err()
	}
	return nil
}

// dispatchLocked hands free slots to waiters, best class first. Nothing is
// admitted while the provider's admission is closed.
func (s *Scheduler) dispatchLocked(p *provider) {
	if len(p.waiters) == 0 {
		return
	}
	now := s.clock.Now()
	if !p.state.OpenAt(now) {
		s.failWaitersLocked(p, s.circuitLocked(p, now))
		return
	}
	for len(p.waiters) > 0 && p.inUse < p.slots() {
		w := p.waiters[0]
		p.waiters = p.waiters[1:]
		p.inUse++
		w.res.slot = true
		w.done = true
		close(w.ch)
	}
}

func (s *Scheduler) failWaitersLocked(p *provider, err error) {
	for _, w := range p.waiters {
		w.done, w.err = true, err
		close(w.ch)
	}
	p.waiters = nil
}

// releaseSlotLocked returns res's slot, if it holds one, and lets the next
// waiter in.
func (s *Scheduler) releaseSlotLocked(res *reservation) {
	p := s.providers[res.provider]
	if p.probe == res {
		p.probe = nil
	}
	if !res.slot {
		return
	}
	res.slot = false
	p.inUse--
	s.dispatchLocked(p)
}

// Reattach implements core.Scheduler.
func (s *Scheduler) Reattach(ctx context.Context, ref string) (core.Ticket, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	res := s.reservations[ref]
	if res == nil || !res.hasReserved() {
		return nil, fmt.Errorf("sched: reservation %q: %w", ref, core.ErrNotFound)
	}
	return &ticket{s: s, res: res}, nil
}

// OpenRefs implements core.Scheduler. The Refs are sorted.
func (s *Scheduler) OpenRefs(ctx context.Context) ([]string, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	out := []string{}
	for ref, res := range s.reservations {
		if res.hasReserved() {
			out = append(out, ref)
		}
	}
	slices.Sort(out)
	return out, nil
}

// Prune drops committed budget events that have left every window, from
// memory and from the store, and returns how many the store deleted. The
// application calls it from its periodic housekeeping.
func (s *Scheduler) Prune(ctx context.Context) (int, error) {
	s.mu.Lock()
	s.refreshLocked()
	cutoff := s.clock.Now().Add(-retention(s.cfg))
	for _, p := range s.providers {
		for id, b := range p.buckets {
			b.compact(cutoff)
			if len(b.events) == 0 {
				delete(p.buckets, id)
			}
		}
	}
	if cutoff.After(s.horizon) {
		s.horizon = cutoff
	}
	s.mu.Unlock()
	return s.budgets.Prune(ctx, cutoff)
}

// Snapshot implements core.Scheduler. It reflects the configuration last
// applied (a reload is applied by the next Acquire, ReportProvider or the
// background follower, whichever comes first); it does no I/O.
func (s *Scheduler) Snapshot() core.SchedulerSnapshot {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.clock.Now()
	snap := core.SchedulerSnapshot{At: now}
	for _, name := range s.order {
		p := s.providers[name]
		ps := core.ProviderSnapshot{
			Name: name, State: p.state, Open: p.state.OpenAt(now),
			SlotsInUse: p.inUse, SlotsTotal: p.slots(), Waiting: len(p.waiters),
		}
		for _, res := range s.reservations {
			if res.provider == name && res.hasReserved() {
				ps.Reserved++
			}
		}
		usage := func(id bucketID) core.BudgetUsage {
			l := limitFor(p.limits, id.kind)
			u := core.BudgetUsage{Kind: id.kind, Key: id.key, Used: p.buckets[id].used(l.Window, now), Limit: l.Count, Window: l.Window}
			if enforced(l) {
				u.RenewalOnly = l.Count - threshold(l, p.limits.RenewalReservePercent, false)
			}
			return u
		}
		ps.Budgets = append(ps.Budgets, usage(bucketID{core.BudgetNewOrder, ""}))
		var rest []core.BudgetUsage
		for id := range p.buckets {
			if id.kind == core.BudgetNewOrder {
				continue
			}
			if u := usage(id); u.Used > 0 {
				rest = append(rest, u)
			}
		}
		slices.SortFunc(rest, func(a, b core.BudgetUsage) int {
			if c := strings.Compare(string(a.Kind), string(b.Kind)); c != 0 {
				return c
			}
			return strings.Compare(a.Key, b.Key)
		})
		ps.Budgets = append(ps.Budgets, rest...)
		snap.Providers = append(snap.Providers, ps)
	}
	return snap
}
