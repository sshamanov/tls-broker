package coretest

import (
	"context"
	"fmt"
	"net/netip"
	"slices"
	"sort"
	"sync"
	"time"

	"tls-broker/internal/core"
	"tls-broker/internal/names"
)

// ---- FakeDirectory --------------------------------------------------------

// FakeDirectory is a core.Directory with a username/password table.
type FakeDirectory struct {
	mu    sync.Mutex
	users map[string]string
	down  error
	calls int
}

var _ core.Directory = (*FakeDirectory)(nil)

// NewFakeDirectory returns an empty, reachable directory.
func NewFakeDirectory() *FakeDirectory { return &FakeDirectory{users: map[string]string{}} }

// SetUser adds a user or changes the password.
func (d *FakeDirectory) SetUser(username, password string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.users[username] = password
}

// RemoveUser deletes a user (as if removed from LDAP or the filter).
func (d *FakeDirectory) RemoveUser(username string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	delete(d.users, username)
}

// SetDown makes the directory unavailable: Authenticate returns an error
// matching core.ErrDirectoryUnavailable. false restores it.
func (d *FakeDirectory) SetDown(down bool) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.down = nil
	if down {
		d.down = fmt.Errorf("%w: fake directory is down", core.ErrDirectoryUnavailable)
	}
}

// Calls returns how many times Authenticate was called.
func (d *FakeDirectory) Calls() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.calls
}

// Authenticate implements core.Directory. Usernames are matched exactly; an
// empty password never authenticates.
func (d *FakeDirectory) Authenticate(ctx context.Context, username, password string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	d.calls++
	if d.down != nil {
		return d.down
	}
	want, ok := d.users[username]
	if !ok || password == "" || want != password {
		return core.ErrInvalidCredentials
	}
	return nil
}

// ---- FakeAuditor ----------------------------------------------------------

// FakeAuditor is a core.Auditor that keeps events in memory.
type FakeAuditor struct {
	mu     sync.Mutex
	clock  core.Clock
	events []core.AuditEvent
}

var _ core.Auditor = (*FakeAuditor)(nil)

// NewFakeAuditor returns an auditor; clock (nil: system clock) fills in
// event times that are zero.
func NewFakeAuditor(clock core.Clock) *FakeAuditor {
	if clock == nil {
		clock = core.SystemClock{}
	}
	return &FakeAuditor{clock: clock}
}

// Record implements core.Auditor.
func (a *FakeAuditor) Record(_ context.Context, ev core.AuditEvent) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if ev.Time.IsZero() {
		ev.Time = a.clock.Now()
	}
	ev.Names = slices.Clone(ev.Names)
	a.events = append(a.events, ev)
}

// Events returns a copy of all recorded events, oldest first.
func (a *FakeAuditor) Events() []core.AuditEvent {
	a.mu.Lock()
	defer a.mu.Unlock()
	return slices.Clone(a.events)
}

// OfType returns the recorded events of one type, oldest first.
func (a *FakeAuditor) OfType(typ string) []core.AuditEvent {
	var out []core.AuditEvent
	for _, ev := range a.Events() {
		if ev.Type == typ {
			out = append(out, ev)
		}
	}
	return out
}

// Reset forgets all events.
func (a *FakeAuditor) Reset() {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.events = nil
}

// ---- FakeGate -------------------------------------------------------------

// GateCall is one recorded FakeGate.Authorize call.
type GateCall struct {
	Mode   core.Mode
	Source netip.Addr
	Names  names.Set
}

// FakeGate is a core.Gate with scripted answers. By default it allows
// everything with reason dns_ip_match.
type FakeGate struct {
	mu    sync.Mutex
	fn    func(mode core.Mode, src netip.Addr, set names.Set) (core.Decision, error)
	calls []GateCall
}

var _ core.Gate = (*FakeGate)(nil)

// NewFakeGate returns a gate that allows everything.
func NewFakeGate() *FakeGate { return &FakeGate{} }

// Decide sets a fixed answer for every request.
func (g *FakeGate) Decide(d core.Decision) {
	g.DecideFunc(func(core.Mode, netip.Addr, names.Set) (core.Decision, error) { return d, nil })
}

// DecideFunc sets the function that answers requests; nil restores
// allow-everything.
func (g *FakeGate) DecideFunc(f func(mode core.Mode, src netip.Addr, set names.Set) (core.Decision, error)) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.fn = f
}

// Calls returns the recorded calls, oldest first.
func (g *FakeGate) Calls() []GateCall {
	g.mu.Lock()
	defer g.mu.Unlock()
	return slices.Clone(g.calls)
}

// Authorize implements core.Gate.
func (g *FakeGate) Authorize(ctx context.Context, mode core.Mode, src netip.Addr, set names.Set) (core.Decision, error) {
	if err := ctx.Err(); err != nil {
		return core.Decision{}, err
	}
	g.mu.Lock()
	g.calls = append(g.calls, GateCall{Mode: mode, Source: src, Names: set})
	fn := g.fn
	g.mu.Unlock()
	if fn == nil {
		return core.Decision{Allowed: true, Reason: core.ReasonDNSIPMatch}, nil
	}
	return fn(mode, src, set)
}

// ---- FakeScheduler --------------------------------------------------------

// TicketRecord is what happened to one admitted request of a FakeScheduler.
type TicketRecord struct {
	Request      core.AdmissionRequest
	OrderCreated bool
	PrepDone     bool
	Committed    bool
	Refunded     bool
}

// Settled reports whether the reservation was committed or refunded.
func (r TicketRecord) Settled() bool { return r.Committed || r.Refunded }

// ProviderReport is one recorded FakeScheduler.ReportProvider call.
type ProviderReport struct {
	Provider string
	Err      error
}

// FakeScheduler is a core.Scheduler with unlimited slots and budgets: it
// admits every request at once unless a refusal is configured, and records
// what callers do with their tickets. It follows the port's rules for Ref
// uniqueness, Reattach, OpenRefs and first-settlement-wins.
type FakeScheduler struct {
	mu       sync.Mutex
	refuse   map[string]error // provider ("" = all) -> error
	records  map[string]*TicketRecord
	order    []string
	reports  []ProviderReport
	snapshot core.SchedulerSnapshot
}

var _ core.Scheduler = (*FakeScheduler)(nil)

// NewFakeScheduler returns a scheduler that admits everything.
func NewFakeScheduler() *FakeScheduler {
	return &FakeScheduler{refuse: map[string]error{}, records: map[string]*TicketRecord{}}
}

// Refuse makes Acquire for the provider ("" for every provider) return err,
// normally a *core.AdmissionError. A nil err admits again.
func (s *FakeScheduler) Refuse(provider string, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err == nil {
		delete(s.refuse, provider)
		return
	}
	s.refuse[provider] = err
}

// SetSnapshot sets what Snapshot returns.
func (s *FakeScheduler) SetSnapshot(snap core.SchedulerSnapshot) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.snapshot = snap
}

// Acquire implements core.Scheduler.
func (s *FakeScheduler) Acquire(ctx context.Context, req core.AdmissionRequest) (core.Ticket, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.refuse[req.Provider]; err != nil {
		return nil, err
	}
	if err := s.refuse[""]; err != nil {
		return nil, err
	}
	if r, ok := s.records[req.Ref]; ok && !r.Settled() {
		return nil, fmt.Errorf("reservation %q already open: %w", req.Ref, core.ErrConflict)
	}
	if _, ok := s.records[req.Ref]; !ok {
		s.order = append(s.order, req.Ref)
	}
	s.records[req.Ref] = &TicketRecord{Request: req}
	return &fakeTicket{s: s, ref: req.Ref}, nil
}

// Reattach implements core.Scheduler.
func (s *FakeScheduler) Reattach(ctx context.Context, ref string) (core.Ticket, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if r, ok := s.records[ref]; !ok || r.Settled() {
		return nil, fmt.Errorf("reservation %q: %w", ref, core.ErrNotFound)
	}
	return &fakeTicket{s: s, ref: ref}, nil
}

// OpenRefs implements core.Scheduler.
func (s *FakeScheduler) OpenRefs(ctx context.Context) ([]string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []string
	for _, ref := range s.order {
		if !s.records[ref].Settled() {
			out = append(out, ref)
		}
	}
	return out, ctx.Err()
}

// ReportProvider implements core.Scheduler; reports are only recorded.
func (s *FakeScheduler) ReportProvider(_ context.Context, provider string, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.reports = append(s.reports, ProviderReport{Provider: provider, Err: err})
}

// Snapshot implements core.Scheduler.
func (s *FakeScheduler) Snapshot() core.SchedulerSnapshot {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.snapshot
}

// Record returns what happened to the reservation with that Ref.
func (s *FakeScheduler) Record(ref string) (TicketRecord, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.records[ref]
	if !ok {
		return TicketRecord{}, false
	}
	return *r, true
}

// Records returns all reservations in admission order.
func (s *FakeScheduler) Records() []TicketRecord {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]TicketRecord, 0, len(s.order))
	for _, ref := range s.order {
		out = append(out, *s.records[ref])
	}
	return out
}

// Reports returns the recorded ReportProvider calls, oldest first.
func (s *FakeScheduler) Reports() []ProviderReport {
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Clone(s.reports)
}

type fakeTicket struct {
	s   *FakeScheduler
	ref string
}

func (t *fakeTicket) update(f func(r *TicketRecord)) {
	t.s.mu.Lock()
	defer t.s.mu.Unlock()
	if r, ok := t.s.records[t.ref]; ok {
		f(r)
	}
}

func (t *fakeTicket) Ref() string { return t.ref }

func (t *fakeTicket) OrderCreated() {
	t.update(func(r *TicketRecord) {
		if !r.Settled() {
			r.OrderCreated = true
		}
	})
}

func (t *fakeTicket) PrepDone() { t.update(func(r *TicketRecord) { r.PrepDone = true }) }

func (t *fakeTicket) Commit() {
	t.update(func(r *TicketRecord) {
		if !r.Settled() {
			r.Committed, r.PrepDone = true, true
		}
	})
}

func (t *fakeTicket) Refund() {
	t.update(func(r *TicketRecord) {
		if !r.Settled() {
			r.Refunded, r.PrepDone = true, true
		}
	})
}

// ---- FakeProviders --------------------------------------------------------

// FakeProviders is a core.Providers over a fixed, ordered list.
type FakeProviders struct {
	mu       sync.Mutex
	list     []core.Provider
	disabled map[string]bool
}

var _ core.Providers = (*FakeProviders)(nil)

// NewFakeProviders returns a registry; the first provider is the primary.
func NewFakeProviders(providers ...core.Provider) *FakeProviders {
	return &FakeProviders{list: providers, disabled: map[string]bool{}}
}

// SetDisabled marks a provider as disabled in configuration: Get still
// returns it, Enabled does not.
func (p *FakeProviders) SetDisabled(name string, disabled bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.disabled[name] = disabled
}

// Get implements core.Providers.
func (p *FakeProviders) Get(name string) (core.Provider, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, pr := range p.list {
		if pr.Name() == name {
			return pr, true
		}
	}
	return nil, false
}

// Enabled implements core.Providers.
func (p *FakeProviders) Enabled() []core.Provider {
	p.mu.Lock()
	defer p.mu.Unlock()
	var out []core.Provider
	for _, pr := range p.list {
		if !p.disabled[pr.Name()] {
			out = append(out, pr)
		}
	}
	return out
}

// ---- FakeConfig -----------------------------------------------------------

// FakeConfig is a core.ConfigSource whose configuration the test sets.
type FakeConfig struct {
	mu   sync.Mutex
	cfg  *core.Config
	subs map[int]chan struct{}
	next int
}

var _ core.ConfigSource = (*FakeConfig)(nil)

// NewFakeConfig returns a source holding cfg; nil uses NewConfig().
func NewFakeConfig(cfg *core.Config) *FakeConfig {
	if cfg == nil {
		cfg = NewConfig()
	}
	return &FakeConfig{cfg: cfg, subs: map[int]chan struct{}{}}
}

// NewConfig returns core.DefaultConfig() with a test fixture filled in: zones
// example.com (Z1EXAMPLE) and example.org (Z2EXAMPLE), providers "primary"
// and "fallback" (matching NewFakeCA("primary"/"fallback") capabilities,
// fallback without ARI exemption), 127.0.0.0/8 as trusted proxy.
func NewConfig() *core.Config {
	c := core.DefaultConfig()
	c.Server.ExternalURL = "https://broker.test"
	c.Server.TrustedProxies = []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")}
	c.Zones = []core.ZoneConfig{{Name: "example.com", HostedZoneID: "Z1EXAMPLE"}, {Name: "example.org", HostedZoneID: "Z2EXAMPLE"}}
	c.Providers = []core.ProviderConfig{
		{Name: "primary", DirectoryURL: "https://primary.test/directory", CAAIssuers: []string{"primary.test"},
			AccountURIHonoured: true, ARI: true, ARIExempt: true, Limits: core.DefaultProviderLimits()},
		{Name: "fallback", DirectoryURL: "https://fallback.test/directory", CAAIssuers: []string{"fallback.test"},
			AccountURIHonoured: true, ARI: true, ARIExempt: false, Limits: core.DefaultProviderLimits()},
	}
	return c
}

// Current implements core.ConfigSource.
func (f *FakeConfig) Current() *core.Config {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.cfg
}

// Set replaces the configuration and notifies subscribers.
func (f *FakeConfig) Set(cfg *core.Config) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.cfg = cfg
	for _, ch := range f.subs {
		select {
		case ch <- struct{}{}:
		default:
		}
	}
}

// Update applies fn to a shallow copy of the current configuration and
// publishes the copy. fn must replace, not modify, slices it changes.
func (f *FakeConfig) Update(fn func(c *core.Config)) {
	cur := *f.Current()
	fn(&cur)
	f.Set(&cur)
}

// Subscribe implements core.ConfigSource.
func (f *FakeConfig) Subscribe() (<-chan struct{}, func()) {
	f.mu.Lock()
	defer f.mu.Unlock()
	id := f.next
	f.next++
	ch := make(chan struct{}, 1)
	f.subs[id] = ch
	var once sync.Once
	return ch, func() {
		once.Do(func() {
			f.mu.Lock()
			defer f.mu.Unlock()
			delete(f.subs, id)
			close(ch)
		})
	}
}

// ---- FakeSecrets ----------------------------------------------------------

// FakeSecrets is an in-memory core.SecretStore.
type FakeSecrets struct {
	mu sync.Mutex
	m  map[string][]byte
}

var _ core.SecretStore = (*FakeSecrets)(nil)

// NewFakeSecrets returns an empty secret store.
func NewFakeSecrets() *FakeSecrets { return &FakeSecrets{m: map[string][]byte{}} }

// Get implements core.SecretStore.
func (s *FakeSecrets) Get(_ context.Context, name string) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	v, ok := s.m[name]
	if !ok {
		return nil, fmt.Errorf("secret %q: %w", name, core.ErrNotFound)
	}
	return slices.Clone(v), nil
}

// Put implements core.SecretStore.
func (s *FakeSecrets) Put(_ context.Context, name string, value []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.m[name] = slices.Clone(value)
	return nil
}

// Delete implements core.SecretStore.
func (s *FakeSecrets) Delete(_ context.Context, name string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.m, name)
	return nil
}

// List implements core.SecretStore.
func (s *FakeSecrets) List(_ context.Context) ([]string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]string, 0, len(s.m))
	for k := range s.m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out, nil
}

// At is a shorthand for a UTC time in tests: At(2026, 3, 1) or
// At(2026, 3, 1, 14, 30).
func At(year int, month time.Month, day int, hm ...int) time.Time {
	h, m := 0, 0
	if len(hm) > 0 {
		h = hm[0]
	}
	if len(hm) > 1 {
		m = hm[1]
	}
	return time.Date(year, month, day, h, m, 0, 0, time.UTC)
}
