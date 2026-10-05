package ctlog

import (
	"context"
	"errors"
	"log/slog"
	"slices"
	"strings"
	"sync"
	"time"

	"tls-broker/internal/core"
	"tls-broker/internal/names"
)

const (
	// Lookback is how long an expired certificate stays in the inventory,
	// so a lapsed identifier set shows up as expired.
	Lookback = 30 * 24 * time.Hour
	// DefaultPace is the pause between two requests to the source.
	DefaultPace = 2 * time.Second
	// DefaultRequestTimeout bounds one request to the source.
	DefaultRequestTimeout = 60 * time.Second
	// RetryDelay is when a refresh that failed for some zone is tried once
	// more (or the source's Retry-After, if longer), unless the regular
	// interval comes sooner.
	RetryDelay = 15 * time.Minute
	// maxPages bounds the pages of one zone in one refresh; the cursor is
	// kept, so the next refresh continues where this one stopped.
	maxPages = 50
)

// Options configure New.
type Options struct {
	Config   core.ConfigSource
	Source   Source
	Resolver core.Resolver // CAA lookups for the managed zones
	Clock    core.Clock
	Logger   *slog.Logger
	// Pace is the pause between two requests to the source; 0 means none.
	Pace time.Duration
	// RequestTimeout bounds one request; 0 means DefaultRequestTimeout.
	RequestTimeout time.Duration
	// RetryPause is the pause before the one retry of a failed request
	// (not after a rate-limit refusal); 0 means 5 s, negative no retry.
	RetryPause time.Duration
}

// Inventory is the in-memory CT inventory. Run keeps it current; Snapshot
// reads it. Nothing survives a restart.
type Inventory struct {
	o Options

	mu         sync.Mutex
	zones      map[string]*zoneState // by queried zone
	caa        map[string]CAAPolicy  // by managed zone
	lastRun    time.Time             // start of the last refresh
	lastEnd    time.Time             // end of the last refresh
	retryAt    time.Time             // one early retry after a failure; zero when none
	retried    bool                  // the last refresh was that retry
	refreshing bool
	enabled    bool
}

type zoneState struct {
	cursor      string
	items       map[string]Issuance // by TBSSHA256
	lastAttempt time.Time
	lastSuccess time.Time
	err         string
}

// New returns an empty inventory.
func New(o Options) *Inventory {
	if o.Logger == nil {
		o.Logger = slog.Default()
	}
	if o.Clock == nil {
		o.Clock = core.SystemClock{}
	}
	if o.RequestTimeout <= 0 {
		o.RequestTimeout = DefaultRequestTimeout
	}
	if o.RetryPause == 0 {
		o.RetryPause = 5 * time.Second
	}
	return &Inventory{o: o, zones: map[string]*zoneState{}, caa: map[string]CAAPolicy{}}
}

// Run refreshes at once and then every ct_inventory.interval until ctx
// ends. A configuration change takes effect immediately: a new interval
// moves the next refresh, a new zone is fetched at once, disabling drops
// all data.
func (inv *Inventory) Run(ctx context.Context) {
	changed, unsubscribe := inv.o.Config.Subscribe()
	defer unsubscribe()
	for ctx.Err() == nil {
		cfg := inv.o.Config.Current()
		var wait <-chan time.Time
		if cfg.CTInventory.Disabled {
			inv.disable()
		} else {
			now := inv.o.Clock.Now()
			due := inv.due(cfg)
			if !now.Before(due) {
				inv.Refresh(ctx)
				continue
			}
			wait = inv.o.Clock.After(due.Sub(now))
		}
		select {
		case <-ctx.Done():
			return
		case <-changed:
		case <-wait:
		}
	}
}

func (inv *Inventory) disable() {
	inv.mu.Lock()
	defer inv.mu.Unlock()
	if inv.enabled {
		inv.o.Logger.Info("ct inventory disabled")
	}
	inv.enabled = false
	inv.zones = map[string]*zoneState{}
	inv.caa = map[string]CAAPolicy{}
	inv.lastRun, inv.lastEnd, inv.retryAt, inv.retried = time.Time{}, time.Time{}, time.Time{}, false
}

// due is when the next refresh should start: now when there was none yet
// or a queried zone has no data, else the early retry or the end of the
// interval, whichever comes first.
func (inv *Inventory) due(cfg *core.Config) time.Time {
	inv.mu.Lock()
	defer inv.mu.Unlock()
	if inv.lastRun.IsZero() {
		return time.Time{}
	}
	for _, z := range cfg.CTZones() {
		if _, ok := inv.zones[z]; !ok {
			return time.Time{}
		}
	}
	next := inv.lastRun.Add(cfg.CTInventory.Interval)
	if !inv.retryAt.IsZero() && inv.retryAt.Before(next) {
		next = inv.retryAt
	}
	return next
}

// Refresh queries the source for every zone of the active configuration,
// one after the other, and the CAA records of every managed zone. A zone
// whose query fails keeps its data. After a rate-limit refusal the
// remaining zones are skipped for this round.
func (inv *Inventory) Refresh(ctx context.Context) {
	cfg := inv.o.Config.Current()
	zones := cfg.CTZones()
	start := inv.o.Clock.Now()
	inv.mu.Lock()
	inv.enabled, inv.refreshing, inv.lastRun = true, true, start
	for z := range inv.zones {
		if !slices.Contains(zones, z) {
			delete(inv.zones, z)
		}
	}
	for _, z := range zones {
		if inv.zones[z] == nil {
			inv.zones[z] = &zoneState{items: map[string]Issuance{}}
		}
	}
	inv.mu.Unlock()

	var limited *RateLimitError
	failed := 0
	for i, z := range zones {
		if ctx.Err() != nil {
			break
		}
		if limited != nil {
			inv.zoneFailed(z, "not queried: "+limited.Error())
			failed++
			continue
		}
		if i > 0 && inv.o.Pace > 0 {
			if core.Sleep(ctx, inv.o.Clock, inv.o.Pace) != nil {
				break
			}
		}
		if err := inv.refreshZone(ctx, z); err != nil {
			if ctx.Err() != nil {
				break
			}
			failed++
			inv.o.Logger.Warn("ct inventory: zone refresh failed; keeping its previous data", "zone", z, "err", err)
			errors.As(err, &limited)
		}
	}
	caa := inv.lookupCAA(ctx, cfg)

	now := inv.o.Clock.Now()
	inv.mu.Lock()
	defer inv.mu.Unlock()
	inv.refreshing, inv.lastEnd = false, now
	if ctx.Err() != nil {
		return
	}
	inv.caa = caa
	total := 0
	for _, st := range inv.zones {
		for k, is := range st.items {
			if is.NotAfter.Before(now.Add(-Lookback)) {
				delete(st.items, k)
			}
		}
		total += len(st.items)
	}
	switch {
	case failed == 0:
		inv.retryAt, inv.retried = time.Time{}, false
	case inv.retried:
		inv.retryAt, inv.retried = time.Time{}, false // back to the regular interval
	default:
		d := RetryDelay
		if limited != nil && limited.RetryAfter > d {
			d = limited.RetryAfter
		}
		inv.retryAt, inv.retried = now.Add(d), true
	}
	inv.o.Logger.Info("ct inventory refreshed", "zones", len(zones), "failed", failed, "certificates", total,
		"took", now.Sub(start).Round(time.Millisecond))
}

// refreshZone reads pages for zone from its cursor until an empty page. A
// failed request is retried once after a short pause, except a rate-limit
// refusal.
func (inv *Inventory) refreshZone(ctx context.Context, zone string) error {
	inv.mu.Lock()
	st := inv.zones[zone]
	st.lastAttempt = inv.o.Clock.Now()
	cursor := st.cursor
	inv.mu.Unlock()
	for page := 0; page < maxPages; page++ {
		if page > 0 && inv.o.Pace > 0 {
			if err := core.Sleep(ctx, inv.o.Clock, inv.o.Pace); err != nil {
				return err
			}
		}
		list, err := inv.list(ctx, zone, cursor)
		if err != nil {
			var rl *RateLimitError
			if !errors.As(err, &rl) && ctx.Err() == nil && inv.o.RetryPause > 0 {
				if core.Sleep(ctx, inv.o.Clock, inv.o.RetryPause) == nil {
					list, err = inv.list(ctx, zone, cursor)
				}
			}
		}
		if err != nil {
			inv.zoneFailed(zone, err.Error())
			return err
		}
		inv.mu.Lock()
		if len(list) == 0 {
			st.lastSuccess, st.err = inv.o.Clock.Now(), ""
			inv.mu.Unlock()
			return nil
		}
		for _, is := range list {
			st.items[is.TBSSHA256] = is
		}
		cursor = list[len(list)-1].ID
		st.cursor = cursor
		inv.mu.Unlock()
	}
	inv.o.Logger.Warn("ct inventory: page limit reached; the next refresh continues", "zone", zone, "pages", maxPages)
	inv.mu.Lock()
	st.lastSuccess, st.err = inv.o.Clock.Now(), ""
	inv.mu.Unlock()
	return nil
}

func (inv *Inventory) list(ctx context.Context, zone, after string) ([]Issuance, error) {
	rctx, cancel := context.WithTimeout(ctx, inv.o.RequestTimeout)
	defer cancel()
	return inv.o.Source.List(rctx, zone, after)
}

func (inv *Inventory) zoneFailed(zone, msg string) {
	inv.mu.Lock()
	defer inv.mu.Unlock()
	if st := inv.zones[zone]; st != nil {
		st.err = msg
		if st.lastAttempt.IsZero() || st.lastAttempt.Before(inv.lastRun) {
			st.lastAttempt = inv.o.Clock.Now()
		}
	}
}

// lookupCAA reads the effective CAA RRset of every managed zone (climbing
// to the parent when the apex has none, RFC 8659 §3).
func (inv *Inventory) lookupCAA(ctx context.Context, cfg *core.Config) map[string]CAAPolicy {
	out := map[string]CAAPolicy{}
	if inv.o.Resolver == nil {
		return out
	}
	for _, z := range cfg.ManagedZones().List() {
		out[z] = inv.policy(ctx, z)
	}
	return out
}

func (inv *Inventory) policy(ctx context.Context, zone string) CAAPolicy {
	for n := zone; n != ""; {
		rrs, err := inv.o.Resolver.LookupCAA(ctx, n)
		if err != nil {
			return CAAPolicy{Err: err.Error()}
		}
		if len(rrs) > 0 {
			return newCAAPolicy(n, rrs)
		}
		_, n, _ = strings.Cut(n, ".")
	}
	return CAAPolicy{}
}

// ZoneStatus is the refresh state of one queried zone.
type ZoneStatus struct {
	Zone string
	// Covers are the other managed zones inside this one: the query for
	// Zone includes them.
	Covers      []string
	LastAttempt time.Time
	LastSuccess time.Time // zero until a complete pass succeeded
	Err         string    // why the last attempt failed; "" when it succeeded
	Count       int       // issuances held for this zone
}

// Snapshot is a copy of the inventory at one moment.
type Snapshot struct {
	Enabled    bool
	Refreshing bool
	Interval   time.Duration
	LastRun    time.Time // start of the last refresh; zero before the first
	LastEnd    time.Time // end of the last refresh
	NextRun    time.Time
	Zones      []ZoneStatus
	// ManagedZones are all managed zones, for matching names to zones.
	ManagedZones []string
	// CAA is the effective CAA policy per managed zone.
	CAA map[string]CAAPolicy
	// Issuances are all issuances held, each once (zones may share one).
	Issuances []Issuance
}

// Loaded reports whether every queried zone has been tried at least once.
func (s Snapshot) Loaded() bool {
	if s.LastEnd.IsZero() {
		return false
	}
	for _, z := range s.Zones {
		if z.LastAttempt.IsZero() {
			return false
		}
	}
	return true
}

// Failed returns the zones whose last attempt failed.
func (s Snapshot) Failed() []ZoneStatus {
	var out []ZoneStatus
	for _, z := range s.Zones {
		if z.Err != "" {
			out = append(out, z)
		}
	}
	return out
}

// Snapshot returns a copy of the current state.
func (inv *Inventory) Snapshot() Snapshot {
	cfg := inv.o.Config.Current()
	inv.mu.Lock()
	defer inv.mu.Unlock()
	s := Snapshot{
		Enabled: !cfg.CTInventory.Disabled, Refreshing: inv.refreshing, Interval: cfg.CTInventory.Interval,
		LastRun: inv.lastRun, LastEnd: inv.lastEnd, ManagedZones: cfg.ManagedZones().List(), CAA: map[string]CAAPolicy{},
	}
	if !s.Enabled {
		return s
	}
	if !inv.lastRun.IsZero() {
		s.NextRun = inv.lastRun.Add(s.Interval)
		if !inv.retryAt.IsZero() && inv.retryAt.Before(s.NextRun) {
			s.NextRun = inv.retryAt
		}
	}
	for z, p := range inv.caa {
		s.CAA[z] = p
	}
	seen := map[string]bool{}
	for _, z := range cfg.CTZones() {
		zs := ZoneStatus{Zone: z}
		for _, m := range s.ManagedZones {
			if m != z && names.InZone(m, z) {
				zs.Covers = append(zs.Covers, m)
			}
		}
		slices.Sort(zs.Covers)
		if st := inv.zones[z]; st != nil {
			zs.LastAttempt, zs.LastSuccess, zs.Err, zs.Count = st.lastAttempt, st.lastSuccess, st.err, len(st.items)
			for k, is := range st.items {
				if !seen[k] {
					seen[k] = true
					s.Issuances = append(s.Issuances, is)
				}
			}
		}
		s.Zones = append(s.Zones, zs)
	}
	slices.SortFunc(s.Issuances, func(a, b Issuance) int {
		if c := a.NotBefore.Compare(b.NotBefore); c != 0 {
			return c
		}
		return strings.Compare(a.TBSSHA256, b.TBSSHA256)
	})
	return s
}
