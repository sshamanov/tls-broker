// Package dns01 is the Route53 DNS-01 engine (architecture §17): it publishes
// ACME challenge TXT values in managed Route53 hosted zones, waits until they
// are visible in public DNS, removes them again, and repairs Route53 from the
// persisted challenge rows after a restart. It implements core.DNSEngine.
//
// The engine never overwrites a value it does not own. For every record name
// it computes the desired TXT RRset as the values Route53 already has that no
// broker challenge owns, plus the values of the record's challenges whose
// state wants a record. Writes to one hosted zone go through one serialized
// queue that batches all pending record names into one change.
//
// FakeRoute53 is the in-memory Route53 used by this package's tests and by
// the end-to-end tests.
package dns01

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/route53"

	"tls-broker/internal/core"
	"tls-broker/internal/names"
)

// ErrClosed is returned by every method once Close has been called.
var ErrClosed = errors.New("dns01: engine is closed")

// ErrChangeTimeout means a Route53 write did not complete, or a submitted
// change did not reach INSYNC, within Route53Config.ChangeTimeout.
var ErrChangeTimeout = errors.New("route53 change did not complete in time")

// errCleanedUp: Present found its challenge cleaned up by a concurrent
// Cleanup/CleanupOwner.
var errCleanedUp = errors.New("dns01: challenge was cleaned up while it was being presented")

// Error prefixes stored in Challenge.Error. Reconcile finishes a challenge
// left in cleaning as failed when its error came from a failed present, and
// as done otherwise.
const (
	presentErrPrefix = "present: "
	cleanupErrPrefix = "cleanup: "
)

const (
	defaultCallTimeout = 30 * time.Second
	defaultPoll        = 2 * time.Second
	// maxPollFactor caps the visibility-poll backoff at this multiple of
	// Route53Config.PollInterval.
	maxPollFactor = 4
)

// Options are the dependencies of an Engine.
type Options struct {
	Config   core.ConfigSource   // zones and Route53 settings, read on every call
	Store    core.ChallengeStore // challenge rows (internal/store)
	Resolver core.Resolver       // public DNS view used to confirm visibility
	API      Route53API          // NewRoute53Client, or a FakeRoute53
	Clock    core.Clock          // nil: core.SystemClock
	// CallTimeout bounds one Route53 API call before it is retried; 0 means
	// 30 s. Every write is still bounded by Route53Config.ChangeTimeout.
	CallTimeout time.Duration
}

// Engine implements core.DNSEngine over Route53. Create it with New; it is
// safe for concurrent use. Call Close on shutdown.
type Engine struct {
	cfg         core.ConfigSource
	store       core.ChallengeStore
	resolver    core.Resolver
	api         Route53API
	clock       core.Clock
	callTimeout time.Duration

	base     context.Context // parent of all Route53 writes; cancelled at the end of Close
	cancel   context.CancelFunc
	stopping context.Context // cancelled (cause ErrClosed) when Close starts; stops visibility polls
	stop     context.CancelCauseFunc
	wg       sync.WaitGroup // running zone writers
	ops      sync.WaitGroup // running Present/Cleanup/Reconcile calls

	mu         sync.Mutex
	closed     bool
	writers    map[string]*zoneWriter // by hosted zone ID
	locks      map[string]*sync.Mutex // by zone|record: guards challenge state transitions
	inflight   map[string]int         // challenge ID -> Present calls working on it
	lastChange map[string]string      // zone|record -> ID of the last change that wrote it
	zoneIDs    map[string]string      // zone name -> hosted zone ID discovered by name
	zoneErrs   map[string]string      // zone name -> why discovery failed last time

	// resolveMu serializes hosted zone discovery so that concurrent Present
	// calls for an unresolved zone share one listing instead of each
	// paging through ListHostedZones.
	resolveMu sync.Mutex
}

// ZoneStatus is the effective hosted zone of one configured zone, for the
// UI and logs.
type ZoneStatus struct {
	Name         string
	HostedZoneID string // effective ID; "" while discovery has not succeeded
	Resolved     bool   // true: discovered by name; false: configured
	Err          string // why discovery failed (only when HostedZoneID is "")
}

var _ core.DNSEngine = (*Engine)(nil)

// New returns an engine. Config, Store, Resolver and API are required.
func New(o Options) (*Engine, error) {
	if o.Config == nil || o.Store == nil || o.Resolver == nil || o.API == nil {
		return nil, errors.New("dns01: Config, Store, Resolver and API are required")
	}
	if o.Clock == nil {
		o.Clock = core.SystemClock{}
	}
	if o.CallTimeout <= 0 {
		o.CallTimeout = defaultCallTimeout
	}
	base, cancel := context.WithCancel(context.Background())
	stopping, stop := context.WithCancelCause(context.Background())
	return &Engine{
		cfg: o.Config, store: o.Store, resolver: o.Resolver, api: o.API, clock: o.Clock,
		callTimeout: o.CallTimeout, base: base, cancel: cancel, stopping: stopping, stop: stop,
		writers: map[string]*zoneWriter{}, locks: map[string]*sync.Mutex{},
		inflight: map[string]int{}, lastChange: map[string]string{},
		zoneIDs: map[string]string{}, zoneErrs: map[string]string{},
	}, nil
}

// Close stops accepting work, stops Present calls that are waiting for
// visibility (they return ErrClosed), lets queued Route53 writes finish until
// ctx is done, then aborts the rest and waits for every call to return. A
// challenge cut short this way stays non-terminal (cleaning, or whatever
// state it had reached) with the value possibly still in Route53, so that
// Reconcile at the next start repairs it. Close is idempotent.
func (e *Engine) Close(ctx context.Context) error {
	e.mu.Lock()
	e.closed = true
	e.mu.Unlock()
	e.stop(ErrClosed)
	done := make(chan struct{})
	go func() { e.ops.Wait(); e.wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-ctx.Done():
	}
	e.cancel()
	<-done
	return nil
}

// beginOp registers a public call; the caller must call e.ops.Done.
func (e *Engine) beginOp() error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.closed {
		return ErrClosed
	}
	e.ops.Add(1)
	return nil
}

func (e *Engine) route53() core.Route53Config {
	c := e.cfg.Current().Route53
	if c.PollInterval <= 0 {
		c.PollInterval = defaultPoll
	}
	if c.ChangeTimeout <= 0 {
		c.ChangeTimeout = core.DefaultConfig().Route53.ChangeTimeout
	}
	if c.PropagationTimeout <= 0 {
		c.PropagationTimeout = core.DefaultConfig().Route53.PropagationTimeout
	}
	if c.TTL < time.Second {
		c.TTL = core.DefaultConfig().Route53.TTL
	}
	return c
}

// locate normalizes record and finds its managed zone (longest suffix). The
// returned zone carries its effective hosted zone ID: the configured one,
// or the one discovered by name (discovered now when it is not known yet).
func (e *Engine) locate(ctx context.Context, record string) (rec string, zone core.ZoneConfig, err error) {
	id, ok := names.IdentifierFromChallengeRecord(record)
	if !ok {
		return "", zone, fmt.Errorf("%w: %q is not an _acme-challenge record", core.ErrOutsideManagedZones, record)
	}
	n, err := names.Normalize(id)
	if err != nil || names.IsWildcard(n) {
		return "", zone, fmt.Errorf("%w: %q is not a valid challenge record", core.ErrOutsideManagedZones, record)
	}
	zone, ok = e.cfg.Current().ZoneFor(n)
	if !ok {
		return "", zone, fmt.Errorf("%w: %s", core.ErrOutsideManagedZones, record)
	}
	zone.HostedZoneID = hostedZoneID(zone.HostedZoneID)
	if zone.HostedZoneID == "" {
		if zone.HostedZoneID, err = e.resolveZone(ctx, zone.Name); err != nil {
			return "", zone, fmt.Errorf("dns01: zone %s has no hosted zone ID: %w", zone.Name, err)
		}
	}
	return names.ChallengeRecord(n), zone, nil
}

// effectiveZoneID returns the hosted zone ID the engine uses for z: the
// configured one, or the discovered one. ok is false when neither is known.
func (e *Engine) effectiveZoneID(z core.ZoneConfig) (id string, ok bool) {
	if id = hostedZoneID(z.HostedZoneID); id != "" {
		return id, true
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	id, ok = e.zoneIDs[z.Name]
	return id, ok
}

// resolveZone returns the discovered hosted zone ID of the named zone,
// discovering it (together with every other zone that still needs it) when
// it is not known yet.
func (e *Engine) resolveZone(ctx context.Context, name string) (string, error) {
	e.mu.Lock()
	id, ok := e.zoneIDs[name]
	e.mu.Unlock()
	if ok {
		return id, nil
	}
	e.resolveMu.Lock()
	defer e.resolveMu.Unlock()
	e.mu.Lock()
	id, ok = e.zoneIDs[name]
	e.mu.Unlock()
	if ok { // another caller discovered it while we waited
		return id, nil
	}
	_ = e.resolveZones(ctx, e.cfg.Current(), false)
	e.mu.Lock()
	defer e.mu.Unlock()
	if id, ok = e.zoneIDs[name]; ok {
		return id, nil
	}
	if msg := e.zoneErrs[name]; msg != "" {
		return "", errors.New(msg)
	}
	return "", errors.New("hosted zone not discovered")
}

// ResolveZones discovers, through ListHostedZones, the hosted zone ID of
// every configured zone without hosted_zone_id: the one public hosted zone
// with that name. It is for startup and configuration changes; the result
// is kept across configuration reloads and dropped when the zone leaves the
// configuration or gets an explicit ID. When the listing fails, earlier
// results are kept and the zones still unresolved report the error. A
// zone whose ID cannot be discovered (none or several public hosted zones
// of that name) is reported in the returned error and DNS-01 for it fails
// until the next ResolveZones, Present or configuration change resolves it.
func (e *Engine) ResolveZones(ctx context.Context) error {
	e.resolveMu.Lock()
	defer e.resolveMu.Unlock()
	return e.resolveZones(ctx, e.cfg.Current(), true)
}

// resolveZones does the work of ResolveZones. With all false only zones
// without a known ID are looked up (a lazy retry after an earlier
// failure); with all true every zone without an explicit ID is looked up
// again, so a hosted zone recreated under a new ID is picked up. Caller
// holds resolveMu.
func (e *Engine) resolveZones(ctx context.Context, cfg *core.Config, all bool) error {
	var pending []string
	byName := map[string]bool{}
	e.mu.Lock()
	for _, z := range cfg.Zones {
		if z.HostedZoneID != "" {
			continue
		}
		byName[z.Name] = true
		if _, known := e.zoneIDs[z.Name]; all || !known {
			pending = append(pending, z.Name)
		}
	}
	for n := range e.zoneIDs {
		if !byName[n] {
			delete(e.zoneIDs, n)
		}
	}
	for n := range e.zoneErrs {
		if !byName[n] {
			delete(e.zoneErrs, n)
		}
	}
	e.mu.Unlock()
	if len(pending) == 0 {
		return nil
	}

	found, err := e.listPublicZones(ctx)
	if err != nil {
		err = fmt.Errorf("list hosted zones: %w", err)
		e.mu.Lock()
		defer e.mu.Unlock()
		var errs []error
		for _, n := range pending {
			if _, known := e.zoneIDs[n]; known {
				continue // keep the earlier result through a transient failure
			}
			e.zoneErrs[n] = err.Error()
			errs = append(errs, fmt.Errorf("zone %s: %w", n, err))
		}
		return errors.Join(errs...)
	}

	e.mu.Lock()
	defer e.mu.Unlock()
	var errs []error
	for _, n := range pending {
		var err error
		switch ids := found[strings.ToLower(n)]; len(ids) {
		case 1:
			e.zoneIDs[n] = ids[0]
			delete(e.zoneErrs, n)
			continue
		case 0:
			err = fmt.Errorf("no public hosted zone named %s", n)
		default:
			err = fmt.Errorf("several public hosted zones named %s (%s); set hosted_zone_id", n, strings.Join(ids, ", "))
		}
		delete(e.zoneIDs, n)
		e.zoneErrs[n] = err.Error()
		errs = append(errs, err)
	}
	return errors.Join(errs...)
}

// listPublicZones pages through ListHostedZones and returns the IDs of the
// public hosted zones by lower-case name without trailing dot.
func (e *Engine) listPublicZones(ctx context.Context) (map[string][]string, error) {
	found := map[string][]string{}
	var marker *string
	for {
		var out *route53.ListHostedZonesOutput
		err := e.retry(ctx, func(ctx context.Context) error {
			var err error
			out, err = e.api.ListHostedZones(ctx, &route53.ListHostedZonesInput{Marker: marker})
			return err
		})
		if err != nil {
			return nil, err
		}
		for _, hz := range out.HostedZones {
			if hz.Config != nil && hz.Config.PrivateZone {
				continue
			}
			n := unfqdn(aws.ToString(hz.Name))
			found[n] = append(found[n], hostedZoneID(aws.ToString(hz.Id)))
		}
		if !out.IsTruncated || out.NextMarker == nil || (marker != nil && *out.NextMarker == *marker) {
			return found, nil
		}
		marker = out.NextMarker
	}
}

// ZoneStatuses reports, for every configured zone, the hosted zone ID in
// effect and whether it was configured or discovered by name, or why
// discovery failed.
func (e *Engine) ZoneStatuses() []ZoneStatus {
	zones := e.cfg.Current().Zones
	out := make([]ZoneStatus, 0, len(zones))
	e.mu.Lock()
	defer e.mu.Unlock()
	for _, z := range zones {
		st := ZoneStatus{Name: z.Name, HostedZoneID: hostedZoneID(z.HostedZoneID)}
		if st.HostedZoneID == "" {
			st.Resolved = true
			if st.HostedZoneID = e.zoneIDs[z.Name]; st.HostedZoneID == "" {
				st.Resolved = false
				if st.Err = e.zoneErrs[z.Name]; st.Err == "" {
					st.Err = "hosted zone not discovered yet"
				}
			}
		}
		out = append(out, st)
	}
	return out
}

func recordKey(zoneID, rec string) string { return zoneID + "|" + rec }

func (e *Engine) recordLock(zoneID, rec string) *sync.Mutex {
	e.mu.Lock()
	defer e.mu.Unlock()
	k := recordKey(zoneID, rec)
	l, ok := e.locks[k]
	if !ok {
		l = &sync.Mutex{}
		e.locks[k] = l
	}
	return l
}

// withEngine returns ctx that is also cancelled (cause ErrClosed) when Close
// starts.
func (e *Engine) withEngine(ctx context.Context) (context.Context, context.CancelFunc) {
	ctx, cancel := context.WithCancelCause(ctx)
	stop := context.AfterFunc(e.stopping, func() { cancel(ErrClosed) })
	return ctx, func() { stop(); cancel(context.Canceled) }
}

// Present implements core.DNSEngine.
func (e *Engine) Present(ctx context.Context, owner, record, value string) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	if err := e.beginOp(); err != nil {
		return "", err
	}
	defer e.ops.Done()
	if owner == "" {
		return "", errors.New("dns01: owner is required")
	}
	rec, zone, err := e.locate(ctx, record)
	if err != nil {
		return "", err
	}
	if err := checkValue(value); err != nil {
		return "", err
	}
	ctx, cancel := e.withEngine(ctx)
	defer cancel()

	ch, err := e.findOrCreate(ctx, owner, rec, value, zone.HostedZoneID)
	if err != nil {
		return "", err
	}
	err = e.present(ctx, ch)

	e.mu.Lock()
	e.inflight[ch.ID]--
	last := e.inflight[ch.ID] == 0
	if last {
		delete(e.inflight, ch.ID)
	}
	e.mu.Unlock()

	if err == nil {
		return ch.ID, nil
	}
	if ctx.Err() != nil && errors.Is(context.Cause(ctx), ErrClosed) {
		err = ErrClosed
	}
	if last && !errors.Is(err, errCleanedUp) {
		e.abandon(ctx, ch, err)
	}
	return "", err
}

// findOrCreate returns the non-terminal challenge for the triple, creating
// it in state pending when there is none, and counts the caller as working
// on it.
func (e *Engine) findOrCreate(ctx context.Context, owner, rec, value, zoneID string) (*core.Challenge, error) {
	lk := e.recordLock(zoneID, rec)
	lk.Lock()
	defer lk.Unlock()
	ch, err := e.store.FindActive(ctx, owner, rec, value)
	switch {
	case err == nil && ch.State.WantsRecord():
		// Resume (idempotent retry, or preparation after a restart). The
		// row keeps the zone it was created in.
	case err == nil || errors.Is(err, core.ErrNotFound):
		now := e.clock.Now()
		ch = &core.Challenge{ID: core.NewID(), ZoneID: zoneID, RecordName: rec, Value: value, Owner: owner,
			State: core.ChallengePending, CreatedAt: now, UpdatedAt: now}
		if err := e.store.Create(ctx, ch); err != nil {
			return nil, fmt.Errorf("dns01: record challenge: %w", err)
		}
	default:
		return nil, fmt.Errorf("dns01: find challenge: %w", err)
	}
	e.mu.Lock()
	e.inflight[ch.ID]++
	e.mu.Unlock()
	return ch, nil
}

// presentRank orders the states a presented challenge moves through.
var presentRank = map[core.ChallengeState]int{
	core.ChallengePending: 0, core.ChallengePresenting: 1, core.ChallengeWaitingDNS: 2, core.ChallengeReady: 3,
}

// advance moves a challenge forward to state `to` unless it is already
// there or further. errCleanedUp if it no longer wants its record.
func (e *Engine) advance(ctx context.Context, ch *core.Challenge, to core.ChallengeState) error {
	lk := e.recordLock(ch.ZoneID, ch.RecordName)
	lk.Lock()
	defer lk.Unlock()
	cur, err := e.store.Get(ctx, ch.ID)
	if err != nil {
		return fmt.Errorf("dns01: read challenge: %w", err)
	}
	if !cur.State.WantsRecord() {
		return errCleanedUp
	}
	if presentRank[cur.State] >= presentRank[to] {
		return nil
	}
	if err := e.store.SetState(ctx, ch.ID, to, "", e.clock.Now()); err != nil {
		if errors.Is(err, core.ErrConflict) {
			return errCleanedUp
		}
		return fmt.Errorf("dns01: set challenge state: %w", err)
	}
	return nil
}

func (e *Engine) present(ctx context.Context, ch *core.Challenge) error {
	if err := e.advance(ctx, ch, core.ChallengePresenting); err != nil {
		return err
	}
	changeID, err := e.write(ctx, ch.ZoneID, ch.RecordName)
	if err != nil {
		return err
	}
	if err := e.advance(ctx, ch, core.ChallengeWaitingDNS); err != nil {
		return err
	}
	if err := e.waitVisible(ctx, ch, changeID); err != nil {
		return err
	}
	return e.advance(ctx, ch, core.ChallengeReady)
}

// waitVisible waits until the challenge's value is visible in public DNS.
// While the change is not yet INSYNC it only asks Route53 for the change
// status and does not query the public resolver: a lookup that reaches an
// authoritative server before the change does gets NXDOMAIN, which the
// public resolvers then cache for the zone's negative TTL (often 15 minutes
// or more), far longer than the propagation timeout. Once the change is in
// sync (or right away when there is no change to wait for) it polls the
// resolver, and the propagation timeout starts. It stops with errCleanedUp
// when the challenge is cleaned up meanwhile.
func (e *Engine) waitVisible(ctx context.Context, ch *core.Challenge, changeID string) error {
	rec, value := ch.RecordName, ch.Value
	cfg := e.route53()
	start := e.clock.Now()
	insync := changeID == ""
	insyncAt := start
	delay := cfg.PollInterval
	var lastErr error
	for {
		if !insync {
			st, err := e.changeStatus(ctx, changeID)
			now := e.clock.Now()
			switch {
			case err == nil && st == "INSYNC":
				insync, insyncAt = true, now
				delay = cfg.PollInterval
			case now.Sub(start) >= cfg.ChangeTimeout:
				if err != nil {
					return fmt.Errorf("%w: change %s: %v", ErrChangeTimeout, changeID, err)
				}
				return fmt.Errorf("%w: change %s still %s after %s", ErrChangeTimeout, changeID, st, cfg.ChangeTimeout)
			}
		}
		if insync {
			vals, err := e.resolver.LookupTXT(ctx, rec)
			if err == nil && slices.Contains(vals, value) {
				return nil
			}
			if err != nil {
				lastErr = err
			}
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if cur, err := e.store.Get(ctx, ch.ID); err == nil && !cur.State.WantsRecord() {
			return errCleanedUp
		}
		now := e.clock.Now()
		var deadline time.Time
		if insync {
			deadline = insyncAt.Add(cfg.PropagationTimeout)
			if !now.Before(deadline) {
				if lastErr != nil {
					return fmt.Errorf("%w: %s (last lookup error: %v)", core.ErrDNSPropagation, rec, lastErr)
				}
				return fmt.Errorf("%w: %s after %s", core.ErrDNSPropagation, rec, cfg.PropagationTimeout)
			}
		} else {
			deadline = start.Add(cfg.ChangeTimeout)
		}
		if err := core.Sleep(ctx, e.clock, min(delay, deadline.Sub(now))); err != nil {
			return err
		}
		delay = min(delay*3/2, maxPollFactor*cfg.PollInterval)
	}
}

// abandon removes the value of a challenge whose Present failed and marks
// it failed. If the removal cannot be done now the challenge stays in
// cleaning with the error recorded, and Reconcile finishes it later.
func (e *Engine) abandon(ctx context.Context, ch *core.Challenge, cause error) {
	ctx = context.WithoutCancel(ctx)
	msg := presentErrPrefix + cause.Error()
	lk := e.recordLock(ch.ZoneID, ch.RecordName)
	lk.Lock()
	cur, err := e.store.Get(ctx, ch.ID)
	// A ready challenge belongs to a Present call that already succeeded;
	// a failing duplicate call must not take it away.
	if err != nil || !cur.State.WantsRecord() || cur.State == core.ChallengeReady {
		lk.Unlock()
		return
	}
	err = e.store.SetState(ctx, ch.ID, core.ChallengeCleaning, msg, e.clock.Now())
	lk.Unlock()
	if err != nil {
		return
	}
	if _, err := e.write(ctx, ch.ZoneID, ch.RecordName); err != nil {
		e.setCleaningError(ctx, ch, msg+"; removal: "+err.Error())
		return
	}
	e.finish(ctx, ch, core.ChallengeFailed, msg)
}

// setCleaningError records an error on a challenge that is still cleaning.
func (e *Engine) setCleaningError(ctx context.Context, ch *core.Challenge, msg string) {
	lk := e.recordLock(ch.ZoneID, ch.RecordName)
	lk.Lock()
	defer lk.Unlock()
	if cur, err := e.store.Get(ctx, ch.ID); err == nil && cur.State == core.ChallengeCleaning {
		_ = e.store.SetState(ctx, ch.ID, core.ChallengeCleaning, msg, e.clock.Now())
	}
}

// finish moves a challenge from cleaning to a terminal state. A challenge
// that is no longer cleaning (finished concurrently) is left alone.
func (e *Engine) finish(ctx context.Context, ch *core.Challenge, to core.ChallengeState, msg string) {
	lk := e.recordLock(ch.ZoneID, ch.RecordName)
	lk.Lock()
	defer lk.Unlock()
	if cur, err := e.store.Get(ctx, ch.ID); err == nil && cur.State == core.ChallengeCleaning {
		_ = e.store.SetState(ctx, ch.ID, to, msg, e.clock.Now())
	}
}

// Cleanup implements core.DNSEngine.
func (e *Engine) Cleanup(ctx context.Context, challengeID string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	ch, err := e.store.Get(ctx, challengeID)
	if err != nil {
		return fmt.Errorf("dns01: challenge %s: %w", challengeID, err)
	}
	if ch.State.Terminal() {
		return nil
	}
	if err := e.beginOp(); err != nil {
		return err
	}
	defer e.ops.Done()
	lk := e.recordLock(ch.ZoneID, ch.RecordName)
	lk.Lock()
	cur, err := e.store.Get(ctx, ch.ID)
	if err == nil && cur.State.Terminal() {
		lk.Unlock()
		return nil
	}
	if err == nil && cur.State != core.ChallengeCleaning {
		err = e.store.SetState(ctx, ch.ID, core.ChallengeCleaning, "", e.clock.Now())
		if errors.Is(err, core.ErrConflict) { // became terminal meanwhile
			lk.Unlock()
			return nil
		}
	}
	lk.Unlock()
	if err != nil {
		return fmt.Errorf("dns01: challenge %s: %w", challengeID, err)
	}
	if _, err := e.write(ctx, ch.ZoneID, ch.RecordName); err != nil {
		e.setCleaningError(context.WithoutCancel(ctx), ch, cleanupErrPrefix+err.Error())
		return err
	}
	e.finish(context.WithoutCancel(ctx), ch, core.ChallengeDone, "")
	return nil
}

// CleanupOwner implements core.DNSEngine. The owner's challenges are
// cleaned concurrently so that removals in one zone share one change.
func (e *Engine) CleanupOwner(ctx context.Context, owner string) error {
	list, err := e.store.ListByOwner(ctx, owner)
	if err != nil {
		return fmt.Errorf("dns01: list challenges of %s: %w", owner, err)
	}
	errs := make([]error, len(list))
	var wg sync.WaitGroup
	for i, ch := range list {
		wg.Go(func() { errs[i] = e.Cleanup(ctx, ch.ID) })
	}
	wg.Wait()
	for _, err := range errs {
		if err != nil {
			return err
		}
	}
	return nil
}

// Reconcile implements core.DNSEngine: every record name with non-terminal
// challenges is rewritten to its desired RRset (values Route53 has that the
// broker does not own are kept), and challenges left in cleaning are
// finished once their value is gone.
func (e *Engine) Reconcile(ctx context.Context) error {
	if err := e.beginOp(); err != nil {
		return err
	}
	defer e.ops.Done()
	list, err := e.store.ListActive(ctx)
	if err != nil {
		return fmt.Errorf("dns01: list active challenges: %w", err)
	}
	type rkey struct{ zone, rec string }
	groups := map[rkey][]core.Challenge{}
	var order []rkey
	for _, ch := range list {
		k := rkey{ch.ZoneID, ch.RecordName}
		if _, ok := groups[k]; !ok {
			order = append(order, k)
		}
		groups[k] = append(groups[k], ch)
	}
	errs := make([]error, len(order))
	var wg sync.WaitGroup
	for i, k := range order {
		wg.Go(func() {
			if _, err := e.write(ctx, k.zone, k.rec); err != nil {
				errs[i] = fmt.Errorf("dns01: reconcile %s: %w", k.rec, err)
				return
			}
			for _, ch := range groups[k] {
				if ch.State != core.ChallengeCleaning {
					continue
				}
				if strings.HasPrefix(ch.Error, presentErrPrefix) {
					e.finish(ctx, &ch, core.ChallengeFailed, ch.Error)
				} else {
					e.finish(ctx, &ch, core.ChallengeDone, "")
				}
			}
		})
	}
	wg.Wait()
	return errors.Join(errs...)
}

// VerifyZones discovers the hosted zone IDs that are not configured
// (ResolveZones) and then checks every zone against Route53: its effective
// hosted zone must exist, carry the configured name and be public. Meant
// for startup and for configuration changes.
func (e *Engine) VerifyZones(ctx context.Context) error {
	var errs []error
	if err := e.ResolveZones(ctx); err != nil {
		errs = append(errs, err)
	}
	for _, z := range e.cfg.Current().Zones {
		id, ok := e.effectiveZoneID(z)
		if !ok {
			continue // reported by ResolveZones
		}
		if err := e.verifyZone(ctx, z.Name, id); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}
