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

// locate normalizes record and finds its managed zone (longest suffix).
func (e *Engine) locate(record string) (rec string, zone core.ZoneConfig, err error) {
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
		return "", zone, fmt.Errorf("dns01: zone %s has no hosted zone ID", zone.Name)
	}
	return names.ChallengeRecord(n), zone, nil
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
	rec, zone, err := e.locate(record)
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

// waitVisible polls the public resolver until the challenge's value is
// visible. While the change is not yet INSYNC it also asks Route53 for its
// status; the propagation timeout starts once the change is in sync (or
// right away when there is no change to wait for). It stops with
// errCleanedUp when the challenge is cleaned up meanwhile.
func (e *Engine) waitVisible(ctx context.Context, ch *core.Challenge, changeID string) error {
	rec, value := ch.RecordName, ch.Value
	cfg := e.route53()
	start := e.clock.Now()
	insync := changeID == ""
	insyncAt := start
	delay := cfg.PollInterval
	var lastErr error
	for {
		vals, err := e.resolver.LookupTXT(ctx, rec)
		if err == nil && slices.Contains(vals, value) {
			return nil
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if err != nil {
			lastErr = err
		}
		if cur, err := e.store.Get(ctx, ch.ID); err == nil && !cur.State.WantsRecord() {
			return errCleanedUp
		}
		now := e.clock.Now()
		if !insync {
			st, err := e.changeStatus(ctx, changeID)
			switch {
			case err == nil && st == "INSYNC":
				insync, insyncAt = true, now
			case now.Sub(start) >= cfg.ChangeTimeout:
				if err != nil {
					return fmt.Errorf("%w: change %s: %v", ErrChangeTimeout, changeID, err)
				}
				return fmt.Errorf("%w: change %s still %s after %s", ErrChangeTimeout, changeID, st, cfg.ChangeTimeout)
			}
		}
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

// VerifyZones checks every configured zone against Route53: the hosted zone
// must exist, carry the configured name and be public. Meant for startup
// and for configuration validation.
func (e *Engine) VerifyZones(ctx context.Context) error {
	var errs []error
	for _, z := range e.cfg.Current().Zones {
		if err := e.verifyZone(ctx, z); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}
