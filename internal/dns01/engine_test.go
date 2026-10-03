package dns01

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/route53/types"

	"tls-broker/internal/core"
	"tls-broker/internal/core/coretest"
	"tls-broker/internal/names"
)

const (
	zoneCom = "Z1EXAMPLE" // example.com (coretest.NewConfig)
	zoneOrg = "Z2EXAMPLE" // example.org (coretest.NewConfig)
	zoneSub = "Z3SUB"     // sub.example.com, added here
)

type env struct {
	t     *testing.T
	clock *coretest.FakeClock
	r53   *FakeRoute53
	store *memStore
	cfg   *coretest.FakeConfig
	eng   *Engine
	logs  *logSink
}

// logSink collects the engine's log lines at debug level.
type logSink struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (l *logSink) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.buf.Write(p)
}

func (l *logSink) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.buf.String()
}

func newEnv(t *testing.T) *env {
	t.Helper()
	clock := coretest.NewFakeClock()
	c := coretest.NewConfig()
	c.Zones = append(c.Zones, core.ZoneConfig{Name: "sub.example.com", HostedZoneID: "/hostedzone/" + zoneSub})
	// Generous write bound: the clock pump moves fast in real time.
	c.Route53.ChangeTimeout = 30 * time.Minute
	r53 := NewFakeRoute53(clock)
	r53.AddZone(zoneCom, "example.com")
	r53.AddZone(zoneOrg, "example.org")
	r53.AddZone("/hostedzone/"+zoneSub, "sub.example.com")
	e := &env{t: t, clock: clock, r53: r53, store: newMemStore(), cfg: coretest.NewFakeConfig(c), logs: &logSink{}}
	e.eng = e.newEngine(time.Hour)
	return e
}

// newEngine builds an engine on the env's fakes (as after a restart).
func (e *env) newEngine(callTimeout time.Duration) *Engine {
	e.t.Helper()
	eng, err := New(Options{Config: e.cfg, Store: e.store, Resolver: e.r53.Resolver(nil), API: e.r53,
		Clock: e.clock, CallTimeout: callTimeout,
		Logger: slog.New(slog.NewTextHandler(e.logs, &slog.HandlerOptions{Level: slog.LevelDebug}))})
	if err != nil {
		e.t.Fatal(err)
	}
	e.t.Cleanup(func() { _ = eng.Close(context.Background()) })
	return eng
}

// run calls f while moving the fake clock forward one second per real
// millisecond, and returns f's error.
func (e *env) run(f func() error) error {
	e.t.Helper()
	done := make(chan error, 1)
	go func() { done <- f() }()
	deadline := time.After(30 * time.Second)
	for {
		select {
		case err := <-done:
			return err
		case <-deadline:
			e.t.Fatal("operation did not finish")
		case <-time.After(time.Millisecond):
			e.clock.Advance(time.Second)
		}
	}
}

func (e *env) present(owner, record, value string) (string, error) {
	e.t.Helper()
	var id string
	err := e.run(func() error {
		var err error
		id, err = e.eng.Present(context.Background(), owner, record, value)
		return err
	})
	return id, err
}

func (e *env) mustPresent(owner, record, value string) string {
	e.t.Helper()
	id, err := e.present(owner, record, value)
	if err != nil {
		e.t.Fatalf("Present(%s, %s, %s): %v", owner, record, value, err)
	}
	return id
}

func (e *env) cleanup(id string) error {
	e.t.Helper()
	return e.run(func() error { return e.eng.Cleanup(context.Background(), id) })
}

func (e *env) state(id string) core.Challenge {
	e.t.Helper()
	c, err := e.store.Get(context.Background(), id)
	if err != nil {
		e.t.Fatal(err)
	}
	return *c
}

func sorted(v []string) []string {
	v = slices.Clone(v)
	slices.Sort(v)
	return v
}

func wantTXT(t *testing.T, r53 *FakeRoute53, record string, want ...string) {
	t.Helper()
	if got := sorted(r53.TXT(record)); !slices.Equal(got, sorted(want)) {
		t.Fatalf("TXT %s = %q, want %q", record, got, sorted(want))
	}
}

func TestPresentPublishesAndCleanupRemoves(t *testing.T) {
	e := newEnv(t)
	rec := names.ChallengeRecord("foo.example.com")
	id := e.mustPresent("order:1", rec, "value-A")

	wantTXT(t, e.r53, rec, "value-A")
	rs, _ := e.r53.RRSet(rec, types.RRTypeTxt)
	if aws.ToInt64(rs.TTL) != 60 || aws.ToString(rs.ResourceRecords[0].Value) != `"value-A"` {
		t.Fatalf("rrset = TTL %d value %s, want TTL 60 quoted value", aws.ToInt64(rs.TTL), aws.ToString(rs.ResourceRecords[0].Value))
	}
	c := e.state(id)
	if c.State != core.ChallengeReady || c.ZoneID != zoneCom || c.RecordName != rec || c.Owner != "order:1" {
		t.Fatalf("challenge = %+v", c)
	}
	if got := e.store.states(id); !slices.Equal(got, []core.ChallengeState{core.ChallengePending, core.ChallengePresenting, core.ChallengeWaitingDNS, core.ChallengeReady}) {
		t.Fatalf("state history = %v", got)
	}

	if err := e.cleanup(id); err != nil {
		t.Fatal(err)
	}
	if _, ok := e.r53.RRSet(rec, types.RRTypeTxt); ok {
		t.Fatal("RRset still exists after the last value was cleaned up")
	}
	if got := e.state(id).State; got != core.ChallengeDone {
		t.Fatalf("state after cleanup = %s", got)
	}
	// Each step is logged with the challenge ID so a slow present can be
	// attributed to Route53 propagation or to public DNS.
	logs := e.logs.String()
	for _, want := range []string{"dns01: presenting", "dns01: route53 change submitted", "dns01: route53 change INSYNC",
		"dns01: value visible", "dns01: value removed"} {
		if !strings.Contains(logs, want) || !strings.Contains(logs, "challenge="+id) {
			t.Errorf("log line %q with the challenge ID missing in:\n%s", want, logs)
		}
	}
}

func TestConcurrentPresentsOnSameRecordKeepAllValues(t *testing.T) {
	e := newEnv(t)
	e.r53.SetPublicDelay(3 * time.Second)
	e.r53.SetSyncDelay(10 * time.Second)
	rec := names.ChallengeRecord("foo.example.com")
	const n = 12
	errs := make([]error, n)
	err := e.run(func() error {
		var wg sync.WaitGroup
		for i := range n {
			wg.Go(func() {
				_, errs[i] = e.eng.Present(context.Background(), fmt.Sprintf("order:%d", i), rec, fmt.Sprintf("v%02d", i))
			})
		}
		wg.Wait()
		return errors.Join(errs...)
	})
	if err != nil {
		t.Fatal(err)
	}
	var want []string
	for i := range n {
		want = append(want, fmt.Sprintf("v%02d", i))
	}
	wantTXT(t, e.r53, rec, want...)
	if got := e.r53.MaxConcurrentChanges(zoneCom); got != 1 {
		t.Fatalf("max concurrent changes in zone = %d, want 1", got)
	}
	if got := e.r53.Changes(zoneCom); got >= n {
		t.Fatalf("%d changes for %d presents: writes were not batched", got, n)
	}
}

func TestWildcardAndBaseShareOneRecord(t *testing.T) {
	e := newEnv(t)
	recWild := names.ChallengeRecord("*.foo.example.com")
	recBase := names.ChallengeRecord("foo.example.com")
	if recWild != recBase {
		t.Fatalf("records differ: %s %s", recWild, recBase)
	}
	idW := e.mustPresent("order:1", recWild, "wild-value")
	idB := e.mustPresent("order:1", recBase, "base-value")
	wantTXT(t, e.r53, recBase, "wild-value", "base-value")

	if err := e.cleanup(idW); err != nil {
		t.Fatal(err)
	}
	wantTXT(t, e.r53, recBase, "base-value")
	if got := e.state(idB).State; got != core.ChallengeReady {
		t.Fatalf("other challenge state = %s", got)
	}
}

func TestCleanupKeepsOtherValuesAndIsIdempotent(t *testing.T) {
	e := newEnv(t)
	rec := names.ChallengeRecord("foo.example.com")
	a := e.mustPresent("order:a", rec, "A")
	b := e.mustPresent("order:b", rec, "B")
	c := e.mustPresent("order:c", rec, "C")

	if err := e.cleanup(b); err != nil {
		t.Fatal(err)
	}
	wantTXT(t, e.r53, rec, "A", "C")
	changes := e.r53.Changes(zoneCom)
	if err := e.cleanup(b); err != nil {
		t.Fatalf("second cleanup: %v", err)
	}
	if got := e.r53.Changes(zoneCom); got != changes {
		t.Fatalf("repeated cleanup wrote to Route53 (%d -> %d changes)", changes, got)
	}
	if err := e.cleanup("no-such-id"); !errors.Is(err, core.ErrNotFound) {
		t.Fatalf("cleanup of unknown id = %v, want ErrNotFound", err)
	}
	for _, id := range []string{a, c} {
		if err := e.cleanup(id); err != nil {
			t.Fatal(err)
		}
	}
	if _, ok := e.r53.RRSet(rec, types.RRTypeTxt); ok {
		t.Fatal("RRset not deleted when empty")
	}
}

func TestPresentIsIdempotentPerTriple(t *testing.T) {
	e := newEnv(t)
	rec := names.ChallengeRecord("foo.example.com")
	id1 := e.mustPresent("order:1", rec, "V")
	changes := e.r53.Changes(zoneCom)
	id2 := e.mustPresent("order:1", rec, "V")
	if id1 != id2 {
		t.Fatalf("second present created %s, want %s", id2, id1)
	}
	if got := e.r53.Changes(zoneCom); got != changes {
		t.Fatalf("idempotent present wrote to Route53")
	}
	// Same record and value but another owner is another challenge; the
	// value is published once and stays until both are cleaned up.
	id3 := e.mustPresent("order:2", rec, "V")
	if id3 == id1 {
		t.Fatal("other owner reused the challenge")
	}
	if len(e.store.all()) != 2 {
		t.Fatalf("rows = %d, want 2", len(e.store.all()))
	}
	wantTXT(t, e.r53, rec, "V")
	if err := e.cleanup(id1); err != nil {
		t.Fatal(err)
	}
	wantTXT(t, e.r53, rec, "V")
	if err := e.cleanup(id3); err != nil {
		t.Fatal(err)
	}
	wantTXT(t, e.r53, rec)
}

func TestConcurrentIdenticalPresentsShareOneChallenge(t *testing.T) {
	e := newEnv(t)
	e.r53.SetPublicDelay(5 * time.Second)
	rec := names.ChallengeRecord("foo.example.com")
	ids := make([]string, 5)
	err := e.run(func() error {
		var wg sync.WaitGroup
		errs := make([]error, len(ids))
		for i := range ids {
			wg.Go(func() { ids[i], errs[i] = e.eng.Present(context.Background(), "order:1", rec, "V") })
		}
		wg.Wait()
		return errors.Join(errs...)
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range ids {
		if id != ids[0] {
			t.Fatalf("ids differ: %v", ids)
		}
	}
	if len(e.store.all()) != 1 {
		t.Fatalf("rows = %d, want 1", len(e.store.all()))
	}
}

// lookupLog is a resolver that records when TXT lookups happen.
type lookupLog struct {
	core.Resolver
	clock core.Clock
	mu    sync.Mutex
	at    []time.Time
}

func (l *lookupLog) LookupTXT(ctx context.Context, name string) ([]string, error) {
	l.mu.Lock()
	l.at = append(l.at, l.clock.Now())
	l.mu.Unlock()
	return l.Resolver.LookupTXT(ctx, name)
}

// Public resolvers cache an NXDOMAIN for the zone's negative TTL, so the
// engine must not look the record up before Route53 says the change is
// INSYNC (found against real Route53: a lookup 1 s after the change pinned
// NXDOMAIN at the resolver for 15 minutes). The value being visible early
// does not matter; the first lookup waits for INSYNC.
func TestPresentDoesNotLookUpBeforeInsync(t *testing.T) {
	e := newEnv(t)
	log := &lookupLog{Resolver: e.r53.Resolver(nil), clock: e.clock}
	eng, err := New(Options{Config: e.cfg, Store: e.store, Resolver: log, API: e.r53, Clock: e.clock, CallTimeout: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = eng.Close(context.Background()) })
	e.eng = eng
	e.r53.SetPublicDelay(10 * time.Second)
	e.r53.SetSyncDelay(90 * time.Second)
	start := e.clock.Now()
	e.mustPresent("order:1", names.ChallengeRecord("foo.example.com"), "V")
	if took := e.clock.Now().Sub(start); took < 90*time.Second || took >= 2*time.Minute {
		t.Fatalf("present took %s; want shortly after INSYNC (90 s)", took)
	}
	log.mu.Lock()
	defer log.mu.Unlock()
	if len(log.at) == 0 {
		t.Fatal("never looked the value up")
	}
	if first := log.at[0].Sub(start); first < 90*time.Second {
		t.Fatalf("first TXT lookup %s after the change, before INSYNC at 90 s", first)
	}
	if e.r53.Calls(OpGetChange) == 0 {
		t.Fatal("never asked Route53 for the change status")
	}
}

func TestPresentWaitsForPropagationDelay(t *testing.T) {
	e := newEnv(t)
	e.r53.SetSyncDelay(20 * time.Second)
	e.r53.SetPublicDelay(70 * time.Second) // visible 50 s after INSYNC; timeout is 2 min
	start := e.clock.Now()
	id := e.mustPresent("order:1", names.ChallengeRecord("foo.example.com"), "V")
	if took := e.clock.Now().Sub(start); took < 70*time.Second {
		t.Fatalf("present returned after %s, before the value was public", took)
	}
	if e.state(id).State != core.ChallengeReady {
		t.Fatal("not ready")
	}
	if e.r53.Calls(OpGetChange) == 0 {
		t.Fatal("never asked Route53 for the change status while the value was invisible")
	}
}

func TestPropagationTimeoutFailsAndRemovesValue(t *testing.T) {
	e := newEnv(t)
	e.r53.SetSyncDelay(10 * time.Second)
	e.r53.SetPublicDelay(24 * time.Hour)
	rec := names.ChallengeRecord("foo.example.com")
	e.r53.SetTXT(rec, "foreign")
	start := e.clock.Now()
	_, err := e.present("order:1", rec, "V")
	if !errors.Is(err, core.ErrDNSPropagation) {
		t.Fatalf("err = %v, want ErrDNSPropagation", err)
	}
	if took := e.clock.Now().Sub(start); took < 10*time.Second+2*time.Minute {
		t.Fatalf("gave up after %s, before INSYNC + propagation timeout", took)
	}
	rows := e.store.all()
	if len(rows) != 1 || rows[0].State != core.ChallengeFailed || rows[0].Error == "" {
		t.Fatalf("rows = %+v, want one failed challenge with an error", rows)
	}
	wantTXT(t, e.r53, rec, "foreign")
}

func TestChangeNeverInsyncTimesOut(t *testing.T) {
	e := newEnv(t)
	e.cfg.Update(func(c *core.Config) { c.Route53.ChangeTimeout = 3 * time.Minute })
	e.r53.SetSyncDelay(24 * time.Hour)
	e.r53.SetPublicDelay(24 * time.Hour)
	_, err := e.present("order:1", names.ChallengeRecord("foo.example.com"), "V")
	if !errors.Is(err, ErrChangeTimeout) {
		t.Fatalf("err = %v, want ErrChangeTimeout", err)
	}
	if rows := e.store.all(); rows[0].State != core.ChallengeFailed {
		t.Fatalf("state = %s", rows[0].State)
	}
}

func TestRoute53ThrottlingIsRetried(t *testing.T) {
	e := newEnv(t)
	e.r53.Throttle(OpChange, 3)
	e.r53.Throttle(OpList, 2)
	e.r53.Fail(OpChange, &types.PriorRequestNotComplete{Message: aws.String("busy")}, 1)
	rec := names.ChallengeRecord("foo.example.com")
	e.mustPresent("order:1", rec, "V")
	wantTXT(t, e.r53, rec, "V")
	if got := e.r53.Calls(OpChange); got != 5 {
		t.Fatalf("change calls = %d, want 4 failures + 1 success", got)
	}
}

func TestRoute53TimeoutIsRetried(t *testing.T) {
	e := newEnv(t)
	e.eng = e.newEngine(20 * time.Second)
	e.r53.Hang(OpList, 1)
	e.r53.Hang(OpChange, 1)
	rec := names.ChallengeRecord("foo.example.com")
	e.mustPresent("order:1", rec, "V")
	wantTXT(t, e.r53, rec, "V")
	if got := e.r53.Calls(OpChange); got != 2 {
		t.Fatalf("change calls = %d, want 2", got)
	}
}

func TestPermanentRoute53ErrorFailsChallenge(t *testing.T) {
	e := newEnv(t)
	e.r53.Fail(OpChange, &types.InvalidInput{Message: aws.String("denied")}, 1)
	rec := names.ChallengeRecord("foo.example.com")
	_, err := e.present("order:1", rec, "V")
	var ae *types.InvalidInput
	if !errors.As(err, &ae) {
		t.Fatalf("err = %v, want the Route53 error", err)
	}
	rows := e.store.all()
	if len(rows) != 1 || rows[0].State != core.ChallengeFailed {
		t.Fatalf("rows = %+v", rows)
	}
	if e.r53.Calls(OpChange) != 1 {
		t.Fatalf("permanent error was retried")
	}
}

func TestRoute53DownDuringCleanupLeavesCleaningForReconcile(t *testing.T) {
	e := newEnv(t)
	e.cfg.Update(func(c *core.Config) { c.Route53.ChangeTimeout = time.Minute })
	rec := names.ChallengeRecord("foo.example.com")
	id := e.mustPresent("order:1", rec, "V")
	e.r53.Throttle(OpChange, 1000)
	err := e.cleanup(id)
	if !errors.Is(err, ErrChangeTimeout) {
		t.Fatalf("err = %v, want ErrChangeTimeout", err)
	}
	c := e.state(id)
	if c.State != core.ChallengeCleaning || c.Error == "" {
		t.Fatalf("challenge = %+v, want cleaning with error", c)
	}
	wantTXT(t, e.r53, rec, "V")

	e.r53.ClearFaults() // Route53 recovers
	if err := e.run(func() error { return e.eng.Reconcile(context.Background()) }); err != nil {
		t.Fatal(err)
	}
	wantTXT(t, e.r53, rec)
	if got := e.state(id).State; got != core.ChallengeDone {
		t.Fatalf("state after reconcile = %s", got)
	}
}

func TestCancelledPresentLeavesConsistentState(t *testing.T) {
	e := newEnv(t)
	e.r53.SetPublicDelay(24 * time.Hour)
	rec := names.ChallengeRecord("foo.example.com")
	ctx, cancel := context.WithCancel(context.Background())
	var id string
	err := e.run(func() error {
		go func() {
			for e.r53.Changes(zoneCom) == 0 {
				time.Sleep(time.Millisecond)
			}
			cancel()
		}()
		var err error
		id, err = e.eng.Present(ctx, "order:1", rec, "V")
		return err
	})
	if !errors.Is(err, context.Canceled) || id != "" {
		t.Fatalf("Present = %q, %v; want context.Canceled", id, err)
	}
	rows := e.store.all()
	if len(rows) != 1 || rows[0].State != core.ChallengeFailed {
		t.Fatalf("rows = %+v, want one failed challenge", rows)
	}
	wantTXT(t, e.r53, rec)
}

func TestForeignValuesArePreserved(t *testing.T) {
	e := newEnv(t)
	rec := names.ChallengeRecord("foo.example.com")
	e.r53.SetTXT(rec, "foreign-1", `with "quotes"`)
	id := e.mustPresent("order:1", rec, "mine")
	wantTXT(t, e.r53, rec, "foreign-1", `with "quotes"`, "mine")
	if err := e.cleanup(id); err != nil {
		t.Fatal(err)
	}
	wantTXT(t, e.r53, rec, "foreign-1", `with "quotes"`)
	if err := e.run(func() error { return e.eng.Reconcile(context.Background()) }); err != nil {
		t.Fatal(err)
	}
	wantTXT(t, e.r53, rec, "foreign-1", `with "quotes"`)
}

func TestForeignChangeBetweenReadAndWriteIsReplanned(t *testing.T) {
	e := newEnv(t)
	rec := names.ChallengeRecord("foo.example.com")
	var once atomic.Bool
	e.r53.OnChange(func(ctx context.Context, zoneID string) error {
		if once.CompareAndSwap(false, true) {
			e.r53.SetTXT(rec, "sneaky") // someone else writes after our read
		}
		return nil
	})
	e.mustPresent("order:1", rec, "mine")
	wantTXT(t, e.r53, rec, "sneaky", "mine")
}

func TestZoneSelectionByLongestSuffix(t *testing.T) {
	e := newEnv(t)
	cases := []struct{ name, zone string }{
		{"a.sub.example.com", zoneSub},
		{"sub.example.com", zoneSub},
		{"*.b.sub.example.com", zoneSub},
		{"b.example.com", zoneCom},
		{"example.com", zoneCom},
		{"x.example.org", zoneOrg},
	}
	for _, c := range cases {
		rec := names.ChallengeRecord(c.name)
		id := e.mustPresent("order:1", rec, "V-"+c.name)
		if got := e.state(id).ZoneID; got != c.zone {
			t.Errorf("%s: zone %s, want %s", c.name, got, c.zone)
		}
		if got := e.r53.TXT(rec); !slices.Contains(got, "V-"+c.name) {
			t.Errorf("%s: value not in Route53 (%v)", c.name, got)
		}
	}
	// The value must live in the sub zone, not in the parent.
	e.r53.mu.Lock()
	_, inParent := e.r53.zones[zoneCom].rrsets[rrKey{"_acme-challenge.a.sub.example.com", types.RRTypeTxt}]
	e.r53.mu.Unlock()
	if inParent {
		t.Error("record of the sub zone written to the parent zone")
	}
	for _, rec := range []string{"_acme-challenge.foo.example.net", "foo.example.com", "_acme-challenge.notexample.com", "_acme-challenge.*.example.com"} {
		_, err := e.present("order:1", rec, "V")
		if !errors.Is(err, core.ErrOutsideManagedZones) {
			t.Errorf("%s: err = %v, want ErrOutsideManagedZones", rec, err)
		}
	}
	if _, err := e.present("order:1", names.ChallengeRecord("foo.example.com"), "bad\nvalue"); !errors.Is(err, ErrInvalidValue) {
		t.Errorf("bad value: err = %v", err)
	}
	if got := len(e.store.all()); got != len(cases) {
		t.Fatalf("rows = %d, want %d (rejected presents must create nothing)", got, len(cases))
	}
}

func TestWritesSerializedPerZoneParallelAcrossZones(t *testing.T) {
	e := newEnv(t) // no delays: presents complete without the clock
	entered := make(chan struct{})
	release := make(chan struct{})
	var first atomic.Bool
	e.r53.OnChange(func(ctx context.Context, zoneID string) error {
		if zoneID == zoneCom && first.CompareAndSwap(false, true) {
			close(entered)
			<-release
		}
		return nil
	})
	ctx := context.Background()
	const n = 5
	errs := make(chan error, n)
	go func() {
		_, err := e.eng.Present(ctx, "order:0", names.ChallengeRecord("r0.example.com"), "v0")
		errs <- err
	}()
	<-entered
	for i := 1; i < n; i++ {
		go func() {
			_, err := e.eng.Present(ctx, fmt.Sprintf("order:%d", i), names.ChallengeRecord(fmt.Sprintf("r%d.example.com", i)), fmt.Sprintf("v%d", i))
			errs <- err
		}()
	}
	w := e.eng.writer(zoneCom)
	for deadline := time.Now().Add(10 * time.Second); w.queued() < n-1; {
		if time.Now().After(deadline) {
			t.Fatalf("queued = %d, want %d", w.queued(), n-1)
		}
		time.Sleep(time.Millisecond)
	}
	// Zone example.com is blocked inside a change; example.org proceeds.
	if _, err := e.eng.Present(ctx, "order:x", names.ChallengeRecord("x.example.org"), "vx"); err != nil {
		t.Fatalf("present in another zone while the first is busy: %v", err)
	}
	close(release)
	for range n {
		if err := <-errs; err != nil {
			t.Fatal(err)
		}
	}
	if got := e.r53.MaxConcurrentChanges(zoneCom); got != 1 {
		t.Fatalf("max concurrent changes = %d, want 1", got)
	}
	if got := e.r53.Changes(zoneCom); got != 2 {
		t.Fatalf("changes = %d, want 2 (the blocked one and one batch of %d)", got, n-1)
	}
	for i := range n {
		wantTXT(t, e.r53, names.ChallengeRecord(fmt.Sprintf("r%d.example.com", i)), fmt.Sprintf("v%d", i))
	}
}

func TestCleanupOwner(t *testing.T) {
	e := newEnv(t)
	r1, r2, r3 := names.ChallengeRecord("a.example.com"), names.ChallengeRecord("b.example.com"), names.ChallengeRecord("c.example.org")
	ids := []string{e.mustPresent("order:1", r1, "1a"), e.mustPresent("order:1", r2, "1b"), e.mustPresent("order:1", r3, "1c")}
	other := e.mustPresent("order:2", r1, "2a")
	if err := e.run(func() error { return e.eng.CleanupOwner(context.Background(), "order:1") }); err != nil {
		t.Fatal(err)
	}
	for _, id := range ids {
		if got := e.state(id).State; got != core.ChallengeDone {
			t.Fatalf("state = %s", got)
		}
	}
	wantTXT(t, e.r53, r1, "2a")
	wantTXT(t, e.r53, r2)
	wantTXT(t, e.r53, r3)
	if e.state(other).State != core.ChallengeReady {
		t.Fatal("other owner's challenge touched")
	}
	if err := e.eng.CleanupOwner(context.Background(), "order:none"); err != nil {
		t.Fatal(err)
	}
}

func TestReconcileAfterCrash(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	rec1 := names.ChallengeRecord("foo.example.com")
	rec2 := names.ChallengeRecord("bar.example.org")
	now := e.clock.Now()
	add := func(zone, rec, owner, value string, st core.ChallengeState, errText string) string {
		c := &core.Challenge{ID: core.NewID(), ZoneID: zone, RecordName: rec, Value: value, Owner: owner,
			State: st, Error: errText, CreatedAt: now, UpdatedAt: now}
		if err := e.store.Create(ctx, c); err != nil {
			t.Fatal(err)
		}
		return c.ID
	}
	// Crash state: one value recorded but never written, one written and
	// waiting, one left half-removed, one failed present half-removed, a
	// finished challenge whose value is (unexpectedly) still there, and a
	// foreign value.
	pending := add(zoneCom, rec1, "order:p", "never-written", core.ChallengePresenting, "")
	waiting := add(zoneCom, rec1, "order:w", "written", core.ChallengeWaitingDNS, "")
	cleaning := add(zoneCom, rec1, "order:c", "stale", core.ChallengeCleaning, "")
	failedPresent := add(zoneOrg, rec2, "order:f", "abandoned", core.ChallengeCleaning, presentErrPrefix+"boom")
	done := add(zoneCom, rec1, "order:d", "done-value", core.ChallengeDone, "")
	e.r53.SetTXT(rec1, "foreign", "written", "stale", "done-value")
	e.r53.SetTXT(rec2, "abandoned")

	eng := e.newEngine(time.Hour) // the restarted broker
	e.eng = eng
	if err := e.run(func() error { return eng.Reconcile(ctx) }); err != nil {
		t.Fatal(err)
	}
	// Values the broker does not own (including one of a finished
	// challenge, which it can no longer prove it owns) are kept.
	wantTXT(t, e.r53, rec1, "foreign", "written", "done-value", "never-written")
	if _, ok := e.r53.RRSet(rec2, types.RRTypeTxt); ok {
		t.Fatal("abandoned value not removed")
	}
	for id, want := range map[string]core.ChallengeState{
		pending: core.ChallengePresenting, waiting: core.ChallengeWaitingDNS,
		cleaning: core.ChallengeDone, failedPresent: core.ChallengeFailed, done: core.ChallengeDone,
	} {
		if got := e.state(id).State; got != want {
			t.Errorf("state = %s, want %s", got, want)
		}
	}
	// Resuming preparation picks up the existing challenges.
	if id := e.mustPresent("order:p", rec1, "never-written"); id != pending {
		t.Fatalf("resumed present returned %s, want %s", id, pending)
	}
	if id := e.mustPresent("order:w", rec1, "written"); id != waiting {
		t.Fatalf("resumed present returned %s, want %s", id, waiting)
	}
	if e.state(pending).State != core.ChallengeReady {
		t.Fatal("resumed challenge not ready")
	}
	// Reconcile again is a no-op.
	changes := e.r53.Changes(zoneCom)
	if err := e.run(func() error { return eng.Reconcile(ctx) }); err != nil {
		t.Fatal(err)
	}
	if e.r53.Changes(zoneCom) != changes {
		t.Fatal("second reconcile wrote to Route53")
	}
}

func TestCloseDuringPresentThenReconcile(t *testing.T) {
	e := newEnv(t)
	e.r53.SetPublicDelay(24 * time.Hour)
	rec := names.ChallengeRecord("foo.example.com")
	errc := make(chan error, 1)
	go func() {
		_, err := e.eng.Present(context.Background(), "order:1", rec, "V")
		errc <- err
	}()
	for e.r53.Changes(zoneCom) == 0 {
		time.Sleep(time.Millisecond)
	}
	if err := e.eng.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := <-errc; !errors.Is(err, ErrClosed) {
		t.Fatalf("Present after Close = %v, want ErrClosed", err)
	}
	if _, err := e.eng.Present(context.Background(), "order:2", rec, "W"); !errors.Is(err, ErrClosed) {
		t.Fatalf("new Present on closed engine = %v", err)
	}
	rows := e.store.all()
	if len(rows) != 1 || rows[0].State != core.ChallengeCleaning || rows[0].Error == "" {
		t.Fatalf("rows after close = %+v, want one cleaning challenge with its error", rows)
	}
	wantTXT(t, e.r53, rec, "V")

	eng := e.newEngine(time.Hour)
	if err := e.run(func() error { return eng.Reconcile(context.Background()) }); err != nil {
		t.Fatal(err)
	}
	wantTXT(t, e.r53, rec)
	if got := e.state(rows[0].ID).State; got != core.ChallengeFailed {
		t.Fatalf("state after reconcile = %s, want failed", got)
	}
}

func TestCleanupDuringPresentWins(t *testing.T) {
	e := newEnv(t)
	e.r53.SetPublicDelay(24 * time.Hour)
	rec := names.ChallengeRecord("foo.example.com")
	errc := make(chan error, 1)
	go func() {
		_, err := e.eng.Present(context.Background(), "order:1", rec, "V")
		errc <- err
	}()
	var id string
	for deadline := time.Now().Add(10 * time.Second); ; time.Sleep(time.Millisecond) {
		if rows := e.store.all(); len(rows) == 1 && rows[0].State == core.ChallengeWaitingDNS {
			id = rows[0].ID
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("present never reached waiting_dns")
		}
	}
	if err := e.cleanup(id); err != nil {
		t.Fatal(err)
	}
	if err := e.run(func() error { return <-errc }); !errors.Is(err, errCleanedUp) {
		t.Fatalf("Present = %v, want errCleanedUp", err)
	}
	if got := e.state(id).State; got != core.ChallengeDone {
		t.Fatalf("state = %s, want done", got)
	}
	wantTXT(t, e.r53, rec)
}

// addUnresolvedZone configures a managed zone without hosted_zone_id.
func (e *env) addUnresolvedZone(name string) {
	e.cfg.Update(func(c *core.Config) {
		c.Zones = append(slices.Clone(c.Zones), core.ZoneConfig{Name: name})
	})
}

func (e *env) zoneStatus(name string) ZoneStatus {
	e.t.Helper()
	for _, st := range e.eng.ZoneStatuses() {
		if st.Name == name {
			return st
		}
	}
	e.t.Fatalf("no status for zone %s", name)
	return ZoneStatus{}
}

func TestResolveZonesByName(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	e.addUnresolvedZone("discover.example")
	// A private zone of the same name is not a candidate.
	e.r53.AddPrivateZone("ZDISCPRIV", "discover.example")
	e.r53.AddZone("/hostedzone/ZDISC", "Discover.Example.")
	e.r53.SetZonePageSize(1) // every zone on its own page
	if err := e.eng.ResolveZones(ctx); err != nil {
		t.Fatal(err)
	}
	if got, want := e.zoneStatus("discover.example"), (ZoneStatus{Name: "discover.example", HostedZoneID: "ZDISC", Resolved: true}); got != want {
		t.Fatalf("status = %+v, want %+v", got, want)
	}
	if got := e.r53.Calls(OpListZones); got != 5 {
		t.Fatalf("ListHostedZones calls = %d, want one per zone (5) with page size 1", got)
	}
	// Configured IDs are reported as such and never looked up.
	if got, want := e.zoneStatus("example.com"), (ZoneStatus{Name: "example.com", HostedZoneID: zoneCom}); got != want {
		t.Fatalf("status = %+v, want %+v", got, want)
	}
	if z, _ := e.cfg.Current().ZoneFor("h.discover.example"); z.HostedZoneID != "" {
		t.Fatal("the configuration must stay as written")
	}

	// A second public zone of the same name makes the name ambiguous.
	e.r53.AddZone("ZDISC2", "discover.example")
	err := e.eng.ResolveZones(ctx)
	if err == nil || !strings.Contains(err.Error(), "several public hosted zones named discover.example") {
		t.Fatalf("ResolveZones = %v, want ambiguity error", err)
	}
	if st := e.zoneStatus("discover.example"); st.HostedZoneID != "" || !strings.Contains(st.Err, "set hosted_zone_id") {
		t.Fatalf("status after ambiguity = %+v", st)
	}
	if _, err := e.present("o", "_acme-challenge.h.discover.example", "v"); err == nil || !strings.Contains(err.Error(), "several public hosted zones") {
		t.Fatalf("Present on an ambiguous zone = %v", err)
	}

	// No public zone at all.
	e.cfg.Update(func(c *core.Config) { c.Zones = []core.ZoneConfig{{Name: "nowhere.example"}} })
	err = e.eng.ResolveZones(ctx)
	if err == nil || !strings.Contains(err.Error(), "no public hosted zone named nowhere.example") {
		t.Fatalf("ResolveZones = %v, want not-found error", err)
	}
	if got := e.eng.ZoneStatuses(); len(got) != 1 || got[0].HostedZoneID != "" {
		t.Fatalf("statuses = %+v; the dropped zone must be forgotten", got)
	}
}

func TestPresentResolvesZoneByName(t *testing.T) {
	e := newEnv(t)
	e.addUnresolvedZone("discover.example")
	e.r53.AddZone("ZDISC", "discover.example")
	rec := "_acme-challenge.host.discover.example"
	id := e.mustPresent("o1", rec, "v1")
	if got := e.state(id).ZoneID; got != "ZDISC" {
		t.Fatalf("challenge zone = %s, want the discovered ZDISC", got)
	}
	wantTXT(t, e.r53, rec, "v1")
	if got := e.r53.Changes("ZDISC"); got != 1 {
		t.Fatalf("changes in ZDISC = %d, want 1", got)
	}
	if e.cleanup(id) != nil {
		t.Fatal("cleanup")
	}
	wantTXT(t, e.r53, rec)
	// One listing served both the discovery and the later lookups.
	if got := e.r53.Calls(OpListZones); got != 1 {
		t.Fatalf("ListHostedZones calls = %d, want 1", got)
	}
}

func TestResolveZonesRetriesLazilyAfterFailure(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	e.addUnresolvedZone("discover.example")
	e.r53.AddZone("ZDISC", "discover.example")
	e.r53.Fail(OpListZones, &types.InvalidInput{Message: aws.String("denied")}, 1)
	if err := e.eng.VerifyZones(ctx); err == nil || !strings.Contains(err.Error(), "denied") {
		t.Fatalf("VerifyZones = %v, want the listing error", err)
	}
	if st := e.zoneStatus("discover.example"); st.HostedZoneID != "" || !strings.Contains(st.Err, "denied") {
		t.Fatalf("status after failure = %+v", st)
	}
	// The next Present resolves the zone itself.
	rec := "_acme-challenge.host.discover.example"
	e.mustPresent("o1", rec, "v1")
	wantTXT(t, e.r53, rec, "v1")
	if st := e.zoneStatus("discover.example"); st.HostedZoneID != "ZDISC" || !st.Resolved || st.Err != "" {
		t.Fatalf("status after lazy resolution = %+v", st)
	}
	// A failing listing on a later configuration change keeps the result.
	e.r53.Fail(OpListZones, &types.InvalidInput{Message: aws.String("denied")}, 1)
	if err := e.eng.ResolveZones(ctx); err != nil {
		t.Fatalf("ResolveZones with a known zone = %v, want nil", err)
	}
	if st := e.zoneStatus("discover.example"); st.HostedZoneID != "ZDISC" {
		t.Fatalf("status lost through a transient failure: %+v", st)
	}
	// An explicit ID replaces the discovered one.
	e.cfg.Update(func(c *core.Config) {
		c.Zones[len(c.Zones)-1].HostedZoneID = "ZEXPLICIT"
	})
	if st := e.zoneStatus("discover.example"); st.HostedZoneID != "ZEXPLICIT" || st.Resolved {
		t.Fatalf("status with explicit ID = %+v", st)
	}
}

// Concurrent Present calls on an unresolved zone share one listing.
func TestResolveZonesNoStampede(t *testing.T) {
	e := newEnv(t)
	e.addUnresolvedZone("discover.example")
	e.r53.AddZone("ZDISC", "discover.example")
	const n = 8
	errs := make([]error, n)
	err := e.run(func() error {
		var wg sync.WaitGroup
		for i := range n {
			wg.Go(func() {
				_, errs[i] = e.eng.Present(context.Background(), "o", fmt.Sprintf("_acme-challenge.h%d.discover.example", i), "v")
			})
		}
		wg.Wait()
		return errors.Join(errs...)
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := e.r53.Calls(OpListZones); got != 1 {
		t.Fatalf("ListHostedZones calls = %d, want 1", got)
	}
}

func TestVerifyZonesMixedIDs(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	e.addUnresolvedZone("discover.example")
	e.r53.AddZone("ZDISC", "discover.example")
	if err := e.eng.VerifyZones(ctx); err != nil {
		t.Fatal(err)
	}
	want := map[string]ZoneStatus{
		"example.com":      {Name: "example.com", HostedZoneID: zoneCom},
		"example.org":      {Name: "example.org", HostedZoneID: zoneOrg},
		"sub.example.com":  {Name: "sub.example.com", HostedZoneID: zoneSub},
		"discover.example": {Name: "discover.example", HostedZoneID: "ZDISC", Resolved: true},
	}
	got := e.eng.ZoneStatuses()
	if len(got) != len(want) {
		t.Fatalf("statuses = %+v", got)
	}
	for _, st := range got {
		if st != want[st.Name] {
			t.Fatalf("status %+v, want %+v", st, want[st.Name])
		}
	}
	// A discovered zone is verified like a configured one: here the
	// listing finds it but GetHostedZone fails.
	e.r53.Fail(OpGetHostedZone, &types.InvalidInput{Message: aws.String("denied")}, len(want))
	if err := e.eng.VerifyZones(ctx); err == nil || !strings.Contains(err.Error(), "ZDISC") {
		t.Fatalf("VerifyZones = %v, want a GetHostedZone failure naming ZDISC", err)
	}
}

func TestVerifyZones(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	if err := e.eng.VerifyZones(ctx); err != nil {
		t.Fatal(err)
	}
	e.cfg.Update(func(c *core.Config) {
		c.Zones = append(slices.Clone(c.Zones), core.ZoneConfig{Name: "wrong.example", HostedZoneID: zoneOrg})
	})
	if err := e.eng.VerifyZones(ctx); err == nil {
		t.Fatal("zone name mismatch not detected")
	}
	e.r53.AddPrivateZone("ZPRIV", "private.example")
	e.cfg.Update(func(c *core.Config) {
		c.Zones = []core.ZoneConfig{{Name: "private.example", HostedZoneID: "ZPRIV"}}
	})
	if err := e.eng.VerifyZones(ctx); err == nil {
		t.Fatal("private zone not detected")
	}
	e.cfg.Update(func(c *core.Config) {
		c.Zones = []core.ZoneConfig{{Name: "missing.example", HostedZoneID: "ZNONE"}}
	})
	if err := e.eng.VerifyZones(ctx); err == nil {
		t.Fatal("missing zone not detected")
	}
}
