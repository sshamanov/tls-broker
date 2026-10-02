package coretest

import (
	"context"
	"errors"
	"net/netip"
	"reflect"
	"sync"
	"testing"
	"time"

	"tls-broker/internal/core"
	"tls-broker/internal/names"
)

var ctx = context.Background()

// ---- FakeClock ------------------------------------------------------------

func TestFakeClockTimersFireInOrder(t *testing.T) {
	start := At(2026, 5, 1)
	c := NewFakeClock(start)
	if !c.Now().Equal(start) {
		t.Fatal("start time")
	}
	late := c.After(30 * time.Second)
	early := c.After(10 * time.Second)
	same := c.After(10 * time.Second)
	if c.Pending() != 3 {
		t.Fatalf("Pending = %d", c.Pending())
	}

	c.Advance(9 * time.Second)
	select {
	case <-early:
		t.Fatal("timer fired early")
	default:
	}
	c.Advance(time.Second)
	if got := <-early; !got.Equal(start.Add(10 * time.Second)) {
		t.Fatalf("early fired with %s", got)
	}
	if got := <-same; !got.Equal(start.Add(10 * time.Second)) {
		t.Fatalf("same fired with %s", got)
	}
	select {
	case <-late:
		t.Fatal("late timer fired")
	default:
	}
	// One big jump fires the rest and carries the deadline, not the target.
	c.Advance(time.Hour)
	if got := <-late; !got.Equal(start.Add(30 * time.Second)) {
		t.Fatalf("late fired with %s", got)
	}
	if c.Pending() != 0 || !c.Now().Equal(start.Add(time.Hour+10*time.Second)) {
		t.Fatalf("after advance: pending=%d now=%s", c.Pending(), c.Now())
	}
}

func TestFakeClockImmediateAndSet(t *testing.T) {
	c := NewFakeClock()
	if !c.Now().Equal(At(2026, 1, 1, 12)) {
		t.Fatalf("default start = %s", c.Now())
	}
	select {
	case <-c.After(0):
	default:
		t.Fatal("After(0) must fire immediately")
	}
	select {
	case <-c.After(-time.Second):
	default:
		t.Fatal("After(negative) must fire immediately")
	}
	ch := c.After(time.Minute)
	c.Set(c.Now().Add(-time.Hour))
	select {
	case <-ch:
		t.Fatal("moving backwards fired a timer")
	default:
	}
	c.Set(At(2026, 1, 2))
	select {
	case <-ch:
	default:
		t.Fatal("Set past the deadline must fire")
	}
}

func TestFakeClockBlockUntilAndSleep(t *testing.T) {
	c := NewFakeClock()
	if c.BlockUntil(1, 20*time.Millisecond) {
		t.Fatal("BlockUntil returned true with no timers")
	}
	done := make(chan error, 1)
	go func() { done <- core.Sleep(ctx, c, time.Minute) }()
	if !c.BlockUntil(1, 5*time.Second) {
		t.Fatal("sleeper never armed its timer")
	}
	select {
	case <-done:
		t.Fatal("Sleep returned before the clock moved")
	default:
	}
	c.Advance(time.Minute)
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Sleep did not return after Advance")
	}
}

func TestFakeClockConcurrentUse(t *testing.T) {
	c := NewFakeClock()
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-c.After(time.Second)
		}()
	}
	if !c.BlockUntil(20, 5*time.Second) {
		t.Fatal("timers not armed")
	}
	c.Advance(time.Second)
	wg.Wait()
}

// ---- FakeResolver ---------------------------------------------------------

func TestFakeResolverLookups(t *testing.T) {
	r := NewFakeResolver()
	r.SetA("Host.Example.com.", "192.0.2.10", "192.0.2.11")
	r.SetCNAME("alias.example.com", "mid.example.com")
	r.SetCNAME("mid.example.com", "host.example.com")
	r.SetTXT("_acme-challenge.host.example.com", "v1")
	r.AddTXT("_acme-challenge.host.example.com", "v2")
	r.AddTXT("_acme-challenge.host.example.com", "v2")
	r.SetCAA("example.com", core.CAA{Tag: "issue", Value: "primary.test"})

	got, err := r.LookupA(ctx, "host.example.com")
	want := []netip.Addr{netip.MustParseAddr("192.0.2.10"), netip.MustParseAddr("192.0.2.11")}
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("LookupA = %v, %v", got, err)
	}
	got, err = r.LookupA(ctx, "ALIAS.example.com")
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("LookupA via CNAME chain = %v, %v", got, err)
	}
	got, err = r.LookupA(ctx, "missing.example.com")
	if err != nil || len(got) != 0 {
		t.Fatalf("NXDOMAIN must be empty with nil error: %v, %v", got, err)
	}
	txt, err := r.LookupTXT(ctx, "_acme-challenge.host.example.com")
	if err != nil || !reflect.DeepEqual(txt, []string{"v1", "v2"}) {
		t.Fatalf("LookupTXT = %v, %v", txt, err)
	}
	r.RemoveTXT("_acme-challenge.host.example.com", "v1")
	txt, _ = r.LookupTXT(ctx, "_acme-challenge.host.example.com")
	if !reflect.DeepEqual(txt, []string{"v2"}) {
		t.Fatalf("after RemoveTXT = %v", txt)
	}
	caa, err := r.LookupCAA(ctx, "example.com")
	if err != nil || len(caa) != 1 || caa[0].Tag != "issue" {
		t.Fatalf("LookupCAA = %v, %v", caa, err)
	}
	// CAA is per node: no climbing.
	caa, err = r.LookupCAA(ctx, "host.example.com")
	if err != nil || len(caa) != 0 {
		t.Fatalf("LookupCAA must not climb: %v, %v", caa, err)
	}
	if r.Calls("A") != 3 || r.Calls("TXT") != 2 || r.Calls("CAA") != 2 || r.Calls("") != 7 {
		t.Fatalf("call counts: A=%d TXT=%d CAA=%d", r.Calls("A"), r.Calls("TXT"), r.Calls("CAA"))
	}
	// Returned slices are copies.
	got, _ = r.LookupA(ctx, "host.example.com")
	got[0] = netip.MustParseAddr("203.0.113.1")
	again, _ := r.LookupA(ctx, "host.example.com")
	if again[0] != want[0] {
		t.Fatal("caller could modify the resolver's table")
	}
}

func TestFakeResolverLoopsAndFailures(t *testing.T) {
	r := NewFakeResolver()
	r.SetCNAME("a.example.com", "b.example.com")
	r.SetCNAME("b.example.com", "a.example.com")
	if _, err := r.LookupA(ctx, "a.example.com"); !errors.Is(err, core.ErrResolver) {
		t.Fatalf("CNAME loop: %v", err)
	}
	r2 := NewFakeResolver()
	r2.MaxCNAMEHops = 2
	r2.SetCNAME("c1.example.com", "c2.example.com")
	r2.SetCNAME("c2.example.com", "c3.example.com")
	r2.SetCNAME("c3.example.com", "c4.example.com")
	r2.SetA("c4.example.com", "192.0.2.1")
	if _, err := r2.LookupA(ctx, "c1.example.com"); !errors.Is(err, core.ErrResolver) {
		t.Fatalf("long chain: %v", err)
	}
	if got, err := r2.LookupA(ctx, "c2.example.com"); err != nil || len(got) != 1 {
		t.Fatalf("chain within the limit: %v, %v", got, err)
	}

	r.SetA("x.example.com", "192.0.2.1")
	r.Fail("x.example.com", core.ErrResolver)
	if _, err := r.LookupA(ctx, "x.example.com"); !errors.Is(err, core.ErrResolver) {
		t.Fatalf("Fail: %v", err)
	}
	if _, err := r.LookupTXT(ctx, "X.example.com."); !errors.Is(err, core.ErrResolver) {
		t.Fatalf("Fail applies to all types and spellings: %v", err)
	}
	r.Fail("x.example.com", nil)
	if got, err := r.LookupA(ctx, "x.example.com"); err != nil || len(got) != 1 {
		t.Fatalf("after clearing Fail: %v, %v", got, err)
	}
	boom := errors.New("boom")
	r.FailAll(boom)
	if _, err := r.LookupCAA(ctx, "anything.example.com"); !errors.Is(err, boom) {
		t.Fatalf("FailAll: %v", err)
	}
	r.FailAll(nil)
	cctx, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := r.LookupA(cctx, "x.example.com"); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled ctx: %v", err)
	}
}

// ---- FakeDNSEngine --------------------------------------------------------

func TestFakeDNSEngineSharedRecord(t *testing.T) {
	r := NewFakeResolver()
	clock := NewFakeClock()
	e := NewFakeDNSEngine(r, clock)
	rec := "_acme-challenge.example.com"

	id1, err := e.Present(ctx, "order:1", rec, "A")
	if err != nil {
		t.Fatal(err)
	}
	id2, err := e.Present(ctx, "order:2", rec, "B")
	if err != nil || id2 == id1 {
		t.Fatalf("second present: %q, %v", id2, err)
	}
	// Idempotent per (owner, record, value).
	again, err := e.Present(ctx, "order:1", rec, "A")
	if err != nil || again != id1 {
		t.Fatalf("idempotent present = %q, %v; want %q", again, err, id1)
	}
	if got := e.Active(rec); !reflect.DeepEqual(got, []string{"A", "B"}) {
		t.Fatalf("Active = %v", got)
	}
	txt, _ := r.LookupTXT(ctx, rec)
	if !reflect.DeepEqual(txt, []string{"A", "B"}) {
		t.Fatalf("resolver TXT = %v", txt)
	}

	if err := e.Cleanup(ctx, id1); err != nil {
		t.Fatal(err)
	}
	if err := e.Cleanup(ctx, id1); err != nil {
		t.Fatalf("Cleanup must be idempotent: %v", err)
	}
	txt, _ = r.LookupTXT(ctx, rec)
	if !reflect.DeepEqual(txt, []string{"B"}) {
		t.Fatalf("cleanup removed another challenge's value: %v", txt)
	}
	if err := e.Cleanup(ctx, "nope"); !errors.Is(err, core.ErrNotFound) {
		t.Fatalf("unknown challenge: %v", err)
	}
	// After cleanup the same triple is a new challenge.
	id3, _ := e.Present(ctx, "order:1", rec, "A")
	if id3 == id1 {
		t.Fatal("terminal challenge was reused")
	}
	if e.ActiveCount() != 2 {
		t.Fatalf("ActiveCount = %d", e.ActiveCount())
	}
	chs := e.Challenges()
	if len(chs) != 3 || chs[0].State != core.ChallengeDone || chs[1].State != core.ChallengeReady || !chs[0].CreatedAt.Equal(clock.Now()) {
		t.Fatalf("Challenges = %+v", chs)
	}
	p, c, _ := e.Calls()
	if p != 4 || c != 3 {
		t.Fatalf("Calls = %d, %d", p, c)
	}
}

func TestFakeDNSEngineSameValueTwoOwners(t *testing.T) {
	r := NewFakeResolver()
	e := NewFakeDNSEngine(r, nil)
	rec := "_acme-challenge.example.com"
	a, _ := e.Present(ctx, "order:1", rec, "V")
	b, _ := e.Present(ctx, "order:2", rec, "V")
	if a == b {
		t.Fatal("different owners must get different challenges")
	}
	_ = e.Cleanup(ctx, a)
	if txt, _ := r.LookupTXT(ctx, rec); !reflect.DeepEqual(txt, []string{"V"}) {
		t.Fatalf("value removed while another owner still needs it: %v", txt)
	}
	_ = e.Cleanup(ctx, b)
	if txt, _ := r.LookupTXT(ctx, rec); len(txt) != 0 {
		t.Fatalf("value left behind: %v", txt)
	}
}

func TestFakeDNSEngineOwnerZonesHooks(t *testing.T) {
	e := NewFakeDNSEngine(nil, nil)
	z, _ := names.NewZones("example.com")
	e.SetZones(z)
	if _, err := e.Present(ctx, "o", "_acme-challenge.a.example.net", "v"); !errors.Is(err, core.ErrOutsideManagedZones) {
		t.Fatalf("outside zone: %v", err)
	}
	if len(e.Challenges()) != 0 {
		t.Fatal("challenge created for a name outside managed zones")
	}
	_, _ = e.Present(ctx, "order:1", "_acme-challenge.a.example.com", "1")
	_, _ = e.Present(ctx, "order:1", "_acme-challenge.b.example.com", "2")
	_, _ = e.Present(ctx, "order:2", "_acme-challenge.c.example.com", "3")
	if err := e.CleanupOwner(ctx, "order:1"); err != nil {
		t.Fatal(err)
	}
	if e.ActiveCount() != 1 {
		t.Fatalf("CleanupOwner left %d active", e.ActiveCount())
	}
	if err := e.CleanupOwner(ctx, "order:none"); err != nil {
		t.Fatalf("CleanupOwner with nothing to do: %v", err)
	}

	e.OnPresent(func(context.Context, string, string, string) error { return core.ErrDNSPropagation })
	if _, err := e.Present(ctx, "o", "_acme-challenge.d.example.com", "v"); !errors.Is(err, core.ErrDNSPropagation) {
		t.Fatalf("present hook: %v", err)
	}
	if e.ActiveCount() != 1 {
		t.Fatal("failed present left a challenge")
	}
	e.OnPresent(nil)
	id, _ := e.Present(ctx, "o", "_acme-challenge.d.example.com", "v")
	boom := errors.New("route53 down")
	e.OnCleanup(func(context.Context, core.Challenge) error { return boom })
	if err := e.Cleanup(ctx, id); !errors.Is(err, boom) {
		t.Fatalf("cleanup hook: %v", err)
	}
	if got := e.Active("_acme-challenge.d.example.com"); len(got) != 1 {
		t.Fatal("failed cleanup must leave the value")
	}
	if err := e.CleanupOwner(ctx, "o"); !errors.Is(err, boom) {
		t.Fatalf("CleanupOwner must report the failure: %v", err)
	}
	e.OnCleanup(nil)
	if err := e.Reconcile(ctx); err != nil {
		t.Fatal(err)
	}
	if _, _, rc := e.Calls(); rc != 1 {
		t.Fatalf("reconcile calls = %d", rc)
	}
}

// ---- small fakes ----------------------------------------------------------

func TestFakeDirectory(t *testing.T) {
	d := NewFakeDirectory()
	d.SetUser("alice", "secret")
	if err := d.Authenticate(ctx, "alice", "secret"); err != nil {
		t.Fatal(err)
	}
	for _, c := range [][2]string{{"alice", "wrong"}, {"alice", ""}, {"bob", "secret"}, {"Alice", "secret"}} {
		if err := d.Authenticate(ctx, c[0], c[1]); !errors.Is(err, core.ErrInvalidCredentials) {
			t.Errorf("Authenticate(%q, %q) = %v", c[0], c[1], err)
		}
	}
	d.SetDown(true)
	if err := d.Authenticate(ctx, "alice", "secret"); !errors.Is(err, core.ErrDirectoryUnavailable) {
		t.Fatalf("down directory: %v", err)
	}
	d.SetDown(false)
	d.RemoveUser("alice")
	if err := d.Authenticate(ctx, "alice", "secret"); !errors.Is(err, core.ErrInvalidCredentials) {
		t.Fatalf("removed user: %v", err)
	}
	if d.Calls() != 7 {
		t.Fatalf("Calls = %d", d.Calls())
	}
}

func TestFakeAuditor(t *testing.T) {
	clock := NewFakeClock()
	a := NewFakeAuditor(clock)
	set := []string{"a.example.com"}
	a.Record(ctx, core.AuditEvent{Type: core.AuditGate, Names: set, Decision: core.AuditDecisionAllow})
	explicit := At(2025, 1, 1)
	a.Record(ctx, core.AuditEvent{Type: core.AuditIssue, Time: explicit})
	set[0] = "changed"
	evs := a.Events()
	if len(evs) != 2 || !evs[0].Time.Equal(clock.Now()) || !evs[1].Time.Equal(explicit) || evs[0].Names[0] != "a.example.com" {
		t.Fatalf("events = %+v", evs)
	}
	if got := a.OfType(core.AuditIssue); len(got) != 1 {
		t.Fatalf("OfType = %+v", got)
	}
	a.Reset()
	if len(a.Events()) != 0 {
		t.Fatal("Reset")
	}
}

func TestFakeGate(t *testing.T) {
	g := NewFakeGate()
	src := netip.MustParseAddr("192.0.2.5")
	set := names.MustSet("a.example.com")
	d, err := g.Authorize(ctx, core.ModeACME, src, set)
	if err != nil || !d.Allowed || d.Reason != core.ReasonDNSIPMatch {
		t.Fatalf("default decision = %+v, %v", d, err)
	}
	g.Decide(core.Decision{Reason: core.ReasonWildcardGrantRequired})
	d, _ = g.Authorize(ctx, core.ModeDirect, src, set)
	if d.Allowed || d.Reason != core.ReasonWildcardGrantRequired {
		t.Fatalf("scripted decision = %+v", d)
	}
	calls := g.Calls()
	if len(calls) != 2 || calls[1].Mode != core.ModeDirect || calls[0].Source != src || !calls[0].Names.Equal(set) {
		t.Fatalf("calls = %+v", calls)
	}
}

func TestFakeScheduler(t *testing.T) {
	s := NewFakeScheduler()
	req := core.AdmissionRequest{Ref: "o1", Provider: "primary", Names: names.MustSet("a.example.com"), Class: core.ClassACMEOrdinary}
	tk, err := s.Acquire(ctx, req)
	if err != nil || tk.Ref() != "o1" {
		t.Fatalf("Acquire: %v", err)
	}
	if _, err := s.Acquire(ctx, req); !errors.Is(err, core.ErrConflict) {
		t.Fatalf("second Acquire for an open Ref: %v", err)
	}
	if refs, _ := s.OpenRefs(ctx); !reflect.DeepEqual(refs, []string{"o1"}) {
		t.Fatalf("OpenRefs = %v", refs)
	}
	re, err := s.Reattach(ctx, "o1")
	if err != nil {
		t.Fatal(err)
	}
	re.OrderCreated()
	tk.PrepDone()
	tk.Commit()
	tk.Refund() // first settlement wins
	tk.Commit()
	rec, ok := s.Record("o1")
	if !ok || !rec.OrderCreated || !rec.PrepDone || !rec.Committed || rec.Refunded {
		t.Fatalf("record = %+v", rec)
	}
	if _, err := s.Reattach(ctx, "o1"); !errors.Is(err, core.ErrNotFound) {
		t.Fatalf("Reattach on a settled Ref: %v", err)
	}
	if _, err := s.Reattach(ctx, "never"); !errors.Is(err, core.ErrNotFound) {
		t.Fatalf("Reattach on an unknown Ref: %v", err)
	}
	if refs, _ := s.OpenRefs(ctx); len(refs) != 0 {
		t.Fatalf("OpenRefs after settlement = %v", refs)
	}

	refusal := &core.AdmissionError{Kind: core.AdmissionRateLimited, Provider: "primary", RetryAfter: time.Hour}
	s.Refuse("primary", refusal)
	if _, err := s.Acquire(ctx, core.AdmissionRequest{Ref: "o2", Provider: "primary"}); core.AsAdmissionError(err) != refusal {
		t.Fatalf("refusal: %v", err)
	}
	tk2, err := s.Acquire(ctx, core.AdmissionRequest{Ref: "o2", Provider: "fallback"})
	if err != nil {
		t.Fatalf("other provider must admit: %v", err)
	}
	tk2.Refund()
	if rec, _ := s.Record("o2"); !rec.Refunded || rec.Committed || rec.OrderCreated {
		t.Fatalf("refund record = %+v", rec)
	}
	s.Refuse("primary", nil)
	if _, err := s.Acquire(ctx, core.AdmissionRequest{Ref: "o3", Provider: "primary"}); err != nil {
		t.Fatal(err)
	}
	if len(s.Records()) != 3 {
		t.Fatalf("Records = %+v", s.Records())
	}

	down := &core.ProviderError{Provider: "primary", Kind: core.ProviderDown}
	s.ReportProvider(ctx, "primary", down)
	s.ReportProvider(ctx, "primary", nil)
	if r := s.Reports(); len(r) != 2 || r[0].Err != down || r[1].Err != nil {
		t.Fatalf("Reports = %+v", r)
	}
	snap := core.SchedulerSnapshot{Providers: []core.ProviderSnapshot{{Name: "primary", Open: true}}}
	s.SetSnapshot(snap)
	if got := s.Snapshot(); len(got.Providers) != 1 || got.Providers[0].Name != "primary" {
		t.Fatalf("Snapshot = %+v", got)
	}
}

func TestFakeProvidersConfigSecrets(t *testing.T) {
	clock := NewFakeClock()
	p1, p2 := NewFakeCA("primary", clock), NewFakeCA("fallback", clock)
	reg := NewFakeProviders(p1, p2)
	if got, ok := reg.Get("fallback"); !ok || got.Name() != "fallback" {
		t.Fatal("Get")
	}
	if _, ok := reg.Get("nope"); ok {
		t.Fatal("Get unknown")
	}
	reg.SetDisabled("primary", true)
	if en := reg.Enabled(); len(en) != 1 || en[0].Name() != "fallback" {
		t.Fatalf("Enabled = %v", en)
	}
	if _, ok := reg.Get("primary"); !ok {
		t.Fatal("disabled provider must still be returned by Get")
	}

	cfg := NewFakeConfig(nil)
	cur := cfg.Current()
	if _, ok := cur.ZoneFor("a.example.com"); !ok || len(cur.EnabledProviders()) != 2 {
		t.Fatalf("fixture config: %+v", cur)
	}
	for _, pc := range cur.Providers {
		ca, _ := reg.Get(pc.Name)
		if !reflect.DeepEqual(ca.Caps().CAAIssuers, pc.CAAIssuers) {
			t.Errorf("fixture provider %s CAA issuers differ from the FakeCA's", pc.Name)
		}
	}
	ch, cancel := cfg.Subscribe()
	select {
	case <-ch:
		t.Fatal("notification without a change")
	default:
	}
	cfg.Update(func(c *core.Config) { c.Scheduler.AdmitWait = time.Second })
	cfg.Update(func(c *core.Config) { c.Scheduler.AdmitWait = 2 * time.Second })
	<-ch // coalesced
	select {
	case <-ch:
		t.Fatal("notifications must coalesce")
	default:
	}
	if cfg.Current().Scheduler.AdmitWait != 2*time.Second || cur.Scheduler.AdmitWait != 20*time.Second {
		t.Fatal("Update must publish a copy and leave the old config untouched")
	}
	cancel()
	cancel()
	if _, open := <-ch; open {
		t.Fatal("cancel must close the channel")
	}
	cfg.Set(NewConfig()) // must not panic after cancel

	sec := NewFakeSecrets()
	if _, err := sec.Get(ctx, "x"); !errors.Is(err, core.ErrNotFound) {
		t.Fatalf("missing secret: %v", err)
	}
	_ = sec.Put(ctx, "b", []byte("2"))
	_ = sec.Put(ctx, "a", []byte("1"))
	if l, _ := sec.List(ctx); !reflect.DeepEqual(l, []string{"a", "b"}) {
		t.Fatalf("List = %v", l)
	}
	v, _ := sec.Get(ctx, "a")
	v[0] = 'X'
	if v2, _ := sec.Get(ctx, "a"); string(v2) != "1" {
		t.Fatal("Get must return a copy")
	}
	if err := sec.Delete(ctx, "a"); err != nil {
		t.Fatal(err)
	}
	if err := sec.Delete(ctx, "a"); err != nil {
		t.Fatalf("Delete of a missing secret: %v", err)
	}
}

func TestKeysAndCSR(t *testing.T) {
	der := MakeCSR(GenKey(), "a.example.com", "b.example.com")
	if core.CSRHash(der) == core.CSRHash(MakeCSR(GenKey(), "a.example.com", "b.example.com")) {
		t.Fatal("CSRs from different keys must differ")
	}
	if _, err := ParseChain([]byte("not pem")); err == nil {
		t.Fatal("ParseChain accepted garbage")
	}
	if GenRSAKey().N.BitLen() != 2048 {
		t.Fatal("RSA key size")
	}
}
