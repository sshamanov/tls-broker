package store

import (
	"net/netip"
	"reflect"
	"testing"
	"time"

	"tls-broker/internal/core"
)

func TestLineages(t *testing.T) {
	s := open(t)
	ls := s.Lineages()
	_, err := ls.Get(ctx, "a.example.com")
	wantErr(t, err, core.ErrNotFound)

	want := core.Lineage{Key: "a.example.com"}
	for _, at := range []time.Time{
		t0,
		t0.Add(10 * time.Minute), // same visit: ignored
		t0.Add(24 * time.Hour),
		t0.Add(48 * time.Hour),
		t0.Add(47 * time.Hour), // negative gap: ignored
		t0.Add(9 * 24 * time.Hour),
	} {
		want = want.Observe(at)
		got, err := ls.Observe(ctx, "a.example.com", at)
		must(t, err)
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("Observe(%v) = %+v, want %+v", at, got, want)
		}
		stored, err := ls.Get(ctx, "a.example.com")
		must(t, err)
		if !reflect.DeepEqual(*stored, want) {
			t.Fatalf("stored %+v, want %+v", stored, want)
		}
	}
	if want.Samples != 3 {
		t.Fatalf("fixture produced %d samples", want.Samples)
	}
	other, err := ls.Observe(ctx, "b.example.com", t0)
	must(t, err)
	if other.Samples != 0 || !other.LastRequestAt.Equal(t0) {
		t.Fatalf("independent lineage %+v", other)
	}
}

func TestChallenges(t *testing.T) {
	s := open(t)
	cs := s.Challenges()
	mk := func(id, zone, record, value, owner string, created time.Time) *core.Challenge {
		c := &core.Challenge{ID: id, ZoneID: zone, RecordName: record, Value: value, Owner: owner,
			State: core.ChallengePending, CreatedAt: created, UpdatedAt: created}
		must(t, cs.Create(ctx, c))
		return c
	}
	rec := "_acme-challenge.foo.example.com"
	a := mk("a", "Z1", rec, "v1", "order:o1", t0)
	mk("b", "Z1", rec, "v2", "order:o2", t0.Add(time.Second))
	mk("c", "Z1", "_acme-challenge.bar.example.com", "v3", "dnsproxy:10.0.0.1", t0.Add(2*time.Second))
	mk("d", "Z2", rec, "v4", "dnsproxy:10.0.0.1", t0.Add(3*time.Second))

	got, err := cs.Get(ctx, "a")
	must(t, err)
	if !reflect.DeepEqual(got, a) {
		t.Fatalf("Get %+v", got)
	}
	wantErr(t, cs.Create(ctx, a), core.ErrConflict)
	if err := cs.Create(ctx, &core.Challenge{ID: "z", State: "weird"}); err == nil {
		t.Fatal("invalid state accepted")
	}
	_, err = cs.Get(ctx, "zz")
	wantErr(t, err, core.ErrNotFound)

	ids := func(list []core.Challenge) []string {
		out := []string{}
		for _, c := range list {
			out = append(out, c.ID)
		}
		return out
	}
	check := func(name string, list []core.Challenge, err error, want ...string) {
		t.Helper()
		must(t, err)
		if want == nil {
			want = []string{}
		}
		if !reflect.DeepEqual(ids(list), want) {
			t.Fatalf("%s = %v, want %v", name, ids(list), want)
		}
	}

	// Walk "a" through the states the engine uses.
	for i, st := range []core.ChallengeState{core.ChallengePresenting, core.ChallengeWaitingDNS, core.ChallengeReady,
		core.ChallengeCleaning} {
		must(t, cs.SetState(ctx, "a", st, "", t0.Add(time.Duration(i+1)*time.Minute)))
	}
	got, _ = cs.Get(ctx, "a")
	if got.State != core.ChallengeCleaning || !got.UpdatedAt.Equal(t0.Add(4*time.Minute)) {
		t.Fatalf("after transitions %+v", got)
	}
	// Back from cleaning to ready is allowed (any non-terminal transition).
	must(t, cs.SetState(ctx, "a", core.ChallengeReady, "", t0.Add(5*time.Minute)))

	l, err := cs.ListActive(ctx)
	check("ListActive", l, err, "a", "b", "c", "d")
	l, err = cs.ListByRecord(ctx, "Z1", rec)
	check("ListByRecord", l, err, "a", "b")
	l, err = cs.ListByOwner(ctx, "dnsproxy:10.0.0.1")
	check("ListByOwner", l, err, "c", "d")
	l, err = cs.ListStale(ctx, t0.Add(2*time.Second))
	check("ListStale", l, err, "a", "b")
	f, err := cs.FindActive(ctx, "order:o2", rec, "v2")
	must(t, err)
	if f.ID != "b" {
		t.Fatalf("FindActive %s", f.ID)
	}

	// Terminal states.
	must(t, cs.SetState(ctx, "b", core.ChallengeFailed, "route53 timeout", t0.Add(time.Hour)))
	got, _ = cs.Get(ctx, "b")
	if got.State != core.ChallengeFailed || got.Error != "route53 timeout" {
		t.Fatalf("failed challenge %+v", got)
	}
	wantErr(t, cs.SetState(ctx, "b", core.ChallengeCleaning, "", t0.Add(2*time.Hour)), core.ErrConflict)
	wantErr(t, cs.SetState(ctx, "b", core.ChallengeDone, "", t0.Add(2*time.Hour)), core.ErrConflict)
	must(t, cs.SetState(ctx, "b", core.ChallengeFailed, "again", t0.Add(2*time.Hour))) // repeat: no change
	got, _ = cs.Get(ctx, "b")
	if got.Error != "route53 timeout" || !got.UpdatedAt.Equal(t0.Add(time.Hour)) {
		t.Fatalf("repeated terminal state changed the row: %+v", got)
	}
	wantErr(t, cs.SetState(ctx, "nope", core.ChallengeDone, "", t0), core.ErrNotFound)
	if err := cs.SetState(ctx, "a", "bogus", "", t0); err == nil {
		t.Fatal("invalid state accepted")
	}
	_, err = cs.FindActive(ctx, "order:o2", rec, "v2")
	wantErr(t, err, core.ErrNotFound)
	l, err = cs.ListByRecord(ctx, "Z1", rec)
	check("ListByRecord after failure", l, err, "a")
	must(t, cs.SetState(ctx, "a", core.ChallengeDone, "", t0.Add(3*time.Hour)))
	l, err = cs.ListActive(ctx)
	check("ListActive after done", l, err, "c", "d")

	// CountCreatedSince counts every state, CreatedAt >= since.
	n, err := cs.CountCreatedSince(ctx, "dnsproxy:10.0.0.1", t0.Add(2*time.Second))
	must(t, err)
	if n != 2 {
		t.Fatalf("CountCreatedSince = %d", n)
	}
	n, _ = cs.CountCreatedSince(ctx, "order:o2", t0)
	if n != 1 {
		t.Fatalf("CountCreatedSince includes terminal: %d", n)
	}
	n, _ = cs.CountCreatedSince(ctx, "dnsproxy:10.0.0.1", t0.Add(3*time.Second+1))
	if n != 0 {
		t.Fatalf("CountCreatedSince after last = %d", n)
	}

	// Prune: terminal rows with UpdatedAt < before.
	n, err = cs.Prune(ctx, t0.Add(3*time.Hour))
	must(t, err)
	if n != 1 { // b (updated t0+1h); a was updated at exactly t0+3h
		t.Fatalf("Prune = %d", n)
	}
	n, _ = cs.Prune(ctx, t0.Add(4*time.Hour))
	if n != 1 {
		t.Fatalf("second Prune = %d", n)
	}
	l, err = cs.ListActive(ctx)
	check("ListActive after prune", l, err, "c", "d")
}

func TestChallengesSurviveRestart(t *testing.T) {
	path := dbPath(t)
	s, err := Open(path)
	must(t, err)
	for i, st := range []core.ChallengeState{core.ChallengePending, core.ChallengePresenting, core.ChallengeWaitingDNS,
		core.ChallengeReady, core.ChallengeCleaning, core.ChallengeDone, core.ChallengeFailed} {
		must(t, s.Challenges().Create(ctx, &core.Challenge{ID: string(st), ZoneID: "Z", RecordName: "_acme-challenge.x.example.com",
			Value: string(st), Owner: "order:o", State: st, CreatedAt: t0.Add(time.Duration(i) * time.Second)}))
	}
	must(t, s.Close())
	s = openAt(t, path)
	act, err := s.Challenges().ListActive(ctx)
	must(t, err)
	var wants int
	for _, c := range act {
		if c.State.Terminal() {
			t.Fatalf("terminal challenge listed: %+v", c)
		}
		if c.State.WantsRecord() {
			wants++
		}
		if !c.UpdatedAt.Equal(c.CreatedAt) {
			t.Fatalf("UpdatedAt defaulted wrong: %+v", c)
		}
	}
	if len(act) != 5 || wants != 4 {
		t.Fatalf("reconcile input: %d active, %d wanting the record", len(act), wants)
	}
}

func TestDirect(t *testing.T) {
	s := open(t)
	ds := s.Direct()
	_, err := ds.Get(ctx, "a.example.com")
	wantErr(t, err, core.ErrNotFound)
	wantErr(t, ds.TouchFetch(ctx, "a.example.com", t0, netip.MustParseAddr("10.0.0.1")), core.ErrNotFound)

	e := &core.DirectEntry{
		Identifier: "*.example.com", Generation: 1, CertificateID: "c1", Provider: "le",
		NotBefore: t0, NotAfter: t0.Add(90 * 24 * time.Hour), RenewAt: t0.Add(60 * 24 * time.Hour),
		NextARICheckAt: t0.Add(6 * time.Hour), LastFetchAt: t0, LastFetchIP: netip.MustParseAddr("10.0.0.2"),
		LastAttemptAt: t0, CreatedAt: t0, UpdatedAt: t0,
	}
	must(t, ds.Put(ctx, e))
	got, err := ds.Get(ctx, "*.example.com")
	must(t, err)
	if !reflect.DeepEqual(got, e) {
		t.Fatalf("Get\n%+v\nwant\n%+v", got, e)
	}

	must(t, ds.TouchFetch(ctx, "*.example.com", t0.Add(time.Hour), netip.MustParseAddr("10.0.0.3")))
	upd := *e
	upd.Generation, upd.CertificateID = 2, "c2"
	upd.LastError, upd.Failures = "boom", 2
	upd.CreatedAt = t0.Add(time.Hour)                            // ignored: kept from the row
	upd.LastFetchAt, upd.LastFetchIP = time.Time{}, netip.Addr{} // ignored: only TouchFetch changes them
	upd.UpdatedAt = t0.Add(2 * time.Hour)
	must(t, ds.Put(ctx, &upd))
	got, _ = ds.Get(ctx, "*.example.com")
	if got.Generation != 2 || got.CertificateID != "c2" || got.LastError != "boom" || got.Failures != 2 ||
		!got.CreatedAt.Equal(t0) || !got.UpdatedAt.Equal(t0.Add(2*time.Hour)) ||
		!got.LastFetchAt.Equal(t0.Add(time.Hour)) || got.LastFetchIP != netip.MustParseAddr("10.0.0.3") {
		t.Fatalf("after Put update %+v", got)
	}

	must(t, ds.Put(ctx, &core.DirectEntry{Identifier: "a.example.com", CreatedAt: t0, UpdatedAt: t0}))
	list, err := ds.List(ctx)
	must(t, err)
	if len(list) != 2 || list[0].Identifier != "*.example.com" || list[1].Identifier != "a.example.com" {
		t.Fatalf("List %+v", list)
	}
	if list[1].LastFetchIP.IsValid() || !list[1].NotAfter.IsZero() {
		t.Fatalf("zero values not preserved: %+v", list[1])
	}
	must(t, ds.Delete(ctx, "a.example.com"))
	must(t, ds.Delete(ctx, "a.example.com"))
	_, err = ds.Get(ctx, "a.example.com")
	wantErr(t, err, core.ErrNotFound)
}

func TestProviderStates(t *testing.T) {
	s := open(t)
	ps := s.ProviderStates()
	_, err := ps.Get(ctx, "le")
	wantErr(t, err, core.ErrNotFound)
	p := &core.ProviderState{Name: "le", Health: core.ProviderLimited, RetryAfter: t0.Add(time.Hour),
		LastError: "429", Failures: 1, UpdatedAt: t0}
	must(t, ps.Put(ctx, p))
	got, err := ps.Get(ctx, "le")
	must(t, err)
	if !reflect.DeepEqual(got, p) {
		t.Fatalf("Get %+v", got)
	}
	p.Health, p.RetryAfter, p.Failures = core.ProviderHealthy, time.Time{}, 0
	must(t, ps.Put(ctx, p))
	must(t, ps.Put(ctx, &core.ProviderState{Name: "gts", Health: core.ProviderUnavailable, UpdatedAt: t0}))
	list, err := ps.List(ctx)
	must(t, err)
	if len(list) != 2 || list[0].Name != "gts" || list[1].Name != "le" || list[1].Health != core.ProviderHealthy ||
		!list[1].RetryAfter.IsZero() {
		t.Fatalf("List %+v", list)
	}
}

func TestBudgets(t *testing.T) {
	s := open(t)
	bs := s.Budgets()
	ev := func(ref string, kind core.BudgetKind, key string, at time.Time) core.BudgetEvent {
		return core.BudgetEvent{Ref: ref, Provider: "le", Kind: kind, Key: key, At: at, Renewal: kind == core.BudgetCertSet}
	}
	r1 := []core.BudgetEvent{
		ev("r1", core.BudgetNewOrder, "", t0),
		ev("r1", core.BudgetCertDomain, "example.com", t0),
		ev("r1", core.BudgetCertSet, "a.example.com", t0),
	}
	must(t, bs.Reserve(ctx, r1))
	for i, e := range r1 {
		if e.ID == 0 || e.State != core.BudgetReserved || (i > 0 && e.ID <= r1[i-1].ID) {
			t.Fatalf("reserved event %+v", e)
		}
	}
	got, err := bs.ListByRef(ctx, "r1")
	must(t, err)
	if !reflect.DeepEqual(got, r1) {
		t.Fatalf("ListByRef\n%+v\nwant\n%+v", got, r1)
	}
	must(t, bs.Reserve(ctx, nil))
	if err := bs.Reserve(ctx, []core.BudgetEvent{ev("x", core.BudgetNewOrder, "", t0), ev("y", core.BudgetNewOrder, "", t0)}); err == nil {
		t.Fatal("mixed refs accepted")
	}
	// All or nothing: the second event is invalid.
	bad := []core.BudgetEvent{ev("r9", core.BudgetNewOrder, "", t0), ev("r9", "bogus", "", t0)}
	if err := bs.Reserve(ctx, bad); err == nil {
		t.Fatal("invalid kind accepted")
	}
	if l, _ := bs.ListByRef(ctx, "r9"); len(l) != 0 {
		t.Fatalf("partial Reserve stored %v", l)
	}

	// Commit new_order only (OrderCreated), then refund the rest.
	must(t, bs.Commit(ctx, "r1", core.BudgetNewOrder))
	must(t, bs.Commit(ctx, "nobody"))
	must(t, bs.Release(ctx, "r1"))
	got, _ = bs.ListByRef(ctx, "r1")
	if len(got) != 1 || got[0].Kind != core.BudgetNewOrder || got[0].State != core.BudgetCommitted {
		t.Fatalf("after commit+release %+v", got)
	}
	must(t, bs.Release(ctx, "r1", core.BudgetNewOrder)) // committed events are never released
	if got, _ = bs.ListByRef(ctx, "r1"); len(got) != 1 {
		t.Fatal("Release deleted a committed event")
	}

	// A second admission, fully committed, and a third still reserved.
	r2 := []core.BudgetEvent{ev("r2", core.BudgetCertDomain, "example.com", t0.Add(time.Hour)),
		ev("r2", core.BudgetCertSet, "b.example.com", t0.Add(time.Hour))}
	must(t, bs.Reserve(ctx, r2))
	must(t, bs.Commit(ctx, "r2", core.BudgetCertDomain, core.BudgetCertSet))
	must(t, bs.Commit(ctx, "r2")) // idempotent
	r3 := []core.BudgetEvent{ev("r3", core.BudgetNewOrder, "", t0.Add(2*time.Hour))}
	must(t, bs.Reserve(ctx, r3))

	// Sliding window: At >= since, ordered by At then ID.
	win, err := bs.ListSince(ctx, t0.Add(time.Hour))
	must(t, err)
	if len(win) != 3 || win[0].ID != r2[0].ID || win[1].ID != r2[1].ID || win[2].ID != r3[0].ID {
		t.Fatalf("ListSince %+v", win)
	}
	win, _ = bs.ListSince(ctx, t0.Add(time.Hour+1))
	if len(win) != 1 || win[0].Ref != "r3" {
		t.Fatalf("ListSince just after %+v", win)
	}
	win, _ = bs.ListSince(ctx, time.Time{})
	if len(win) != 4 {
		t.Fatalf("ListSince(zero) = %d events", len(win))
	}

	resv, err := bs.ListReserved(ctx)
	must(t, err)
	if len(resv) != 1 || resv[0].Ref != "r3" {
		t.Fatalf("ListReserved %+v", resv)
	}

	// Prune: committed events with At < before; reserved never.
	n, err := bs.Prune(ctx, t0.Add(3*time.Hour))
	must(t, err)
	if n != 3 {
		t.Fatalf("Prune = %d, want 3", n)
	}
	all, _ := bs.ListSince(ctx, time.Time{})
	if len(all) != 1 || all[0].Ref != "r3" || all[0].State != core.BudgetReserved {
		t.Fatalf("after Prune %+v", all)
	}
}

func TestBudgetsSurviveRestart(t *testing.T) {
	path := dbPath(t)
	s, err := Open(path)
	must(t, err)
	must(t, s.Budgets().Reserve(ctx, []core.BudgetEvent{{Ref: "o1", Provider: "le", Kind: core.BudgetCertSet, Key: "a", At: t0, Renewal: true}}))
	must(t, s.Budgets().Reserve(ctx, []core.BudgetEvent{{Ref: "o2", Provider: "le", Kind: core.BudgetNewOrder, At: t0}}))
	must(t, s.Budgets().Commit(ctx, "o2"))
	must(t, s.Close())
	s = openAt(t, path)
	ev, err := s.Budgets().ListSince(ctx, t0)
	must(t, err)
	if len(ev) != 2 || ev[0].State != core.BudgetReserved || !ev[0].Renewal || ev[1].State != core.BudgetCommitted {
		t.Fatalf("after restart %+v", ev)
	}
}
