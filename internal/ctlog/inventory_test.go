package ctlog

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"strings"
	"testing"
	"time"

	"tls-broker/internal/core"
	"tls-broker/internal/core/coretest"
)

const day = 24 * time.Hour

var t0 = coretest.At(2026, 10, 5, 12)

// iss is an issuance by Let's Encrypt, 10 days old, of a 90-day lifetime.
// names must be sorted.
func iss(tbs string, names ...string) Issuance {
	return Issuance{TBSSHA256: tbs, Names: names, NotBefore: t0.Add(-10 * day), NotAfter: t0.Add(80 * day),
		Issuer: "Let's Encrypt", IssuerCAA: []string{"letsencrypt.org"}}
}

// aged returns is issued age ago with the given lifetime.
func aged(is Issuance, age, life time.Duration) Issuance {
	is.NotBefore = t0.Add(-age)
	is.NotAfter = is.NotBefore.Add(life)
	return is
}

type invFixture struct {
	cfg   *coretest.FakeConfig
	src   *FakeSource
	clock *coretest.FakeClock
	res   *coretest.FakeResolver
	inv   *Inventory
}

func newInv(t *testing.T, pageSize int, zones ...string) *invFixture {
	t.Helper()
	c := coretest.NewConfig()
	c.Zones = nil
	for _, z := range zones {
		c.Zones = append(c.Zones, core.ZoneConfig{Name: z})
	}
	f := &invFixture{cfg: coretest.NewFakeConfig(c), src: NewFakeSource(pageSize), clock: coretest.NewFakeClock(t0),
		res: coretest.NewFakeResolver()}
	f.inv = New(Options{Config: f.cfg, Source: f.src, Resolver: f.res, Clock: f.clock, RetryPause: -1,
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil))})
	return f
}

func (f *invFixture) zone(t *testing.T, name string) ZoneStatus {
	t.Helper()
	for _, z := range f.inv.Snapshot().Zones {
		if z.Zone == name {
			return z
		}
	}
	t.Fatalf("zone %s not in snapshot", name)
	return ZoneStatus{}
}

func TestRefreshPaginatesDedupesAndSkipsNestedZones(t *testing.T) {
	f := newInv(t, 2, "example.com", "dev.example.com", "example.org")
	f.src.Add(iss("a", "x.example.com"), iss("b", "y.dev.example.com"), iss("c", "example.com", "example.org"), iss("d", "www.example.org"))
	if f.inv.Snapshot().Loaded() {
		t.Fatal("loaded before the first refresh")
	}
	f.inv.Refresh(context.Background())

	calls := f.src.Calls()
	want := []FakeCall{{"example.com", ""}, {"example.com", "2"}, {"example.com", "3"}, {"example.org", ""}, {"example.org", "4"}}
	if len(calls) != len(want) {
		t.Fatalf("calls %v, want %v", calls, want)
	}
	for i := range want {
		if calls[i] != want[i] {
			t.Fatalf("calls %v, want %v", calls, want)
		}
	}
	s := f.inv.Snapshot()
	if !s.Loaded() || len(s.Issuances) != 4 {
		t.Fatalf("loaded %v, %d issuances (shared one must count once)", s.Loaded(), len(s.Issuances))
	}
	com := f.zone(t, "example.com")
	if com.Count != 3 || len(com.Covers) != 1 || com.Covers[0] != "dev.example.com" || com.Err != "" || !com.LastSuccess.Equal(t0) {
		t.Fatalf("example.com status %+v", com)
	}
	if !s.NextRun.Equal(t0.Add(core.DefaultCTInterval)) {
		t.Fatalf("next run %s", s.NextRun)
	}

	// A routine refresh continues from each zone's cursor.
	f.src.Add(iss("e", "z.example.com"))
	f.inv.Refresh(context.Background())
	calls = f.src.Calls()[len(want):]
	want = []FakeCall{{"example.com", "3"}, {"example.com", "5"}, {"example.org", "4"}}
	if len(calls) != 3 || calls[0] != want[0] || calls[1] != want[1] || calls[2] != want[2] {
		t.Fatalf("incremental calls %v, want %v", calls, want)
	}
	if n := len(f.inv.Snapshot().Issuances); n != 5 {
		t.Fatalf("%d issuances after the incremental refresh", n)
	}
}

// A precertificate and its certificate are one issuance: the source may
// list the same TBS hash again (as the certificate, under a new ID).
func TestRefreshDedupesByTBS(t *testing.T) {
	f := newInv(t, 10, "example.com")
	pre := iss("same", "a.example.com")
	f.src.Add(pre)
	final := pre
	final.Serial = "abc"
	f.src.Add(final)
	f.inv.Refresh(context.Background())
	s := f.inv.Snapshot()
	if len(s.Issuances) != 1 || s.Issuances[0].Serial != "abc" {
		t.Fatalf("issuances %+v", s.Issuances)
	}
}

func TestRefreshFailureKeepsDataAndRetriesOnce(t *testing.T) {
	f := newInv(t, 10, "example.com", "example.org")
	f.src.Add(iss("a", "a.example.com"), iss("b", "b.example.org"))
	f.inv.Refresh(context.Background())

	f.src.Fail("example.com", errors.New("connection refused"))
	f.src.Add(iss("c", "c.example.org"))
	f.clock.Advance(4 * time.Hour)
	f.inv.Refresh(context.Background())
	com := f.zone(t, "example.com")
	if com.Count != 1 || !strings.Contains(com.Err, "connection refused") || !com.LastSuccess.Equal(t0) {
		t.Fatalf("failed zone %+v", com)
	}
	if org := f.zone(t, "example.org"); org.Count != 2 || org.Err != "" {
		t.Fatalf("healthy zone %+v", org)
	}
	s := f.inv.Snapshot()
	if len(s.Failed()) != 1 || !s.NextRun.Equal(f.clock.Now().Add(RetryDelay)) {
		t.Fatalf("failed %v, next run %s (want one early retry)", s.Failed(), s.NextRun)
	}
	// The early retry fails too: back to the regular interval.
	f.clock.Advance(RetryDelay)
	f.inv.Refresh(context.Background())
	if s := f.inv.Snapshot(); !s.NextRun.Equal(f.clock.Now().Add(core.DefaultCTInterval)) {
		t.Fatalf("next run after the failed retry %s", s.NextRun)
	}
	f.src.Fail("example.com", nil)
	f.clock.Advance(4 * time.Hour)
	f.inv.Refresh(context.Background())
	if com := f.zone(t, "example.com"); com.Err != "" || !com.LastSuccess.Equal(f.clock.Now()) {
		t.Fatalf("recovered zone %+v", com)
	}
}

func TestRetryOnceOnTransientError(t *testing.T) {
	f := newInv(t, 10, "example.com")
	f.inv.o.RetryPause = time.Second
	f.src.Fail("example.com", errors.New("timeout"))
	done := make(chan struct{})
	go func() { f.inv.Refresh(context.Background()); close(done) }()
	if !f.clock.BlockUntil(1, 2*time.Second) {
		t.Fatal("no retry pause")
	}
	f.src.Fail("example.com", nil)
	f.clock.Advance(time.Second)
	<-done
	if z := f.zone(t, "example.com"); z.Err != "" || len(f.src.Calls()) != 2 {
		t.Fatalf("zone %+v after %d calls", z, len(f.src.Calls()))
	}
}

func TestRateLimitSkipsRemainingZones(t *testing.T) {
	f := newInv(t, 10, "example.com", "example.org")
	f.src.Fail("example.com", &RateLimitError{RetryAfter: 2 * time.Hour})
	f.inv.Refresh(context.Background())
	if n := len(f.src.Calls()); n != 1 {
		t.Fatalf("%d calls; a rate-limit refusal must stop the round without retry", n)
	}
	org := f.zone(t, "example.org")
	if !strings.Contains(org.Err, "not queried") || org.LastAttempt.IsZero() {
		t.Fatalf("skipped zone %+v", org)
	}
	if s := f.inv.Snapshot(); !s.NextRun.Equal(t0.Add(2*time.Hour)) || !s.Loaded() {
		t.Fatalf("next run %s (want the source's Retry-After), loaded %v", s.NextRun, s.Loaded())
	}
}

func TestRefreshPrunesLongExpired(t *testing.T) {
	f := newInv(t, 10, "example.com")
	f.src.Add(aged(iss("old", "a.example.com"), 121*day, 90*day), aged(iss("recent", "b.example.com"), 119*day, 90*day))
	f.inv.Refresh(context.Background())
	s := f.inv.Snapshot()
	if len(s.Issuances) != 1 || s.Issuances[0].TBSSHA256 != "recent" {
		t.Fatalf("issuances %+v", s.Issuances)
	}
}

func TestRefreshReadsCAA(t *testing.T) {
	f := newInv(t, 10, "example.com", "dev.example.com", "example.org")
	f.res.SetCAA("example.com", core.CAA{Tag: "issue", Value: "letsencrypt.org"},
		core.CAA{Tag: "issuewild", Value: "letsencrypt.org; accounturi=https://acme.test/acct/1"})
	f.res.Fail("example.org", core.ErrResolver)
	f.inv.Refresh(context.Background())
	s := f.inv.Snapshot()
	com, dev, org := s.CAA["example.com"], s.CAA["dev.example.com"], s.CAA["example.org"]
	if com.Node != "example.com" || !com.HasIssueWild || com.IssueWild[0] != "letsencrypt.org" {
		t.Fatalf("example.com %+v", com)
	}
	if dev.Node != "example.com" {
		t.Fatalf("dev.example.com must climb to its parent: %+v", dev)
	}
	if org.Err == "" {
		t.Fatalf("example.org lookup failure lost: %+v", org)
	}
}

// Run fetches at once, then every interval; a new interval and a new zone
// take effect without restart; disabling drops the data.
func TestRunSchedule(t *testing.T) {
	f := newInv(t, 10, "example.com")
	f.src.Add(iss("a", "a.example.com"))
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { f.inv.Run(ctx); close(done) }()
	defer func() { cancel(); <-done }()

	waitCalls := func(n int) {
		t.Helper()
		deadline := time.Now().Add(3 * time.Second)
		for len(f.src.Calls()) < n {
			if time.Now().After(deadline) {
				t.Fatalf("%d calls, want %d", len(f.src.Calls()), n)
			}
			time.Sleep(time.Millisecond)
		}
	}
	armed := func(n int) {
		t.Helper()
		if !f.clock.BlockUntil(n, 3*time.Second) {
			t.Fatalf("timer %d never armed", n)
		}
	}
	waitCalls(2) // startup: first page and the empty page
	armed(1)
	f.clock.Advance(core.DefaultCTInterval - time.Minute)
	time.Sleep(20 * time.Millisecond)
	if n := len(f.src.Calls()); n != 2 {
		t.Fatalf("refreshed early: %d calls", n)
	}
	f.clock.Advance(time.Minute)
	waitCalls(3)
	armed(1)

	// Shorter interval: due 2 h after the last refresh.
	f.cfg.Update(func(c *core.Config) { c.CTInventory.Interval = 2 * time.Hour })
	armed(2)
	f.clock.Advance(2 * time.Hour)
	waitCalls(4)

	// A new zone is fetched at once.
	f.cfg.Update(func(c *core.Config) { c.Zones = append(c.Zones, core.ZoneConfig{Name: "example.net"}) })
	waitCalls(6)
	if c := f.src.Calls(); c[len(c)-1].Domain != "example.net" {
		t.Fatalf("last call %+v", c[len(c)-1])
	}

	f.cfg.Update(func(c *core.Config) { c.CTInventory.Disabled = true })
	deadline := time.Now().Add(3 * time.Second)
	for len(f.inv.Snapshot().Issuances) > 0 || f.inv.Snapshot().Enabled {
		if time.Now().After(deadline) {
			t.Fatal("disabled inventory kept its data")
		}
		time.Sleep(time.Millisecond)
	}
}
